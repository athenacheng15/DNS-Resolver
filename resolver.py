import sys, socket, time

from root_hints import parse_root_hints
from dns_message import parse_header, parse_questions, parse_dns_message
from dns_encoder import encode_dns_response, encode_upstream_query
from dns_records import DNSQuestion

UPSTREAM_DNS_PORT = 53
MAX_DNS_MESSAGE_SIZE = 4096

MAX_OUTBOUND_ATTEMPTS = 50
MAX_REFERRAL_LEVELS = 10
MAX_CNAME_RECORDS = 10

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_PTR = 12
TYPE_MX = 15
CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3


class ResolutionLimitError(Exception):
    pass


class ResolutionBudget:
    def __init__(self):
        self.outbound_attempts = 0
        self.referrals_levels = 0

    def use_outbound_attempt(self):
        if self.outbound_attempts >= MAX_OUTBOUND_ATTEMPTS:
            raise ResolutionLimitError("Outbound attempts limit reached")
        self.outbound_attempts += 1

    def use_referral_level(self):
        if self.referrals_levels >= MAX_REFERRAL_LEVELS:
            raise ResolutionLimitError("Referral levels limit reached")
        self.referrals_levels += 1


def parse_args():
    if len(sys.argv) != 4:
        print("Usage: python3 resolver.py " "<root_hints_file> <timeout> <listen_port>")
        sys.exit(1)

    root_hints_file = sys.argv[1]
    timeout = int(sys.argv[2])
    listen_port = int(sys.argv[3])

    return root_hints_file, timeout, listen_port


def create_server_socket(listen_port):
    # socket.AF_INET for IPv4, socket.SOCK_DGRAM for UDP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", listen_port))

    return server_socket


def decode_client_query(query_data):
    header, offset = parse_header(query_data)
    questions, offset = parse_questions(query_data, offset, header.qdcount)

    return header, questions


def normalize_dns_name(name):
    if name == ".":
        return "."

    return name.rstrip(".").lower() + "."


def question_match(actual_question, expected_question):
    return (
        normalize_dns_name(actual_question.qname)
        == normalize_dns_name(expected_question.qname)
        and actual_question.qtype == expected_question.qtype
        and actual_question.qclass == expected_question.qclass
    )


def record_name_matches(actual_name, expected_name):
    return normalize_dns_name(actual_name) == normalize_dns_name(expected_name)


def find_requested_answer(message, question):
    answers = []
    for record in message.answers:
        if (
            record.rclass == question.qclass
            and record.rtype == question.qtype
            and record_name_matches(record.name, question.qname)
        ):
            answers.append(record)
    return answers


def find_cname_answer(message, expected_name, expected_class):
    cname_records = []

    for record in message.answers:
        if (
            record.rclass == expected_class
            and record.rtype == TYPE_CNAME
            and record_name_matches(record.name, expected_name)
        ):
            cname_records.append(record)
    return cname_records


def extract_cname_chain_and_final_answers(message, question):
    original_name = normalize_dns_name(question.qname)

    # A direct CNAME query must return only the CNAME RRset whose owner is the original QNAME.
    # Its target must not be chased.
    if question.qtype == TYPE_CNAME:
        direct_answers = find_cname_answer(message, original_name, question.qclass)
        return [], direct_answers, original_name

    current_name = original_name
    visited_names = {current_name}
    cname_chain = []

    while True:
        final_answers = []
        for record in message.answers:
            if (
                record.rclass == question.qclass
                and record.rtype == question.qtype
                and record_name_matches(record.name, current_name)
            ):
                final_answers.append(record)

        if final_answers:
            return cname_chain, final_answers, current_name

        cname_records = find_cname_answer(message, current_name, question.qclass)
        if not cname_records:
            return cname_chain, [], current_name

        # A CNAME owner should point to one canonical target.
        target_name = normalize_dns_name(cname_records[0].rdata)

        for record in cname_records:
            if normalize_dns_name(record.rdata) != target_name:
                raise ValueError("Conflicting CNAME targets")

        if len(cname_chain) > MAX_CNAME_RECORDS:
            raise ResolutionLimitError("CNAME chain limit reached")

        if target_name in visited_names:
            raise ResolutionLimitError("CNAME loop detected")

        cname_chain.append(cname_records)
        visited_names.add(target_name)
        current_name = target_name


def get_referral_records(message):
    ns_records = []
    for record in message.authority:
        if record.rclass == CLASS_IN and record.rtype == TYPE_NS:
            # The parser stores authority records in the order they appear in the packet.
            ns_records.append(record)

    return ns_records


def get_matching_glue_ips(message, ns_records):
    # Match glue records only for referred name servers.
    glue_ips = []
    for ns_record in ns_records:
        ns_name = normalize_dns_name(ns_record.rdata)

        for additional_record in message.additional:
            if additional_record.rclass != CLASS_IN:
                continue
            if additional_record.rtype != TYPE_A:
                continue

            additional_name = normalize_dns_name(additional_record.name)
            if additional_name == ns_name:
                glue_ips.append(additional_record.rdata)

    return glue_ips


def is_authoritative_nodata_response(message, question):
    return (
        message.header.aa == 1
        and message.header.rcode == RCODE_NOERROR
        and not find_requested_answer(message, question)
    )


def is_referral_response(message, question):
    if message.header.aa == 1:
        return False
    if message.header.rcode != RCODE_NOERROR:
        return False
    if find_requested_answer(message, question):
        return False

    return bool(get_referral_records(message))


def make_resolution_result(
    answers=None, authorities=None, additional=None, rcode=RCODE_NOERROR
):
    return {
        "answers": [] if answers is None else answers,
        "authorities": [] if authorities is None else authorities,
        "additional": [] if additional is None else additional,
        "rcode": rcode,
    }


def resolve_name_server_addresses(ns_records, root_server_ips, timeout, budget):
    for ns_record in ns_records:
        ns_question = DNSQuestion(qname=ns_record.rdata, qtype=TYPE_A, qclass=CLASS_IN)

        nested_result = iterative_resolve(
            ns_question,
            root_server_ips,
            timeout,
            budget,
        )

        if nested_result is None:
            continue

        if nested_result["rcode"] != RCODE_NOERROR:
            continue

        addresses = []

        for record in nested_result["answers"]:
            if (
                record.rclass == CLASS_IN
                and record.rtype == TYPE_A
                and record_name_matches(record.name, ns_record.rdata)
            ):
                addresses.append(record.rdata)

        if addresses:
            return addresses

    return []


def iterative_resolve(question, root_server_ips, timeout, budget):

    current_question = DNSQuestion(
        qname=normalize_dns_name(question.qname),
        qtype=question.qtype,
        qclass=question.qclass,
    )

    candidate_ips = list(root_server_ips)

    cname_chain = []
    visited_cname_names = {normalize_dns_name(question.qname)}

    while candidate_ips:
        upstream_result = query_upstream_candidate(
            candidate_ips, current_question, timeout, budget
        )

        if upstream_result is None:
            return None

        message = upstream_result["message"]

        # NXDOMAIN is final only when returned by an authoritative server.
        if message.header.aa == 1 and message.header.rcode == RCODE_NXDOMAIN:
            return make_resolution_result(
                answers=list(cname_chain),
                authorities=message.authority,
                additional=[],
                rcode=RCODE_NXDOMAIN,
            )

        # Other upstream errors currently fail this resolution.
        if message.header.rcode != RCODE_NOERROR:
            return None

        response_cnames, final_answers, terminal_name = (
            extract_cname_chain_and_final_answers(message, current_question)
        )

        # Direct CNAME query:
        # extract_cname_chain_and_final_answers() returns the requested
        # CNAME RRset as final_answers and does not chase its target.
        if current_question.qtype == TYPE_CNAME:
            if final_answers:
                return make_resolution_result(
                    answers=final_answers,
                    authorities=message.authority,
                    additional=message.additional,
                    rcode=RCODE_NOERROR,
                )

            # Stop if this is an authoritative NODATA response.
            if is_authoritative_nodata_response(message, current_question):
                return make_resolution_result(
                    answers=[],
                    authorities=message.authority,
                    additional=[],
                    rcode=RCODE_NOERROR,
                )

        # For A, NS, MX, and PTR queries, process any CNAME records found
        # in this response before checking for authoritative NODATA.
        if response_cnames:
            if len(cname_chain) + len(response_cnames) > MAX_CNAME_RECORDS:
                raise ResolutionLimitError("CNAME chain limit reached")

            expected_owner = normalize_dns_name(current_question.qname)

            for cname_record in response_cnames:
                owner_name = normalize_dns_name(cname_record.name)
                target_name = normalize_dns_name(cname_record.rdata)

                # The extracted chain should continue from the current name.
                if owner_name != expected_owner:
                    raise ValueError("CNAME chain owner does not match expected name")

                if target_name in visited_cname_names:
                    raise ResolutionLimitError("CNAME loop detected")

                cname_chain.append(cname_record)
                visited_cname_names.add(target_name)
                expected_owner = target_name

        # The same response may already contain the complete CNAME chain
        # followed by the requested-type RRset.
        if final_answers:
            return make_resolution_result(
                answers=cname_chain + final_answers,
                authorities=message.authority,
                additional=message.additional,
                rcode=RCODE_NOERROR,
            )

        # A CNAME chain was found, but this response did not contain the
        # final requested-type RRset. Restart iterative resolution from
        # the root for the canonical target, preserving the original type.
        if response_cnames:
            current_question = DNSQuestion(
                qname=terminal_name,
                qtype=question.qtype,
                qclass=question.qclass,
            )
            candidate_ips = list(root_server_ips)
            continue

        # No requested answer and no CNAME remain. If the response is
        # authoritative, this is terminal NODATA rather than a referral.
        if is_authoritative_nodata_response(message, current_question):
            return make_resolution_result(
                answers=list(cname_chain),
                authorities=message.authority,
                additional=[],
                rcode=RCODE_NOERROR,
            )

        if not is_referral_response(message, current_question):
            return None

        budget.use_referral_level()

        ns_records = get_referral_records(message)
        glue_ips = get_matching_glue_ips(message, ns_records)

        if glue_ips:
            candidate_ips = glue_ips
        else:
            # Resolve NS hostnames from the root when no glue is available.
            candidate_ips = resolve_name_server_addresses(
                ns_records, root_server_ips, timeout, budget
            )

        if not candidate_ips:
            return None

    return None


def build_root_hints_response(question, root_ns_records, root_a_records, root_a_map):
    qname = normalize_dns_name(question.qname)

    # Root hints only contains IN records
    if question.qclass != 1:
        return None

    # Query: .NS
    if qname == "." and question.qtype == 2:
        answers = list(root_ns_records)
        additional = []

        # For every returned NS record, find its matching A glue records.
        # The nested loop preserves: NS record order, A record file order.
        for ns_record in root_ns_records:
            ns_name = normalize_dns_name(ns_record.rdata)

            for a_record in root_a_records:
                a_name = normalize_dns_name(a_record.name)

                if a_name == ns_name:
                    additional.append(a_record)

        return {
            "answers": answers,
            "authorities": [],
            "additional": additional,
            "rcode": 0,
        }

    # Query: a.root-servers.net. A, b.root-servers.net. A, etc.
    if question.qtype == 1:
        answers = root_a_map.get(qname, [])
        if answers:
            return {
                "answers": list(answers),
                "authorities": [],
                "additional": [],
                "rcode": 0,
            }

    # This query cannot be answered using named.root.
    return None


def get_root_server_ips(root_a_records):
    return [record.rdata for record in root_a_records if record.rtype == 1]


def validate_upstream_response(
    response_data,
    response_address,
    expected_server_ip,
    expected_transaction_id,
    expected_question,
):

    source_ip, source_port = response_address

    # The response must come from the server that was queried.
    if source_ip != expected_server_ip:
        raise ValueError("Upstream response came from the wrong IP address")

    # DNS servers must respond from port 53.
    if source_port != UPSTREAM_DNS_PORT:
        raise ValueError("Upstream response came from the wrong port")

    message = parse_dns_message(response_data)
    header = message.header

    if header.message_id != expected_transaction_id:
        raise ValueError("Upstream response has the wrong transaction ID")
    if header.qr != 1:
        raise ValueError("Upstream response is not a DNS response")
    if header.opcode != 0:
        raise ValueError("Upstream response has an unsupported OPCODE")

    # Do not retry with TCP. A truncated UDP response makes this
    # candidate fail.
    if header.tc != 0:
        raise ValueError("Upstream response is truncated")

    if header.qdcount != 1:
        raise ValueError("Upstream response must contain exactly one question")

    if len(message.questions) != 1:
        raise ValueError("Parsed question count does not match QDCOUNT")

    if not question_match(
        message.questions[0],
        expected_question,
    ):
        raise ValueError("Upstream response question does not match the query")

    return message


def query_upstream_server(server_ip, question, timeout):
    transaction_id, query_data = encode_upstream_query(question)

    upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    deadline = time.monotonic() + timeout

    try:
        upstream_socket.sendto(query_data, (server_ip, UPSTREAM_DNS_PORT))
        while True:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                return None

            upstream_socket.settimeout(remaining_time)

            try:
                response_data, response_address = upstream_socket.recvfrom(
                    MAX_DNS_MESSAGE_SIZE
                )
            except socket.timeout:
                return None
            try:
                message = validate_upstream_response(
                    response_data, response_address, server_ip, transaction_id, question
                )
            except ValueError:
                continue  # Ignore invalid or unrelated UDP datagrams and keep waiting until the original timeout deadline.

            return {
                "transaction_id": transaction_id,
                "response_data": response_data,
                "response_address": response_address,
                "message": message,
            }
    finally:
        upstream_socket.close()


def query_upstream_candidate(server_ips, question, timeout, budget):
    for server_ip in server_ips:
        budget.use_outbound_attempt()

        result = query_upstream_server(server_ip, question, timeout)

        if result is not None:
            return result

    return None


def run_server(server_socket, root_ns_records, root_a_records, root_a_map, timeout):

    # Root server IPs are the starting point for iterative resolution.
    root_server_ips = get_root_server_ips(root_a_records)

    while True:
        query_data, client_address = server_socket.recvfrom(MAX_DNS_MESSAGE_SIZE)

        try:
            header, questions = decode_client_query(query_data)

            if len(questions) == 0:
                print("Invalid query: no questions")
                continue

            question = questions[0]

            # Answer directly when the query can be resolved from root hints.
            local_response = build_root_hints_response(
                question, root_ns_records, root_a_records, root_a_map
            )

            if local_response is None:
                # Each client query gets its own resolution limits.
                budget = ResolutionBudget()
                try:
                    resolution_result = iterative_resolve(
                        question, root_server_ips, timeout, budget
                    )
                except ResolutionLimitError:
                    resolution_result = None

                # Resolution failure or limit exceeded becomes SERVFAIL.
                if resolution_result is None:
                    response_data = encode_dns_response(
                        query_header=header,
                        question=question,
                        rcode=RCODE_SERVFAIL,
                    )
                else:
                    response_data = encode_dns_response(
                        query_header=header,
                        question=question,
                        answers=resolution_result["answers"],
                        authorities=resolution_result["authorities"],
                        additional=resolution_result["additional"],
                        rcode=resolution_result["rcode"],
                    )

            else:
                response_data = encode_dns_response(
                    query_header=header,
                    question=question,
                    answers=local_response["answers"],
                    authorities=local_response["authorities"],
                    additional=local_response["additional"],
                    rcode=local_response["rcode"],
                )

            server_socket.sendto(
                response_data,
                client_address,
            )

        except ValueError:
            # Assessed Stage 2 client queries are valid DNS messages.
            # Malformed queries are ignored safely.
            continue


def main():
    root_hints_file, timeout, listen_port = parse_args()
    root_ns_records, root_a_records, root_a_map = parse_root_hints(root_hints_file)
    server_socket = create_server_socket(listen_port)

    try:
        run_server(server_socket, root_ns_records, root_a_records, root_a_map, timeout)
    except KeyboardInterrupt:
        pass
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
