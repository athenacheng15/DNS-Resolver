import sys, socket, time, threading

from root_hints import parse_root_hints
from dns_message import parse_header, parse_questions, parse_dns_message
from dns_encoder import encode_dns_response, encode_upstream_query
from dns_records import DNSQuestion
from cache import DNSCache

from utils import normalize_name

UPSTREAM_DNS_PORT = 53
MAX_DNS_MESSAGE_SIZE = 4096

MAX_OUTBOUND_ATTEMPTS = 50
MAX_REFERRAL_LEVELS = 10
MAX_CNAME_RECORDS = 10
MAX_RESOLUTION_SECONDS = 30

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_PTR = 12
TYPE_MX = 15

CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5

SUPPORTED_QUERY_TYPES = {
    TYPE_A,
    TYPE_NS,
    TYPE_CNAME,
    TYPE_PTR,
    TYPE_MX,
}

ENCODABLE_RECORD_TYPES = {
    TYPE_A,
    TYPE_NS,
    TYPE_CNAME,
    TYPE_PTR,
    TYPE_MX,
}


class ResolutionLimitError(Exception):
    pass


class ResolutionBudget:
    """
    Track limits shared by one complete client resolution.

    The same budget is reused by:
    - the original iterative lookup,
    - nested name-server address lookups,
    - CNAME chasing.

    This ensures all work triggered by one client query shares the same
    outbound-attempt, referral-level, and wall-clock limits.
    """

    def __init__(self, timeout):
        self.outbound_attempts = 0
        self.referral_levels = 0

        total_time_limit = min(MAX_RESOLUTION_SECONDS, MAX_OUTBOUND_ATTEMPTS * timeout)
        self.deadline = time.monotonic() + total_time_limit

    def remaining_time(self):
        """
        Return the number of seconds remaining for this client resolution.
        The returned value may be zero when the overall deadline has passed.
        """

        return max(0.0, self.deadline - time.monotonic())

    def ensure_time_remaining(self):
        """
        Raise ResolutionLimitError when the total resolution deadline expires.
        """
        if self.remaining_time() <= 0:
            raise ResolutionLimitError("Total resolution time limit reached")

    def use_outbound_attempt(self):
        self.ensure_time_remaining()
        if self.outbound_attempts >= MAX_OUTBOUND_ATTEMPTS:
            raise ResolutionLimitError("Outbound attempts limit reached")
        self.outbound_attempts += 1

    def use_referral_level(self):
        self.ensure_time_remaining()
        if self.referral_levels >= MAX_REFERRAL_LEVELS:
            raise ResolutionLimitError("Referral levels limit reached")
        self.referral_levels += 1


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


def is_supported_client_question(question):
    return question.qtype in SUPPORTED_QUERY_TYPES


def question_match(actual_question, expected_question):
    return (
        normalize_name(actual_question.qname) == normalize_name(expected_question.qname)
        and actual_question.qtype == expected_question.qtype
        and actual_question.qclass == expected_question.qclass
    )


def record_name_matches(actual_name, expected_name):
    return normalize_name(actual_name) == normalize_name(expected_name)


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
    original_name = normalize_name(question.qname)

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
        target_name = normalize_name(cname_records[0].rdata)

        for record in cname_records:
            if normalize_name(record.rdata) != target_name:
                raise ValueError("Conflicting CNAME targets")

        if len(cname_chain) > MAX_CNAME_RECORDS:
            raise ResolutionLimitError("CNAME chain limit reached")

        if target_name in visited_names:
            raise ResolutionLimitError("CNAME loop detected")

        cname_chain.extend(cname_records)
        visited_names.add(target_name)
        current_name = target_name


def has_complete_positive_answer(question, records):
    """
    Return True when records form a complete positive answer for question.

    For a direct CNAME query, the answer must contain a CNAME RRset whose
    owner is the original QNAME.

    For A, NS, MX, or PTR, the records may contain a CNAME chain, but that
    chain must eventually reach at least one record of the requested type.
    """

    current_name = normalize_name(question.qname)
    visited_names = {current_name}
    cname_count = 0

    if question.qtype == TYPE_CNAME:
        for record in records:
            if (
                record.rclass == question.qclass
                and record.rtype == TYPE_CNAME
                and record_name_matches(record.name, current_name)
            ):
                return True
        return False

    while True:
        # Check whether the requested-type RRset exists for the current
        # canonical name.
        for record in records:
            if (
                record.rclass == question.qclass
                and record.rtype == question.qtype
                and record_name_matches(record.name, current_name)
            ):
                return True

        # Otherwise, find the next CNAME link.
        matching_cnames = []

        for record in records:
            if (
                record.rclass == question.qclass
                and record.rtype == TYPE_CNAME
                and record_name_matches(record.name, current_name)
            ):
                matching_cnames.append(record)

        if not matching_cnames:
            return False

        target_name = normalize_name(matching_cnames[0].rdata)

        # One alias owner must not point to conflicting targets.
        for record in matching_cnames:
            if normalize_name(record.rdata) != target_name:
                return False

        cname_count += len(matching_cnames)
        if cname_count > MAX_CNAME_RECORDS:
            return False

        if target_name in visited_names:
            return False

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
        ns_name = normalize_name(ns_record.rdata)

        for additional_record in message.additional:
            if additional_record.rclass != CLASS_IN:
                continue
            if additional_record.rtype != TYPE_A:
                continue

            additional_name = normalize_name(additional_record.name)
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


def filter_encodable_records(records):
    """
    Keep only resource records that the response encoder can safely encode.

    Record order is preserved. Unsupported records such as SOA, AAAA,
    TXT, and OPT are excluded from client-facing responses.
    """
    return [record for record in records if record.rtype in ENCODABLE_RECORD_TYPES]


def make_resolution_result(
    answers=None, authorities=None, additional=None, rcode=RCODE_NOERROR, aa=0
):
    return {
        "answers": [] if answers is None else answers,
        "authorities": [] if authorities is None else authorities,
        "additional": [] if additional is None else additional,
        "rcode": rcode,
        "aa": aa,
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
        qname=normalize_name(question.qname),
        qtype=question.qtype,
        qclass=question.qclass,
    )

    candidate_ips = list(root_server_ips)

    cname_chain = []
    visited_cname_names = {normalize_name(question.qname)}
    response_was_assembled = False

    while candidate_ips:
        budget.ensure_time_remaining()

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
                authorities=[],
                additional=[],
                rcode=RCODE_NXDOMAIN,
                aa=1 if not response_was_assembled else 0,
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
                    authorities=[],
                    additional=[],
                    rcode=RCODE_NOERROR,
                    aa=(
                        1
                        if message.header.aa == 1 and not response_was_assembled
                        else 0
                    ),
                )

            # Stop if this is an authoritative NODATA response.
            if is_authoritative_nodata_response(message, current_question):
                return make_resolution_result(
                    answers=[],
                    authorities=[],
                    additional=[],
                    rcode=RCODE_NOERROR,
                    aa=1 if not response_was_assembled else 0,
                )

        # For A, NS, MX, and PTR queries, process any CNAME records found
        # in this response before checking for authoritative NODATA.
        if response_cnames:
            if len(cname_chain) + len(response_cnames) > MAX_CNAME_RECORDS:
                raise ResolutionLimitError("CNAME chain limit reached")

            expected_owner = normalize_name(current_question.qname)

            for cname_record in response_cnames:
                owner_name = normalize_name(cname_record.name)
                target_name = normalize_name(cname_record.rdata)

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
                authorities=[],
                additional=[],
                rcode=RCODE_NOERROR,
                aa=(1 if message.header.aa == 1 and not response_was_assembled else 0),
            )

        # A CNAME chain was found, but this response did not contain the
        # final requested-type RRset. Restart iterative resolution from
        # the root for the canonical target, preserving the original type.
        if response_cnames:
            response_was_assembled = True
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
                authorities=[],
                additional=[],
                rcode=RCODE_NOERROR,
                aa=1 if not response_was_assembled else 0,
            )

        if not is_referral_response(message, current_question):
            return None

        budget.use_referral_level()
        response_was_assembled = True

        ns_records = get_referral_records(message)
        glue_ips = get_matching_glue_ips(message, ns_records)

        if glue_ips:
            candidate_ips = glue_ips
        else:
            # Resolve NS hostnames from the root when no glue is available.
            budget.ensure_time_remaining()
            candidate_ips = resolve_name_server_addresses(
                ns_records, root_server_ips, timeout, budget
            )

        if not candidate_ips:
            return None

    return None


def build_root_hints_response(question, root_ns_records, root_a_records, root_a_map):
    qname = normalize_name(question.qname)

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
            ns_name = normalize_name(ns_record.rdata)

            for a_record in root_a_records:
                a_name = normalize_name(a_record.name)

                if a_name == ns_name:
                    additional.append(a_record)

        return {
            "answers": answers,
            "authorities": [],
            "additional": additional,
            "rcode": 0,
            "aa": 0,
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
                "aa": 0,
            }

    # This query cannot be answered using named.root.
    return None


def get_root_server_ips(root_ns_records, root_a_records):
    root_server_ips = []

    for ns_record in root_ns_records:
        ns_name = normalize_name(ns_record.rdata)

        for a_record in root_a_records:
            a_name = normalize_name(a_record.name)

            if a_name == ns_name:
                root_server_ips.append(a_record.rdata)

    return root_server_ips


def is_retryable_upstream_response(message):
    """
    Return True when a valid upstream DNS response should be treated as a
    failure for this candidate server.

    NOERROR responses may contain a final answer, NODATA, CNAME, or referral.
    NXDOMAIN may be terminal when authoritative, so it must be examined by
    iterative_resolve().
    """
    return message.header.rcode not in (
        RCODE_NOERROR,
        RCODE_NXDOMAIN,
    )


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


def query_upstream_server(server_ip, question, timeout, budget):
    """
    Send one DNS query to one upstream server.

    The function waits no longer than both:
    - the configured timeout for one upstream attempt, and
    - the remaining wall-clock budget for the complete client resolution.

    Invalid or unrelated UDP datagrams are ignored while the same attempt
    deadline remains active.
    """
    budget.ensure_time_remaining()
    transaction_id, query_data = encode_upstream_query(question)

    upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    now = time.monotonic()
    attempt_deadline = min(now + timeout, budget.deadline)

    try:
        upstream_socket.sendto(query_data, (server_ip, UPSTREAM_DNS_PORT))
        while True:
            remaining_time = attempt_deadline - time.monotonic()
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
    """
    Query candidate upstream servers sequentially.

    Each attempted server consumes one outbound-attempt unit. Timeouts,
    invalid packets, and retryable DNS error responses cause the resolver
    to continue with the next candidate.
    """
    for server_ip in server_ips:
        budget.use_outbound_attempt()

        result = query_upstream_server(server_ip, question, timeout, budget)

        if result is None:
            continue

        if is_retryable_upstream_response(result["message"]):
            continue

        return result

    return None


def resolve_client_question(question, root_server_ips, timeout, cache):
    """
    Resolve one client question using the shared positive-answer cache.

    A complete unexpired cached answer is returned without sending any
    upstream DNS packets. On a cache miss, iterative resolution is used.

    Only complete positive NOERROR answers are inserted into the cache.
    NXDOMAIN, NODATA, SERVFAIL, and incomplete CNAME chains are not cached.
    """

    cache_answers = cache.get(question)
    if cache_answers is not None:
        return make_resolution_result(
            answers=cache_answers,
            authorities=[],
            additional=[],
            rcode=RCODE_NOERROR,
        )

    budget = ResolutionBudget(timeout)
    try:
        resolution_result = iterative_resolve(
            question, root_server_ips, timeout, budget
        )
    except (ResolutionLimitError, ValueError):
        return None

    if resolution_result is None:
        return None

    if resolution_result["rcode"] == RCODE_NOERROR and has_complete_positive_answer(
        question, resolution_result["answers"]
    ):
        cache.put(question, resolution_result["answers"])
        return resolution_result

    return resolution_result


def build_client_response(query_header, question, resolution_result):
    """
    Encode the final DNS response sent to the client.

    A failed resolution is returned as SERVFAIL. Otherwise, the answer,
    authority, additional, and RCODE fields come from the resolution result.
    """

    if resolution_result is None:
        return encode_dns_response(
            query_header=query_header,
            question=question,
            rcode=RCODE_SERVFAIL,
        )
    answers = filter_encodable_records(resolution_result["answers"])
    authorities = filter_encodable_records(resolution_result["authorities"])
    additional = filter_encodable_records(resolution_result["additional"])

    return encode_dns_response(
        query_header=query_header,
        question=question,
        answers=answers,
        authorities=authorities,
        additional=additional,
        rcode=resolution_result["rcode"],
        aa=resolution_result["aa"],
    )


def handle_client_query(
    server_socket,
    query_data,
    client_address,
    root_ns_records,
    root_a_records,
    root_a_map,
    root_server_ips,
    timeout,
    cache,
):
    """
    Process and answer one client DNS query.

    This function runs inside a worker thread. All state created while
    resolving the query is local to this invocation. The cache is the only
    shared mutable resolver state and is protected internally by a lock.
    """
    try:
        header, questions = decode_client_query(query_data)

        # This resolver supports exactly one question per client query.
        if len(questions) != 1:
            return

        question = questions[0]

        if not is_supported_client_question(question):
            response_data = build_client_response(
                header,
                question,
                resolution_result=None,
            )
            server_socket.sendto(response_data, client_address)
            return

        # Root-hints queries can be answered locally without contacting upstream DNS servers.
        resolution_result = build_root_hints_response(
            question, root_ns_records, root_a_records, root_a_map
        )

        if resolution_result is None:
            resolution_result = resolve_client_question(
                question, root_server_ips, timeout, cache
            )

        response_data = build_client_response(header, question, resolution_result)

        server_socket.sendto(response_data, client_address)

    except (ValueError, OSError):
        # Malformed client messages and per-query socket failures must not
        # terminate the main resolver process or affect other worker threads.
        return


def run_server(
    server_socket, root_ns_records, root_a_records, root_a_map, timeout, cache
):
    """
    Receive client DNS queries and dispatch each query to a worker thread.

    The main thread returns immediately to recvfrom(), allowing multiple
    client resolutions to overlap while workers wait for upstream replies.
    """

    # Root server IPs are the starting point for iterative resolution.
    root_server_ips = get_root_server_ips(root_ns_records, root_a_records)

    while True:
        query_data, client_address = server_socket.recvfrom(MAX_DNS_MESSAGE_SIZE)

        worker = threading.Thread(
            target=handle_client_query,
            args=(
                server_socket,
                query_data,
                client_address,
                root_ns_records,
                root_a_records,
                root_a_map,
                root_server_ips,
                timeout,
                cache,
            ),
            daemon=True,
        )
        worker.start()


def main():
    root_hints_file, timeout, listen_port = parse_args()
    root_ns_records, root_a_records, root_a_map = parse_root_hints(root_hints_file)
    server_socket = create_server_socket(listen_port)
    cache = DNSCache()

    try:
        run_server(
            server_socket, root_ns_records, root_a_records, root_a_map, timeout, cache
        )
    except KeyboardInterrupt:
        pass
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
