import sys, socket, time

from root_hints import parse_root_hints
from dns_message import parse_header, parse_questions, parse_dns_message
from dns_encoder import encode_dns_response, encode_upstream_query
from dns_records import DNSQuestion

UPSTREAM_DNS_PORT = 53
MAX_DNS_MESSAGE_SIZE = 4096

MAX_OUTBOUND_ATTEMPTS = 50
MAX_REFERRAL_LEVELS = 10

TYPE_A = 1
TYPE_NS = 2
CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3


class ResolutionLimitError(Exception):
    pass


class ResloutionBudget:
    def __init__(self):
        self.outbount_attempts = 0
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
            and record_name_matches(record, question.qname)
        ):
            answers.append(record)
    return answers


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
            if additional_record.rclass == CLASS_IN:
                continue
            if additional_record.rtype != TYPE_A:
                continue

            additional_name = normalize_dns_name(additional_record.name)
            if additional_name == ns_name:
                glue_ips.append(additional_record)

    return glue_ips


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


def run_server(server_socket, root_ns_records, root_a_records, root_a_map):
    while True:
        query_data, client_address = server_socket.recvfrom(MAX_DNS_MESSAGE_SIZE)

        try:
            header, questions = decode_client_query(query_data)

            if len(questions) == 0:
                print("Invalid query: no questions")
                continue

            question = questions[0]

            local_response = build_root_hints_response(
                question, root_ns_records, root_a_records, root_a_map
            )

            if local_response is None:
                response_data = encode_dns_response(
                    query_header=header,
                    question=question,
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
        run_server(server_socket, root_ns_records, root_a_records, root_a_map)
    except KeyboardInterrupt:
        pass
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
