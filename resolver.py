import sys, socket

from root_hints import parse_root_hints
from dns_message import parse_header, parse_questions
from dns_encoder import encode_dns_response, encode_upstream_query

UPSTREAM_DNS_PORT = 53
MAX_DNS_MESSAGE_SIZE = 4096


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


def send_upstream_query(server_ip, question, timeout):
    transaction_id, query_data = encode_upstream_query(question)

    upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_socket.settimeout(timeout)

    try:
        upstream_socket.sendto(query_data, (server_ip, UPSTREAM_DNS_PORT))
        response_data, response_address = upstream_socket.recvfrom(MAX_DNS_MESSAGE_SIZE)
        return {
            "transaction_id": transaction_id,
            "response_data": response_data,
            "response_address": response_address,
        }
    except socket.timeout:
        return None
    finally:
        upstream_socket.close()


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
