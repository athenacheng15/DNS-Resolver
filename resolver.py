import sys, socket

from root_hints import parse_root_hints
from dns_message import parse_header, parse_questions
from dns_records import TYPE_MAP, CLASS_MAP
from dns_encoder import encode_dns_response


def parse_args():
    if len(sys.argv) != 4:
        print("Usage: python3 resolver.py " "<root_hints_file> <timeout> <listen_port>")
        sys.exit(1)

    root_hints_file = sys.argv[1]
    timeout = int(sys.argv[2])
    listen_port = int(sys.argv[3])

    return root_hints_file, timeout, listen_port


def load_root_hints(root_hints_file):
    root_ns_records, root_a_records, root_a_map = parse_root_hints(root_hints_file)

    print(f"Loaded {len(root_ns_records)} root NS records")
    print(f"Loaded {len(root_a_records)} root A records")

    return root_ns_records, root_a_records, root_a_map


def create_server_socket(listen_port):
    # socket.AF_INET for IPv4, socket.SOCK_DGRAM for UDP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("127.0.0.1", listen_port)
    server_socket.bind(server_address)

    print(f"Resolver server socket  listening on 127.0.0.1:{listen_port}")

    return server_socket


def create_request_state(client_address, header, question):
    client_ip, client_port = client_address

    return {
        "client_address": client_ip,
        "client_port": client_port,
        "original_id": header.message_id,
        "question": question,
    }


def decode_client_query(query_data):
    header, offset = parse_header(query_data)
    questions, offset = parse_questions(query_data, offset, header.qdcount)

    return header, questions


MAX_DNS_MESSAGE_SIZE = 4096


def run_server(server_socket):
    while True:
        query_data, client_address = server_socket.recvfrom(MAX_DNS_MESSAGE_SIZE)
        print(f"Received {len(query_data)} bytes from {client_address}")

        try:
            header, questions = decode_client_query(query_data)

            if len(questions) == 0:
                print("Invalid query: no questions")
                continue

            question = questions[0]
            request_state = create_request_state(client_address, header, question)
            print_request_state(request_state)

            response_data = encode_dns_response(
                query_header=header,
                question=question,
            )

            server_socket.sendto(
                response_data,
                client_address,
            )

            print(f"Sent {len(response_data)} bytes " f"to {client_address}")

        except ValueError as e:
            print(f"Failed to parse DNS query: {e}")


def print_request_state(request_state):
    question = request_state["question"]

    qtype_name = TYPE_MAP.get(question.qtype, f"UNKNOWN {question.qtype}")
    qclass_name = CLASS_MAP.get(question.qclass, f"UNKNOWN {question.qclass}")

    print("--- CLIENT QUERY ---")
    print(
        f"Client: "
        f"{request_state['client_address']}:"
        f"{request_state['client_port']}"
    )
    print(f"ID: {request_state['original_id']}")
    print(f"QNAME: {question.qname}")
    print(f"QTYPE: {question.qtype} ({qtype_name})")
    print(f"QCLASS: {question.qclass} ({qclass_name})")


def main():
    root_hints_file, timeout, listen_port = parse_args()
    root_ns_records, root_a_records, root_a_map = load_root_hints(root_hints_file)
    server_socket = create_server_socket(listen_port)

    try:
        run_server(server_socket)
    except KeyboardInterrupt:
        print("Shutting down resolver server...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
