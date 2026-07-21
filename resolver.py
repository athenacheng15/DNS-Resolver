import socket
import sys
import threading

from cache import DNSCache
from constants import (
    MAX_CLIENT_DNS_RESPONSE_SIZE,
    MAX_RECEIVED_DNS_MESSAGE_SIZE,
    RCODE_SERVFAIL,
)
from dns.encoder import encode_dns_response
from dns.message import parse_header, parse_questions
from resolver_core.helpers import (
    build_root_hints_response,
    filter_encodable_records,
    get_root_server_ips,
    is_supported_client_question,
)
from resolver_core.iterative import resolve_client_question
from root_hints import parse_root_hints


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


def build_client_response(query_header, question, resolution_result):
    # Convert the resolution result into sections that the encoder supports.
    # A missing result represents a failed resolution.
    if resolution_result is None:
        answers = []
        authorities = []
        additional = []
        rcode = RCODE_SERVFAIL
        aa = 0
    else:
        answers = filter_encodable_records(resolution_result["answers"])
        authorities = filter_encodable_records(resolution_result["authorities"])
        additional = filter_encodable_records(resolution_result["additional"])
        rcode = resolution_result["rcode"]
        aa = resolution_result["aa"]

    # Encoding errors and responses over the UDP size limit fall back to SERVFAIL.
    try:
        response = encode_dns_response(
            query_header,
            question,
            answers,
            authorities,
            additional,
            rcode,
            aa,
        )
    except ValueError:
        response = None

    if response is not None and len(response) <= MAX_CLIENT_DNS_RESPONSE_SIZE:
        return response

    servfail_response = encode_dns_response(
        query_header=query_header,
        question=question,
        rcode=RCODE_SERVFAIL,
    )

    if len(servfail_response) > MAX_CLIENT_DNS_RESPONSE_SIZE:
        raise ValueError("SERVFAIL response exceeds client UDP size limit")

    return servfail_response


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
    try:
        header, questions = decode_client_query(query_data)

        #  supports exactly one question per client query.
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
        # Malformed client messages and per-query socket failures won't terminate the main resolver process
        # or affect other worker threads.
        return


def run_server(
    server_socket, root_ns_records, root_a_records, root_a_map, timeout, cache
):

    # Root server IPs are the starting point for iterative resolution.
    root_server_ips = get_root_server_ips(root_ns_records, root_a_records)

    while True:
        query_data, client_address = server_socket.recvfrom(
            MAX_RECEIVED_DNS_MESSAGE_SIZE
        )

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
