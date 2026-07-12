import socket
import sys

from root_hints import parse_root_hints


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


MAX_DNS_MESSAGE_SIZE = 4096


def run_server(server_socket):
    while True:
        query_data, client_address = server_socket.recvfrom(MAX_DNS_MESSAGE_SIZE)
        print(f"Received {len(query_data)} bytes from {client_address}")
