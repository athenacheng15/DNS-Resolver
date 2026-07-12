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
