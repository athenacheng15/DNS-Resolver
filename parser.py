import sys
from dns_message import parse_header
from dns_records import RCODE_MAP

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 parser.py <dns-message-file>")
        sys.exit(1)
    
    filename = sys.argv[1]

    with open(filename, 'rb') as file: # r:read, b:binary
        data = file.read()

    header, offset = parse_header(data)

    print("DNS Header")
    print("----------")
    print(f"ID: {header.message_id}")
    print(f"Flags: {header.flags}")
    print(f"QDCOUNT: {header.qdcount}")
    print(f"ANCOUNT: {header.ancount}")
    print(f"NSCOUNT: {header.nscount}")
    print(f"ARCOUNT: {header.arcount}")
    print()

    print("FLAGS")
    print("-----------")
    print(f"QR: {header.qr}")
    print(f"Opcode: {header.opcode}")
    print(f"AA: {header.aa}")
    print(f"TC: {header.tc}")
    print(f"RD: {header.rd}")
    print(f"RA: {header.ra}")
    print(f"RCODE: {header.rcode} ({RCODE_MAP.get(header.rcode, 'UNKNOWN')})")
    print()

    print(f"Next offset: {offset}")
    print(f"File size: {len(data)} bytes")
    
if __name__ == "__main__":
    main()