import sys
from dns_message import parse_header

def main():
    filename = sys.argv[1]

    with open(filename, 'rb') as file: # r:read, b:binary
        data = file.read()

    header, offset = parse_header(data)
    print("ID:", header.message_id)
    print("Flags:", header.flags)
    print("QDCOUNT:", header.qdcount)
    print("ANCOUNT:", header.ancount)
    print("NSCOUNT:", header.nscount)
    print("ARCOUNT:", header.arcount)
    print("Next offset:", offset)

    print(f"File size: {len(data)} bytes")

if __name__ == "__main__":
    main()