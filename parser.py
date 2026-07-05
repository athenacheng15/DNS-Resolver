import sys
from dns_message import parse_header, parse_questions, parse_resource_records
from dns_records import RCODE_MAP,  TYPE_MAP, CLASS_MAP

def print_records(title, records):
    print(f"{title}")

    if len(records) == 0:
        print("No records\n")
        return

    for record in records:
        print(f"{record.name} {record.ttl} {CLASS_MAP.get(record.rclass, 'UNKNOWN')} {TYPE_MAP.get(record.rtype, 'UNKNOWN')} {record.rdata}")
    print()


def print_questions(questions):
    print("--- QUESTIONS ---")
    for question in questions:
        print(f"{question.qname} {CLASS_MAP.get(question.qclass, 'UNKNOWN')} {TYPE_MAP.get(question.qtype, 'UNKNOWN')}")
    print()


def print_counts(header):
    print("--- COUNTS ---")
    print(f"QDCOUNT: {header.qdcount} (Questions)")
    print(f"ANCOUNT: {header.ancount} (Answers)")
    print(f"NSCOUNT: {header.nscount} (Authorities)")
    print(f"ARCOUNT: {header.arcount} (Additional)")
    print()


def print_flags(header):
    print("--- FLAGS ---")
    print(f"QR: {header.qr}")
    print(f"Opcode: {header.opcode}")
    print(f"AA: {header.aa} (Authoritative Answer)")
    print(f"TC: {header.tc} (Truncated)")
    print(f"RD: {header.rd} (Recursion Desired)")
    print(f"RA: {header.ra} (Recursion Available)")
    print(f"RCODE: {header.rcode} ({RCODE_MAP.get(header.rcode, 'UNKNOWN')})")
    print()


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 parser.py <dns-message-file>")
        sys.exit(1)
    
    filename = sys.argv[1]

    with open(filename, 'rb') as file: # r:read, b:binary
        data = file.read()

    header, offset = parse_header(data)
    questions, offset = parse_questions(data, offset, header.qdcount)
    answers, offset = parse_resource_records(data, offset, header.ancount)
    authorities, offset = parse_resource_records(data, offset, header.nscount)
    additional, offset = parse_resource_records(data, offset, header.arcount)

    print(f"ID : {header.message_id}")
    print_flags(header)
    print_counts(header)
    print_questions(questions)
    print_records("--- ANSWERS ---", answers)
    print_records("--- AUTHORITIES ---", authorities)
    print_records("--- ADDITIONAL ---", additional)

    # For debugging:
    # print(f"Next offset: {offset}")
    # print(f"File size: {len(data)} bytes")
    
if __name__ == "__main__":
    main()