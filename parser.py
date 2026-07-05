import sys
from dns_message import parse_header, parse_questions, parse_resource_records
from dns_records import RCODE_MAP,  TYPE_MAP, CLASS_MAP

def print_records(title, records):
    print(f"{title}")
    print("---------")

    if len(records) == 0:
        print("No records\n")
        return

    for record in records:
        print(f"NAME: {record.name}")
        print(f"TYPE: {record.rtype} ({TYPE_MAP.get(record.rtype, 'UNKNOWN')})")
        print(f"CLASS: {record.rclass} ({CLASS_MAP.get(record.rclass, 'UNKNOWN')})")
        print(f"TTL: {record.ttl}")
        print(f"RDLENGTH: {record.rdlength}")
        print(f"RDATA: {record.rdata}")
        print()

def print_questions(questions):
    print("Question")
    print("---------")
    for question in questions:
        print(f"QNAME: {question.qname}")
        print(f"QTYPE: {question.qtype} ({TYPE_MAP.get(question.qtype, 'UNKNOWN')})")
        print(f"QCLASS: {question.qclass} ({CLASS_MAP.get(question.qclass, 'UNKNOWN')})")
        print()


def print_header(header):
    print("DNS Header")
    print("----------")
    print(f"ID: {header.message_id}")
    print(f"Flags: {header.flags}")
    print(f"QDCOUNT: {header.qdcount}")
    print(f"ANCOUNT: {header.ancount}")
    print(f"NSCOUNT: {header.nscount}")
    print(f"ARCOUNT: {header.arcount}")
    print()


def print_flags(header):
    print("Flags")
    print("-----------")
    print(f"QR: {header.qr}")
    print(f"Opcode: {header.opcode}")
    print(f"AA: {header.aa}")
    print(f"TC: {header.tc}")
    print(f"RD: {header.rd}")
    print(f"RA: {header.ra}")
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


    print_questions(questions)
    print_header(header)
    print_flags(header)

    print_records("Answers", answers)
    print_records("Authorities", authorities)
    print_records("Additional", additional)

    print(f"Next offset: {offset}")
    print(f"File size: {len(data)} bytes")
    
if __name__ == "__main__":
    main()