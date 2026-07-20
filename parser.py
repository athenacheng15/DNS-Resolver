import sys
from dns_message import parse_header, parse_questions, parse_resource_records
from dns_records import RCODE_MAP, TYPE_MAP, CLASS_MAP


def format_type(type_number):
    return TYPE_MAP.get(type_number, f"TYPE{type_number}")


def format_class(class_number):
    return CLASS_MAP.get(class_number, f"CLASS{class_number}")


def print_records(title, records):
    print(title)

    if len(records) == 0:
        print("No records\n")
        return

    for record in records:
        rclass = format_class(record.rclass)
        rtype = format_type(record.rtype)

        if isinstance(record.rdata, dict):
            status = record.rdata.get("status")

            if status in ("unsupported", "malformed"):
                print(
                    f"{record.name} {record.ttl} "
                    f"{rclass} {rtype} "
                    f"RDLENGTH {record.rdlength}"
                )
                continue

            # MX record
            if "preference" in record.rdata and "exchange" in record.rdata:
                preference = record.rdata["preference"]
                exchange = record.rdata["exchange"]

                print(
                    f"{record.name} {record.ttl} "
                    f"{rclass} {rtype} "
                    f"{preference} {exchange}"
                )
                continue

        print(f"{record.name} {record.ttl} " f"{rclass} {rtype} {record.rdata}")

    print()


def print_questions(questions):
    print("--- QUESTIONS ---")
    for question in questions:
        qclass = format_class(question.qclass)
        qtype = format_type(question.qtype)

        print(f"{question.qname} {qclass} {qtype}")

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

    with open(filename, "rb") as file:  # r:read, b:binary
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
    print_records("--- AUTHORITY ---", authorities)
    print_records("--- ADDITIONAL ---", additional)

    # For debugging:
    # print(f"Next offset: {offset}")
    # print(f"File size: {len(data)} bytes")


if __name__ == "__main__":
    main()
