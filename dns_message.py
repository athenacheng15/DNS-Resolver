from cProfile import label
from dns_records import DNSHeader, DNSQuestion, ResourceRecord

# Ensure that there are enough bytes remaining to read.
def ensure_available(data, offset, length):
    if offset + length > len(data):
        raise ValueError("Unexpected end of DNS message")


# Read an unsigned 16-bit integer.
# Returns: (value, next_offset) e.g. (44325, 2) for 44325 at offset 2
def read_uint16(data, offset):
    ensure_available(data, offset, 2)
    value = int.from_bytes(data[offset:offset+2], 'big')  
    return value, offset + 2


# Read an unsigned 32-bit integer.
# Returns: (value, next_offset) e.g. (44325, 4) for 44325 at offset 4
def read_uint32(data, offset):
    ensure_available(data, offset, 4)
    value = int.from_bytes(data[offset:offset+4], 'big')
    return value, offset + 4


# Read a sequence of bytes.
# Returns: (bytes, next_offset) e.g. (b'\x03www', 16)
def read_bytes(data, offset, length):
    ensure_available(data, offset, length)
    return data[offset:offset+length], offset + length


# Parse the header of a DNS message.
# Returns: (header, next_offset) e.g. (DNSHeader(44325, 0x0100, 1, 0, 0, 0), 12)
def parse_header(data):
    offset = 0
    message_id, offset = read_uint16(data, offset)
    flags, offset = read_uint16(data, offset)
    qdcount, offset = read_uint16(data, offset)
    ancount, offset = read_uint16(data, offset)
    nscount, offset = read_uint16(data, offset)
    arcount, offset = read_uint16(data, offset)
    header = DNSHeader(message_id, flags, qdcount, ancount, nscount, arcount)

    return header, offset

# Parse a DNS domain name.
# Returns: (name, next_offset) e.g. ("www.example.com.", 29)
def parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset
    jumps = 0
    total_length = 0
    visited_offsets = set()

    while True:

        ensure_available(data, offset, 1)

        if offset in visited_offsets:
            raise ValueError("Pointer loop detected")

        visited_offsets.add(offset)
        length = data[offset]

        # Pointer: first two bits are 11
        if (length & 0xC0) == 0xC0:
            ensure_available(data, offset, 2)

            if jumps > 20:
                raise ValueError("Too many DNS compression pointer jumps")

            pointer_bytes = data[offset:offset+2]
            pointer_offset = int.from_bytes(pointer_bytes, 'big') & 0x3FFF  # Network Byte Order = Big Endian

            if pointer_offset >= len(data):
                raise ValueError("Pointer offset is out of bounds")

            if not jumped:
                original_offset = offset+2
                jumped = True

            offset = pointer_offset
            jumps += 1
            continue

        # Invalid label type
        if (length & 0xC0) != 0:
            raise ValueError("Invalid DNS label format")

        offset += 1

        # End of name
        if length == 0:
            if not jumped:
                original_offset = offset
            break

        # Label length
        if length > 63:
            raise ValueError("Label length is too long (longer than 63 bytes)")

        ensure_available(data, offset, length)
        label_bytes = data[offset:offset+length]
        label = label_bytes.decode('ascii')
        labels.append(label)

        total_length += length + 1

        if total_length > 255:
            raise ValueError("Domain name is too long (longer than 255 bytes)")

        offset += length

    return f'{".".join(labels)}.', original_offset


# Parse one DNS question.
# Reads QNAME, QTYPE, and QCLASS from the DNS question section.
# Returns: (question, next_offset) e.g. (DNSQuestion("www.example.com.", 1, 1), 33)
def parse_question(data, offset):
    name, offset = parse_name(data, offset)
    qtype, offset = read_uint16(data, offset)
    qclass, offset = read_uint16(data, offset)

    question = DNSQuestion(name, qtype, qclass)
    return question, offset


# Parse all DNS questions based on QDCOUNT.
# Returns: (questions, next_offset) e.g. ([DNSQuestion("www.example.com.", 1, 1)], 33)
def parse_questions(data, offset, qdcount):
    questions = []
    for _ in range(qdcount):
        question, offset = parse_question(data, offset)
        questions.append(question)

    return questions, offset


# Parse one DNS resource record.
# Reads NAME, TYPE, CLASS, TTL, RDLENGTH, and RDATA.
# Returns: (record, next_offset) e.g. (ResourceRecord("www.example.com.", 1, 1, 300, 4, "142.250.181.14"), 49)
def parse_resource_record(data, offset):
    name, offset = parse_name(data, offset)
    rtype, offset = read_uint16(data, offset)
    rclass, offset = read_uint16(data, offset)
    ttl, offset = read_uint32(data, offset)
    rdlength, offset = read_uint16(data, offset)

    rdata_offset = offset
    rdata, offset = parse_rdata(data, rdata_offset, rtype, rdlength)

    record = ResourceRecord(name, rtype, rclass, ttl, rdlength, rdata)

    return record, offset


# Parse RDATA based on the DNS record type.
# Returns: (rdata, next_offset) e.g. ("142.250.181.14", 49) for an A record
def parse_rdata(data, offset, rtype, rdlength):
    rdata_start = offset
    rdata_end = offset + rdlength

    ensure_available(data, offset, rdlength)

    try:

        # A record: must be exactly 4 bytes
        if rtype == 1:
            if rdlength != 4:
                return malformed_rdata("A record RDATA must be 4 bytes"), rdata_end

            rdata, _ = read_bytes(data, offset, 4)
            return ".".join(str(byte) for byte in rdata), rdata_end

        # NS, CNAME, PTR: RDATA is a domain name
        if rtype in (2, 5, 12):
            name, _ = parse_name(data, offset)
            return name, rdata_end
        
        # MX: 2 bytes preference + domain name
        if rtype == 15:
            if rdlength < 3:
                return malformed_rdata("MX record RDATA is too short"), rdata_end

            preference, name_offset = read_uint16(data, offset)
            exchange, _ = parse_name(data, name_offset)

            return {
                "preference": preference,
                "exchange": exchange
            }, rdata_end
    
        # Unknown type: skip safely
        rdata, _ = read_bytes(data, offset, rdlength)
        return {
            "status": "unsupported",
            "raw": rdata
        }, rdata_end
        
    except ValueError as e:
        return malformed_rdata(str(e)), rdata_end


# Parse multiple DNS resource records.
# The count may come from ANCOUNT, NSCOUNT, or ARCOUNT.
# Returns: (records, next_offset) e.g. ([ResourceRecord("www.example.com.", 1, 1, 300, 4, "142.250.181.14")], 49)
def parse_resource_records(data, offset, count):
    records = []

    for _ in range(count):
        record, offset = parse_resource_record(data, offset)
        records.append(record)

    return records, offset


def malformed_rdata(reason):
    return {
        "status": "malformed",
        "reason": reason
    }