from cProfile import label
from dns_records import DNSHeader, DNSQuestion

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

    while True:
        length, offset = read_bytes(data, offset, 1)
        length = length[0]

        if length == 0:
            break

        label_bytes, offset = read_bytes(data, offset, length)
        label = label_bytes.decode('ascii')
        labels.append(label)
    
    return f'{".".join(labels)}.', offset