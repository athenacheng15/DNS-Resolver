import socket, struct


def encode_uint16(value):
    # ! for network byte order, H for 16-bit unsigned integer
    return struct.pack("!H", value)


def encode_uint32(value):
    # ! for network byte order, I for 32-bit unsigned integer
    return struct.pack("!I", value)


def encode_name(name):
    if name == ".":
        return b"\x00"  # root label

    name = name.rstrip(".")
    labels = name.split(".")

    encoded = bytearray()

    for label in labels:
        label_bytes = label.encode("ascii")

        if len(label_bytes) > 63:
            raise ValueError(f"DNS label is longer than 63 bytes: {label}")

        encoded.append(len(label_bytes))
        encoded.extend(label_bytes)

    encoded.append(0)

    return bytes(encoded)


def encode_question(question):
    return (
        encode_name(question.qname)
        + encode_uint16(question.qtype)
        + encode_uint16(question.qclass)
    )


def encode_header(
    message_id, flags, question_count, answer_count, authority_count, additional_count
):
    return struct.pack(
        "!HHHHHH",
        message_id,
        flags,
        question_count,
        answer_count,
        authority_count,
        additional_count,
    )


def encode_a_rdata(address):
    try:
        # inet_aton Convert IPv4 address string into 4 network bytes. (e.g. b'\xc6)\x00\x04')
        return socket.inet_aton(address)
    except OSError as e:
        raise ValueError(f"Invalid IPv4 address: {address}") from e


def build_response_flags(query_header, rcode=0):
    flags = 0

    flags |= 1 << 15  # | for bitwise OR
    flags |= (query_header.opcode & 0xF) << 11
    flags |= (query_header.rd & 0x1) << 8
    flags |= 1 << 7
    flags |= rcode & 0xF

    return flags
