import socket, struct, secrets


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


def encode_mx_rdata(rdata):
    preference = rdata["preference"]
    exchange = rdata["exchange"]

    return encode_uint16(preference) + encode_name(exchange)


def encode_rdata(record):
    if record.rtype == 1:
        return encode_a_rdata(record.rdata)

    if record.rtype in (2, 5, 12):
        return encode_name(record.rdata)

    if record.rtype == 15:
        return encode_mx_rdata(record.rdata)

    raise ValueError(f"Unsupported DNS record type: {record.rtype}")


def encode_resource_record(record):

    encoded_name = encode_name(record.name)
    encoded_rdata = encode_rdata(record)

    fixed_fields = struct.pack(
        "!HHIH",
        record.rtype,
        record.rclass,
        record.ttl,
        len(encoded_rdata),
    )
    # Recalculate RDLENGTH from the actual encoded RDATA because root hints records store it as 0.

    return encoded_name + fixed_fields + encoded_rdata


def encode_records(records):
    encoded = bytearray()
    for record in records:
        encoded.extend(encode_resource_record(record))
    return bytes(encoded)


def encode_upstream_query(question):
    transaction_id = secrets.randbits(16)
    flags = build_upstream_query_flags()

    header_bytes = encode_header(
        message_id=transaction_id,
        flags=flags,
        question_count=1,
        answer_count=0,
        authority_count=0,
        additional_count=0,
    )
    question_bytes = encode_question(question)
    query_data = header_bytes + question_bytes

    return transaction_id, query_data


def encode_name_compressed(name, message, name_offsets):
    """
    Append a DNS name to message using a pointer to an earlier suffix
    when possible.

    name_offsets maps normalised DNS suffixes to offsets in message.
    """
    if name == ".":
        root_offset = len(message)
        name_offsets.setdefault(".", root_offset)
        message.append(0)
        return

    labels = name.rstrip(".").split(".")

    for index, label in enumerate(labels):
        suffix = ".".join(labels[index:]).lower() + "."

        if suffix in name_offsets:
            pointer_offset = name_offsets[suffix]

            if pointer_offset >= 0x4000:
                raise ValueError("DNS compression pointer offset is too large")

            pointer = 0xC000 | pointer_offset
            message.extend(struct.pack("!H", pointer))
            return

        name_offsets[suffix] = len(message)

        label_bytes = label.encode("ascii")

        if len(label_bytes) > 63:
            raise ValueError(f"DNS label is longer than 63 bytes: {label}")

        message.append(len(label_bytes))
        message.extend(label_bytes)

    name_offsets.setdefault(".", len(message))
    message.append(0)


def append_question_compressed(
    message,
    question,
    name_offsets,
):
    encode_name_compressed(
        question.qname,
        message,
        name_offsets,
    )
    message.extend(encode_uint16(question.qtype))
    message.extend(encode_uint16(question.qclass))


def append_rdata_compressed(
    message,
    record,
    name_offsets,
):
    if record.rtype == 1:
        message.extend(encode_a_rdata(record.rdata))
        return

    if record.rtype in (2, 5, 12):
        encode_name_compressed(
            record.rdata,
            message,
            name_offsets,
        )
        return

    if record.rtype == 15:
        preference = record.rdata["preference"]
        exchange = record.rdata["exchange"]

        message.extend(encode_uint16(preference))
        encode_name_compressed(
            exchange,
            message,
            name_offsets,
        )
        return

    raise ValueError(f"Unsupported DNS record type: {record.rtype}")


def append_resource_record_compressed(
    message,
    record,
    name_offsets,
):
    encode_name_compressed(
        record.name,
        message,
        name_offsets,
    )

    message.extend(encode_uint16(record.rtype))
    message.extend(encode_uint16(record.rclass))
    message.extend(encode_uint32(record.ttl))

    rdlength_position = len(message)
    message.extend(b"\x00\x00")

    rdata_start = len(message)

    append_rdata_compressed(
        message,
        record,
        name_offsets,
    )

    rdlength = len(message) - rdata_start

    message[rdlength_position : rdlength_position + 2] = encode_uint16(rdlength)


def append_records_compressed(
    message,
    records,
    name_offsets,
):
    for record in records:
        append_resource_record_compressed(
            message,
            record,
            name_offsets,
        )


def encode_dns_response_compressed(
    query_header,
    question,
    answers=None,
    authorities=None,
    additional=None,
    rcode=0,
    aa=0,
):
    answers = [] if answers is None else answers
    authorities = [] if authorities is None else authorities
    additional = [] if additional is None else additional

    flags = build_response_flags(
        query_header,
        rcode,
        aa,
    )

    message = bytearray(
        encode_header(
            message_id=query_header.message_id,
            flags=flags,
            question_count=1,
            answer_count=len(answers),
            authority_count=len(authorities),
            additional_count=len(additional),
        )
    )

    name_offsets = {}

    append_question_compressed(
        message,
        question,
        name_offsets,
    )

    append_records_compressed(
        message,
        answers,
        name_offsets,
    )
    append_records_compressed(
        message,
        authorities,
        name_offsets,
    )
    append_records_compressed(
        message,
        additional,
        name_offsets,
    )

    return bytes(message)


def build_upstream_query_flags():
    return 0


def build_response_flags(query_header, rcode=0, aa=0):
    flags = 0

    flags |= 1 << 15  # | for bitwise OR
    flags |= (query_header.opcode & 0xF) << 11
    flags |= (aa & 0x1) << 10
    flags |= (query_header.rd & 0x1) << 8
    flags |= 1 << 7
    flags |= rcode & 0xF

    return flags


def encode_dns_response(
    query_header,
    question,
    answers=None,
    authorities=None,
    additional=None,
    rcode=0,
    aa=0,
):
    answers = [] if answers is None else answers
    authorities = [] if authorities is None else authorities
    additional = [] if additional is None else additional

    flags = build_response_flags(query_header, rcode, aa)

    header_bytes = encode_header(
        message_id=query_header.message_id,
        flags=flags,
        question_count=1,
        answer_count=len(answers),
        authority_count=len(authorities),
        additional_count=len(additional),
    )

    question_bytes = encode_question(question)
    answer_bytes = encode_records(answers)
    authority_bytes = encode_records(authorities)
    additional_bytes = encode_records(additional)

    return (
        header_bytes
        + question_bytes
        + answer_bytes
        + authority_bytes
        + additional_bytes
    )
