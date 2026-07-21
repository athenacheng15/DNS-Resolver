import socket, struct, secrets


def encode_uint16(value):
    # ! for network byte order, H for 16-bit unsigned integer
    return struct.pack("!H", value)


def encode_uint32(value):
    # ! for network byte order, I for 32-bit unsigned integer
    return struct.pack("!I", value)


def encode_name(name):
    message = bytearray()
    _append_name(message, name)
    return bytes(message)


def encode_question(question):
    message = bytearray()
    _append_question(message, question)
    return bytes(message)


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
    message = bytearray()
    _append_mx_rdata(message, rdata)
    return bytes(message)


def encode_rdata(record):
    message = bytearray()
    _append_rdata(message, record)
    return bytes(message)


def encode_resource_record(record):
    message = bytearray()
    _append_resource_record(message, record)
    return bytes(message)


def encode_records(records):
    message = bytearray()
    _append_records(message, records)
    return bytes(message)


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


def _append_name(message, name, name_offsets=None):
    """
    Append a DNS name, optionally compressing it against earlier suffixes.

    When supplied, name_offsets maps normalised DNS suffixes to their
    absolute offsets in the complete DNS message.
    """
    if name == ".":
        if name_offsets is not None:
            name_offsets.setdefault(".", len(message))
        message.append(0)
        return

    labels = name.rstrip(".").split(".")
    encoded_labels = []
    total_length = 1  # Include the final zero-length root label.

    for label in labels:
        label_bytes = label.encode("ascii")

        if len(label_bytes) > 63:
            raise ValueError(f"DNS label is longer than 63 bytes: {label}")

        total_length += len(label_bytes) + 1
        if total_length > 255:
            raise ValueError("DNS name is longer than 255 bytes")

        encoded_labels.append(label_bytes)

    for index, label_bytes in enumerate(encoded_labels):
        suffix = ".".join(labels[index:]).lower() + "."

        if name_offsets is not None and suffix in name_offsets:
            pointer_offset = name_offsets[suffix]

            if pointer_offset >= 0x4000:
                raise ValueError("DNS compression pointer offset is too large")

            pointer = 0xC000 | pointer_offset
            message.extend(struct.pack("!H", pointer))
            return

        if name_offsets is not None:
            name_offsets[suffix] = len(message)

        message.append(len(label_bytes))
        message.extend(label_bytes)

    if name_offsets is not None:
        name_offsets.setdefault(".", len(message))
    message.append(0)


def _append_question(message, question, name_offsets=None):
    _append_name(message, question.qname, name_offsets)
    message.extend(encode_uint16(question.qtype))
    message.extend(encode_uint16(question.qclass))


def _append_mx_rdata(message, rdata, name_offsets=None):
    message.extend(encode_uint16(rdata["preference"]))
    _append_name(message, rdata["exchange"], name_offsets)


def _append_rdata(message, record, name_offsets=None):
    if record.rtype == 1:
        message.extend(encode_a_rdata(record.rdata))
        return

    if record.rtype in (2, 5, 12):
        _append_name(message, record.rdata, name_offsets)
        return

    if record.rtype == 15:
        _append_mx_rdata(message, record.rdata, name_offsets)
        return

    raise ValueError(f"Unsupported DNS record type: {record.rtype}")


def _append_resource_record(message, record, name_offsets=None):
    _append_name(message, record.name, name_offsets)
    message.extend(struct.pack("!HHI", record.rtype, record.rclass, record.ttl))

    rdlength_position = len(message)
    message.extend(b"\x00\x00")

    rdata_start = len(message)
    _append_rdata(message, record, name_offsets)
    rdlength = len(message) - rdata_start

    # Root hints records store RDLENGTH as 0, so calculate it from encoded RDATA.
    message[rdlength_position : rdlength_position + 2] = encode_uint16(rdlength)


def _append_records(message, records, name_offsets=None):
    for record in records:
        _append_resource_record(message, record, name_offsets)


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
    _append_question(message, question, name_offsets)
    _append_records(message, answers, name_offsets)
    _append_records(message, authorities, name_offsets)
    _append_records(message, additional, name_offsets)

    return bytes(message)
