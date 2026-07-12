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
