import struct

from dns.encoder import encode_name
from dns.records import DNSHeader, DNSMessage, DNSQuestion, ResourceRecord


def question(name="www.example.com.", qtype=1, qclass=1):
    return DNSQuestion(name, qtype, qclass)


def header(message_id=0x1234, flags=0x0100, qd=1, an=0, ns=0, ar=0):
    return DNSHeader(message_id, flags, qd, an, ns, ar)


def rr(name, rtype, rdata, ttl=300, rclass=1, rdlength=0):
    return ResourceRecord(name, rtype, rclass, ttl, rdlength, rdata)


def message(*, flags=0x8000, questions=None, answers=None, authority=None, additional=None):
    questions = questions or [question()]
    answers = answers or []
    authority = authority or []
    additional = additional or []
    return DNSMessage(
        header(0xBEEF, flags, len(questions), len(answers), len(authority), len(additional)),
        questions,
        answers,
        authority,
        additional,
    )


def wire_question(name, qtype=1, qclass=1):
    return encode_name(name) + struct.pack("!HH", qtype, qclass)


def wire_rr(name_wire, rtype, rdata, ttl=300, rclass=1):
    return name_wire + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def wire_message(*, message_id=0x1234, flags=0x8180, questions=(), answers=(), authority=(), additional=()):
    return (
        struct.pack("!HHHHHH", message_id, flags, len(questions), len(answers), len(authority), len(additional))
        + b"".join(questions)
        + b"".join(answers)
        + b"".join(authority)
        + b"".join(additional)
    )
