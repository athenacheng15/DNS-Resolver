class DNSHeader:
    def __init__(self, message_id, flags, qdcount, ancount, nscount, arcount):
        self.message_id = message_id
        self.flags = flags

        self.qr = (flags>>15) & 1
        self.opcode = (flags>>11) & 0b1111
        self.aa = (flags>>10) & 1
        self.tc = (flags>>9) & 1
        self.rd = (flags>>8) & 1
        self.ra = (flags>>7) & 1
        self.rcode = flags & 0b1111
        

        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

class DNSQuestion:
    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

class ResourceRecord:
    def __init__(self, name, rtype, rclass, ttl, rdlength, rdata):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata = rdata

class DNSMessage:
    def __init__(self, header, questions, answers, authority, additional):
        self.header = header
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional

# -----------------------------
# DNS Lookup Tables
# -----------------------------

# DNS record type lookup table
TYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    28: "AAAA",
}

# DNS class lookup table
CLASS_MAP = {
    1: "IN",
}

# DNS response code lookup table
RCODE_MAP = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}