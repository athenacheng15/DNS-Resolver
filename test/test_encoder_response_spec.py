import unittest
from unittest.mock import patch

from dns.encoder import encode_dns_response, encode_upstream_query
from dns.message import parse_dns_message
from test.helpers import header, question, rr


class EncoderResponseSpecificationTests(unittest.TestCase):
    def test_upstream_query_has_fresh_id_and_required_non_recursive_shape(self):
        with patch("dns.encoder.secrets.randbits", return_value=0xCAFE):
            transaction_id, wire = encode_upstream_query(question("Example.COM.", 15))
        parsed = parse_dns_message(wire)
        self.assertEqual(transaction_id, 0xCAFE)
        self.assertEqual(parsed.header.message_id, 0xCAFE)
        self.assertEqual(parsed.header.flags, 0)
        self.assertEqual((parsed.header.qdcount, parsed.header.ancount, parsed.header.nscount, parsed.header.arcount), (1, 0, 0, 0))
        self.assertEqual((parsed.questions[0].qname, parsed.questions[0].qtype, parsed.questions[0].qclass), ("Example.COM.", 15, 1))

    def test_client_response_copies_id_opcode_rd_and_sets_required_flags(self):
        query_header = header(0x4242, (3 << 11) | (1 << 8))
        wire = encode_dns_response(query_header, question(), [rr("www.example.com.", 1, "192.0.2.4")], rcode=3, aa=1)
        parsed = parse_dns_message(wire)
        self.assertEqual(parsed.header.message_id, 0x4242)
        self.assertEqual((parsed.header.qr, parsed.header.opcode, parsed.header.aa, parsed.header.tc), (1, 3, 1, 0))
        self.assertEqual((parsed.header.rd, parsed.header.ra, parsed.header.rcode), (1, 1, 3))
        self.assertEqual(parsed.header.flags & 0x70, 0)  # Z, AD and CD

    def test_counts_equal_records_actually_encoded(self):
        wire = encode_dns_response(
            header(), question(),
            [rr("example.com.", 1, "192.0.2.1")],
            [rr("example.com.", 2, "ns.example.com.")],
            [rr("ns.example.com.", 1, "192.0.2.53")],
        )
        parsed = parse_dns_message(wire)
        self.assertEqual((parsed.header.qdcount, parsed.header.ancount, parsed.header.nscount, parsed.header.arcount), (1, 1, 1, 1))
        self.assertEqual(parsed.questions[0].qname, "www.example.com.")


if __name__ == "__main__":
    unittest.main()
