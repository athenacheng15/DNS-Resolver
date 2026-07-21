import unittest
from unittest.mock import patch

from dns.encoder import (
    encode_dns_response,
    encode_question,
    encode_records,
    encode_upstream_query,
)
from dns.message import parse_dns_message
from resolver import build_client_response, encode_client_response
from resolver_core.helpers import make_resolution_result
from resolver_core.constants import MAX_CLIENT_DNS_RESPONSE_SIZE, RCODE_SERVFAIL
from test.helpers import header, question, rr


class EncoderResponseSpecificationTests(unittest.TestCase):
    def test_upstream_query_has_fresh_id_and_required_non_recursive_shape(self):
        with patch("dns.encoder.secrets.randbits", return_value=0xCAFE):
            transaction_id, wire = encode_upstream_query(question("Example.COM.", 15))
        parsed = parse_dns_message(wire)
        self.assertEqual(transaction_id, 0xCAFE)
        self.assertEqual(parsed.header.message_id, 0xCAFE)
        self.assertEqual(parsed.header.flags, 0)
        self.assertEqual(
            (
                parsed.header.qdcount,
                parsed.header.ancount,
                parsed.header.nscount,
                parsed.header.arcount,
            ),
            (1, 0, 0, 0),
        )
        self.assertEqual(
            (
                parsed.questions[0].qname,
                parsed.questions[0].qtype,
                parsed.questions[0].qclass,
            ),
            ("Example.COM.", 15, 1),
        )

    def test_client_response_copies_id_opcode_rd_and_sets_required_flags(self):
        query_header = header(0x4242, (3 << 11) | (1 << 8))
        wire = encode_dns_response(
            query_header,
            question(),
            [rr("www.example.com.", 1, "192.0.2.4")],
            rcode=3,
            aa=1,
        )
        parsed = parse_dns_message(wire)
        self.assertEqual(parsed.header.message_id, 0x4242)
        self.assertEqual(
            (
                parsed.header.qr,
                parsed.header.opcode,
                parsed.header.aa,
                parsed.header.tc,
            ),
            (1, 3, 1, 0),
        )
        self.assertEqual(
            (parsed.header.rd, parsed.header.ra, parsed.header.rcode), (1, 1, 3)
        )
        self.assertEqual(parsed.header.flags & 0x70, 0)  # Z, AD and CD

    def test_counts_equal_records_actually_encoded(self):
        wire = encode_dns_response(
            header(),
            question(),
            [rr("example.com.", 1, "192.0.2.1")],
            [rr("example.com.", 2, "ns.example.com.")],
            [rr("ns.example.com.", 1, "192.0.2.53")],
        )
        parsed = parse_dns_message(wire)
        self.assertEqual(
            (
                parsed.header.qdcount,
                parsed.header.ancount,
                parsed.header.nscount,
                parsed.header.arcount,
            ),
            (1, 1, 1, 1),
        )
        self.assertEqual(parsed.questions[0].qname, "www.example.com.")

    def test_response_compresses_names_in_owners_and_supported_rdata(self):
        records = [
            rr("www.example.com.", 1, "192.0.2.1"),
            rr("example.com.", 2, "ns.example.com."),
            rr("alias.example.com.", 5, "www.example.com."),
            rr("1.2.0.192.in-addr.arpa.", 12, "www.example.com."),
            rr(
                "example.com.",
                15,
                {"preference": 10, "exchange": "mail.example.com."},
            ),
        ]

        wire = encode_dns_response(header(), question(), records)
        parsed = parse_dns_message(wire)

        self.assertIn(b"\xc0\x0c", wire)
        self.assertEqual(parsed.header.ancount, len(records))
        self.assertEqual(
            [record.rdata for record in parsed.answers],
            [
                "192.0.2.1",
                "ns.example.com.",
                "www.example.com.",
                "www.example.com.",
                {"preference": 10, "exchange": "mail.example.com."},
            ],
        )

    def test_compression_keeps_repeated_records_within_udp_limit(self):
        original_question = question()
        answers = [
            rr("www.example.com.", 1, f"192.0.2.{index}") for index in range(1, 21)
        ]

        uncompressed_size = (
            12 + len(encode_question(original_question)) + len(encode_records(answers))
        )
        wire = encode_client_response(header(), original_question, answers)
        parsed = parse_dns_message(wire)

        self.assertGreater(uncompressed_size, MAX_CLIENT_DNS_RESPONSE_SIZE)
        self.assertLessEqual(len(wire), MAX_CLIENT_DNS_RESPONSE_SIZE)
        self.assertEqual(parsed.header.rcode, 0)
        self.assertEqual(parsed.header.ancount, len(answers))

    def test_encoding_error_returns_servfail(self):
        wire = encode_client_response(
            header(),
            question(),
            answers=[rr("www.example.com.", 1, "not-an-ip-address")],
            aa=1,
        )
        parsed = parse_dns_message(wire)

        self.assertEqual(parsed.header.rcode, RCODE_SERVFAIL)
        self.assertEqual(parsed.header.aa, 0)
        self.assertEqual(parsed.header.ancount, 0)

    def test_response_too_large_after_compression_returns_servfail(self):
        answers = [
            rr("www.example.com.", 1, f"192.0.2.{(index % 254) + 1}")
            for index in range(40)
        ]

        wire = encode_client_response(
            header(),
            question(),
            answers,
            authorities=[rr("example.com.", 2, "ns.example.com.")],
            additional=[rr("ns.example.com.", 1, "192.0.2.53")],
            aa=1,
        )
        parsed = parse_dns_message(wire)

        self.assertLessEqual(len(wire), MAX_CLIENT_DNS_RESPONSE_SIZE)
        self.assertEqual(parsed.header.rcode, RCODE_SERVFAIL)
        self.assertEqual(parsed.header.aa, 0)
        self.assertEqual(parsed.header.tc, 0)
        self.assertEqual(
            (parsed.header.ancount, parsed.header.nscount, parsed.header.arcount),
            (0, 0, 0),
        )

    def test_compression_rejects_name_longer_than_255_bytes_when_expanded(self):
        maximum_name = ".".join(["a" * 63] * 3 + ["a" * 61]) + "."
        too_long_name = "x." + maximum_name

        with self.assertRaises(ValueError):
            encode_dns_response(
                header(),
                question(maximum_name),
                [rr(too_long_name, 1, "192.0.2.1")],
            )

    def test_unsupported_upstream_records_are_not_copied_to_client(self):
        unsupported = rr("example.", 41, {"status": "unsupported", "raw": b""})
        result = make_resolution_result(
            answers=[rr("example.", 1, "192.0.2.1"), unsupported],
            authorities=[unsupported],
            additional=[unsupported],
            aa=1,
        )
        wire = build_client_response(header(), question("example."), result)
        parsed = parse_dns_message(wire)

        self.assertEqual(parsed.header.ancount, 1)
        self.assertEqual(parsed.answers[0].rtype, 1)
        self.assertEqual((parsed.header.nscount, parsed.header.arcount), (0, 0))


if __name__ == "__main__":
    unittest.main()
