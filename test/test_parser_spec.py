import os
import struct
import subprocess
import sys
import unittest

from dns.encoder import encode_name
from dns.message import parse_dns_message, parse_name
from test.helpers import wire_message, wire_question, wire_rr


ROOT = os.path.dirname(os.path.dirname(__file__))


class ParserSpecificationTests(unittest.TestCase):
    def test_supplied_query_and_response_files_parse(self):
        for filename in os.listdir(os.path.join(ROOT, "src")):
            if filename.endswith(".bin"):
                with self.subTest(filename=filename):
                    with open(os.path.join(ROOT, "src", filename), "rb") as stream:
                        parsed = parse_dns_message(stream.read())
                    self.assertEqual(parsed.header.qdcount, len(parsed.questions))
                    self.assertEqual(parsed.header.ancount, len(parsed.answers))
                    self.assertEqual(parsed.header.nscount, len(parsed.authority))
                    self.assertEqual(parsed.header.arcount, len(parsed.additional))

    def test_multiple_questions_are_traversed_before_answers(self):
        questions = [wire_question("one.example.", 1), wire_question("two.example.", 15)]
        answer = wire_rr(b"\xc0\x0c", 1, bytes([192, 0, 2, 1]))
        parsed = parse_dns_message(wire_message(questions=questions, answers=[answer]))
        self.assertEqual([q.qname for q in parsed.questions], ["one.example.", "two.example."])
        self.assertEqual(parsed.answers[0].rdata, "192.0.2.1")

    def test_supported_rdata_types_decode_in_all_sections(self):
        q = wire_question("example.com.")
        owner = b"\xc0\x0c"
        records = [
            wire_rr(owner, 1, bytes([203, 0, 113, 7])),
            wire_rr(owner, 2, encode_name("ns.example.com.")),
            wire_rr(owner, 5, encode_name("alias.example.com.")),
            wire_rr(owner, 12, encode_name("host.example.com.")),
            wire_rr(owner, 15, struct.pack("!H", 10) + encode_name("mail.example.com.")),
        ]
        parsed = parse_dns_message(wire_message(questions=[q], answers=records[:2], authority=records[2:4], additional=records[4:]))
        all_records = parsed.answers + parsed.authority + parsed.additional
        self.assertEqual([r.rtype for r in all_records], [1, 2, 5, 12, 15])
        self.assertEqual(all_records[0].rdata, "203.0.113.7")
        self.assertEqual(all_records[4].rdata, {"preference": 10, "exchange": "mail.example.com."})

    def test_unknown_type_is_skipped_using_rdlength(self):
        q = wire_question("example.com.")
        unknown = wire_rr(b"\xc0\x0c", 99, b"\xde\xad\xbe\xef")
        following = wire_rr(b"\xc0\x0c", 1, bytes([1, 2, 3, 4]))
        parsed = parse_dns_message(wire_message(questions=[q], answers=[unknown, following]))
        self.assertEqual(parsed.answers[0].rdata["status"], "unsupported")
        self.assertEqual(parsed.answers[1].rdata, "1.2.3.4")

    def test_compressed_name_in_rdata_resumes_at_rdlength_boundary(self):
        q = wire_question("example.com.")
        cname = wire_rr(b"\xc0\x0c", 5, b"\xc0\x0c")
        following = wire_rr(b"\xc0\x0c", 1, bytes([10, 0, 0, 1]))
        parsed = parse_dns_message(wire_message(questions=[q], answers=[cname, following]))
        self.assertEqual(parsed.answers[0].rdata, "example.com.")
        self.assertEqual(parsed.answers[1].rdata, "10.0.0.1")

    def test_malformed_supported_rdata_is_rejected(self):
        q = wire_question("example.com.")
        bad_a = wire_rr(b"\xc0\x0c", 1, b"\x01\x02\x03")
        with self.assertRaises(ValueError):
            parse_dns_message(wire_message(questions=[q], answers=[bad_a]))

    def test_pointer_out_of_bounds_loop_and_reserved_label_fail_safely(self):
        for data in (b"\xc0\xff", b"\xc0\x00", b"\x40"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_name(data, 0)

    def test_name_length_constraints(self):
        with self.assertRaises(ValueError):
            parse_name(bytes([64]) + b"a" * 64 + b"\0", 0)
        too_long = b"".join(bytes([63]) + b"a" * 63 for _ in range(4)) + b"\0"
        with self.assertRaises(ValueError):
            parse_name(too_long, 0)

    def test_parser_cli_prints_required_sections_and_exits(self):
        path = os.path.join(ROOT, "src", "unsw.edu.au-A-44325-query.bin")
        result = subprocess.run([sys.executable, os.path.join(ROOT, "parser.py"), path], capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        for heading in ("--- FLAGS ---", "--- COUNTS ---", "--- QUESTIONS ---", "--- ANSWERS ---", "--- AUTHORITY ---", "--- ADDITIONAL ---"):
            self.assertIn(heading, result.stdout)
        for field in ("QR:", "Opcode:", "AA:", "TC:", "RD:", "RA:", "RCODE:"):
            self.assertIn(field, result.stdout)


if __name__ == "__main__":
    unittest.main()
