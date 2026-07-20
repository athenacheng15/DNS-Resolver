import unittest
from unittest.mock import patch

from dns.encoder import encode_dns_response
from resolver_core.models import ResolutionBudget
from resolver_core.upstream import query_upstream_candidate, validate_upstream_response
from test.helpers import header, question


class UpstreamSpecificationTests(unittest.TestCase):
    def response(self, expected_question=None, transaction_id=0x1111, flags=0x8000):
        expected_question = expected_question or question()
        query_header = header(transaction_id, flags & 0x7FFF)
        wire = encode_dns_response(query_header, expected_question)
        # Override flags when testing TC/opcode/QR validation.
        return wire[:2] + flags.to_bytes(2, "big") + wire[4:]

    def test_valid_response_matches_source_id_and_question_case_insensitively(self):
        expected = question("Example.COM.")
        wire = self.response(question("example.com."))
        parsed = validate_upstream_response(wire, ("192.0.2.53", 53), "192.0.2.53", 0x1111, expected)
        self.assertEqual(parsed.header.qr, 1)

    def test_mismatched_response_dimensions_are_rejected(self):
        expected = question()
        cases = [
            (self.response(), ("192.0.2.54", 53), "192.0.2.53", 0x1111, expected),
            (self.response(), ("192.0.2.53", 5353), "192.0.2.53", 0x1111, expected),
            (self.response(), ("192.0.2.53", 53), "192.0.2.53", 0x2222, expected),
            (self.response(question("other.example.")), ("192.0.2.53", 53), "192.0.2.53", 0x1111, expected),
            (self.response(flags=0x8200), ("192.0.2.53", 53), "192.0.2.53", 0x1111, expected),
        ]
        for args in cases:
            with self.subTest(args=args[1:]), self.assertRaises(ValueError):
                validate_upstream_response(*args)

    def test_candidates_are_tried_in_order_after_failure(self):
        budget = ResolutionBudget(1)
        usable = {"message": type("M", (), {"header": type("H", (), {"rcode": 0})()})()}
        with patch("resolver_core.upstream.query_upstream_server", side_effect=[None, usable]) as query:
            result = query_upstream_candidate(["192.0.2.1", "192.0.2.2"], question(), 1, budget)
        self.assertIs(result, usable)
        self.assertEqual([call.args[0] for call in query.call_args_list], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(budget.outbound_attempts, 2)


if __name__ == "__main__":
    unittest.main()
