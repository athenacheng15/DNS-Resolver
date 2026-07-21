import unittest
from unittest.mock import patch

from dns.encoder import encode_dns_response
from resolver_core.models import ResolutionBudget
from resolver_core.upstream import query_upstream_candidate, validate_upstream_response
from test.helpers import header, message, question


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

    def test_socket_error_retries_next_candidate(self):
        budget = ResolutionBudget(1)
        usable = {"message": message(flags=0x8400)}

        with patch(
            "resolver_core.upstream.query_upstream_server",
            side_effect=[OSError("network unreachable"), usable],
        ) as query:
            result = query_upstream_candidate(
                ["192.0.2.1", "192.0.2.2"],
                question(),
                1,
                budget,
            )

        self.assertIs(result, usable)
        self.assertEqual(query.call_count, 2)
        self.assertEqual(budget.outbound_attempts, 2)

    def test_all_socket_errors_exhaust_candidates(self):
        budget = ResolutionBudget(1)

        with patch(
            "resolver_core.upstream.query_upstream_server",
            side_effect=OSError("network unreachable"),
        ) as query:
            result = query_upstream_candidate(
                ["192.0.2.1", "192.0.2.2"],
                question(),
                1,
                budget,
            )

        self.assertIsNone(result)
        self.assertEqual(query.call_count, 2)
        self.assertEqual(budget.outbound_attempts, 2)

    def test_non_authoritative_nxdomain_retries_next_candidate(self):
        non_authoritative_nxdomain = {"message": message(flags=0x8003)}
        authoritative_nxdomain = {"message": message(flags=0x8403)}

        with patch(
            "resolver_core.upstream.query_upstream_server",
            side_effect=[non_authoritative_nxdomain, authoritative_nxdomain],
        ) as query:
            result = query_upstream_candidate(
                ["192.0.2.1", "192.0.2.2"],
                question(),
                1,
                ResolutionBudget(1),
            )

        self.assertIs(result, authoritative_nxdomain)
        self.assertEqual(query.call_count, 2)

    def test_semantically_unusable_response_retries_next_candidate(self):
        responses = [
            {"message": message()},
            {"message": message()},
            {"message": message()},
        ]
        decisions = iter([False, ValueError("malformed response"), True])

        def accept_response(_message):
            decision = next(decisions)
            if isinstance(decision, Exception):
                raise decision
            return decision

        with patch(
            "resolver_core.upstream.query_upstream_server",
            side_effect=responses,
        ) as query:
            result = query_upstream_candidate(
                ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
                question(),
                1,
                ResolutionBudget(1),
                accept_response=accept_response,
            )

        self.assertIs(result, responses[2])
        self.assertEqual(query.call_count, 3)

    def test_all_semantically_unusable_candidates_return_none(self):
        responses = [{"message": message()}, {"message": message()}]

        with patch(
            "resolver_core.upstream.query_upstream_server",
            side_effect=responses,
        ):
            result = query_upstream_candidate(
                ["192.0.2.1", "192.0.2.2"],
                question(),
                1,
                ResolutionBudget(1),
                accept_response=lambda _message: False,
            )

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
