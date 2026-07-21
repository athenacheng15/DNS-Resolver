import socket
import struct
import unittest
from unittest.mock import patch

from dns.encoder import encode_dns_response, encode_header, encode_question
from resolver_core.models import ResolutionBudget
from resolver_core.upstream import (
    query_upstream_candidate,
    query_upstream_server,
    validate_upstream_response,
)
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

    def test_qr_opcode_qdcount_qtype_and_qclass_are_validated(self):
        expected = question("www.example.com.", 1, 1)
        cases = [
            self.response(flags=0x0000),
            self.response(flags=0x8800),
            self.response(question("www.example.com.", 15, 1)),
            self.response(question("www.example.com.", 1, 3)),
        ]

        qdcount_zero = bytearray(self.response())
        qdcount_zero[4:6] = b"\x00\x00"
        cases.append(bytes(qdcount_zero))

        for wire in cases:
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                validate_upstream_response(
                    wire,
                    ("192.0.2.53", 53),
                    "192.0.2.53",
                    0x1111,
                    expected,
                )

    def test_malformed_section_count_and_rdlength_are_rejected(self):
        malformed_count = bytearray(self.response())
        malformed_count[6:8] = b"\x00\x01"

        q = question()
        malformed_rdlength = (
            encode_header(0x1111, 0x8400, 1, 1, 0, 0)
            + encode_question(q)
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + b"\x7f\x00"
        )

        for wire in (bytes(malformed_count), malformed_rdlength):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                validate_upstream_response(
                    wire,
                    ("192.0.2.53", 53),
                    "192.0.2.53",
                    0x1111,
                    q,
                )

    def test_socket_ignores_unmatched_datagram_then_accepts_match(self):
        class FakeSocket:
            def __init__(self, packets):
                self.packets = iter(packets)
                self.sent = []
                self.timeouts = []
                self.closed = False

            def sendto(self, data, address):
                self.sent.append((data, address))

            def settimeout(self, timeout):
                self.timeouts.append(timeout)

            def recvfrom(self, _size):
                return next(self.packets)

            def close(self):
                self.closed = True

        q = question()
        wrong = self.response(transaction_id=0x2222)
        valid = self.response(transaction_id=0x1111, flags=0x8400)
        fake = FakeSocket(
            [
                (wrong, ("192.0.2.53", 53)),
                (valid, ("192.0.2.53", 53)),
            ]
        )

        with patch(
            "resolver_core.upstream.socket.socket",
            return_value=fake,
        ), patch(
            "resolver_core.upstream.encode_upstream_query",
            return_value=(0x1111, b"query"),
        ):
            result = query_upstream_server(
                "192.0.2.53",
                q,
                1,
                ResolutionBudget(1),
            )

        self.assertEqual(fake.sent, [(b"query", ("192.0.2.53", 53))])
        self.assertEqual(result["message"].header.aa, 1)
        self.assertGreaterEqual(len(fake.timeouts), 2)
        self.assertTrue(fake.closed)

    def test_socket_timeout_returns_none_and_closes_socket(self):
        class TimeoutSocket:
            def __init__(self):
                self.closed = False

            def sendto(self, _data, _address):
                pass

            def settimeout(self, _timeout):
                pass

            def recvfrom(self, _size):
                raise socket.timeout

            def close(self):
                self.closed = True

        fake = TimeoutSocket()

        with patch(
            "resolver_core.upstream.socket.socket",
            return_value=fake,
        ), patch(
            "resolver_core.upstream.encode_upstream_query",
            return_value=(0x1111, b"query"),
        ):
            result = query_upstream_server(
                "192.0.2.53",
                question(),
                1,
                ResolutionBudget(1),
            )

        self.assertIsNone(result)
        self.assertTrue(fake.closed)

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

    def test_error_rcodes_retry_next_candidate(self):
        for rcode in (1, 2, 5):
            failed = {"message": message(flags=0x8000 | rcode)}
            usable = {"message": message(flags=0x8400)}

            with self.subTest(rcode=rcode), patch(
                "resolver_core.upstream.query_upstream_server",
                side_effect=[failed, usable],
            ) as query:
                result = query_upstream_candidate(
                    ["192.0.2.1", "192.0.2.2"],
                    question(),
                    1,
                    ResolutionBudget(1),
                )

            self.assertIs(result, usable)
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
