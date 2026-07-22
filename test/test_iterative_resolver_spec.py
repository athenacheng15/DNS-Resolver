import unittest
from unittest.mock import patch

from resolver_core.iterative import (
    is_usable_upstream_response,
    iterative_resolve,
    resolve_client_question,
)
from resolver_core.models import ResolutionBudget, ResolutionLimitError
from test.helpers import message, question, rr


def upstream(msg):
    return {"message": msg}


class IterativeResolverSpecificationTests(unittest.TestCase):
    def test_only_terminal_or_referral_responses_are_usable(self):
        q = question()
        cases = [
            (message(flags=0x8403), True),
            (message(flags=0x8003), False),
            (message(flags=0x8400), True),
            (
                message(
                    flags=0x8400,
                    answers=[rr("www.example.com.", 1, "192.0.2.80")],
                ),
                True,
            ),
            (
                message(
                    answers=[rr("www.example.com.", 1, "192.0.2.80")],
                ),
                False,
            ),
            (
                message(
                    flags=0x8400,
                    answers=[rr("www.example.com.", 5, "target.example.com.")],
                ),
                True,
            ),
            (
                message(
                    answers=[rr("www.example.com.", 5, "target.example.com.")],
                ),
                False,
            ),
            (
                message(
                    authority=[rr("example.com.", 2, "ns.example.com.")],
                ),
                True,
            ),
            (message(), False),
        ]

        for response, expected in cases:
            with self.subTest(flags=response.header.flags):
                self.assertEqual(
                    is_usable_upstream_response(response, q),
                    expected,
                )

    def test_referral_with_glue_then_authoritative_answer(self):
        referral = message(
            authority=[rr("example.com.", 2, "ns.example.com.")],
            additional=[rr("ns.example.com.", 1, "192.0.2.53")],
        )
        answer = message(flags=0x8400, answers=[rr("www.example.com.", 1, "192.0.2.80")])
        budget = ResolutionBudget(1)
        with patch("resolver_core.iterative.query_upstream_candidate", side_effect=[upstream(referral), upstream(answer)]) as query:
            result = iterative_resolve(question(), ["198.41.0.4"], 1, budget)
        self.assertEqual(result["answers"][0].rdata, "192.0.2.80")
        self.assertEqual(result["aa"], 1)
        self.assertEqual(query.call_args_list[1].args[0], ["192.0.2.53"])

    def test_no_glue_referral_resolves_ns_address_from_root(self):
        referral = message(authority=[rr("example.com.", 2, "ns.example.net.")])
        answer = message(flags=0x8400, answers=[rr("www.example.com.", 1, "192.0.2.80")])
        budget = ResolutionBudget(1)
        with patch("resolver_core.iterative.query_upstream_candidate", side_effect=[upstream(referral), upstream(answer)]), patch(
            "resolver_core.iterative.resolve_next_name_server_addresses",
            return_value=(["192.0.2.53"], 1),
        ) as nested:
            result = iterative_resolve(question(), ["198.41.0.4"], 1, budget)
        self.assertEqual(result["answers"][0].rdata, "192.0.2.80")
        self.assertEqual(result["aa"], 1)
        nested.assert_called_once()

    def test_no_glue_referral_falls_back_to_next_ns_name(self):
        referral = message(
            authority=[
                rr("example.com.", 2, "ns1.example.net."),
                rr("example.com.", 2, "ns2.example.net."),
            ]
        )
        answer = message(
            flags=0x8400,
            answers=[rr("www.example.com.", 1, "192.0.2.80")],
        )
        budget = ResolutionBudget(1)

        with patch(
            "resolver_core.iterative.query_upstream_candidate",
            side_effect=[upstream(referral), None, upstream(answer)],
        ) as query, patch(
            "resolver_core.iterative.resolve_next_name_server_addresses",
            side_effect=[(["192.0.2.1"], 1), (["192.0.2.2"], 2)],
        ) as nested:
            result = iterative_resolve(
                question(),
                ["198.41.0.4"],
                1,
                budget,
            )

        self.assertEqual(result["answers"][0].rdata, "192.0.2.80")
        self.assertEqual(query.call_args_list[1].args[0], ["192.0.2.1"])
        self.assertEqual(query.call_args_list[2].args[0], ["192.0.2.2"])
        self.assertEqual(nested.call_args_list[0].args[1], 0)
        self.assertEqual(nested.call_args_list[1].args[1], 1)

    def test_ptr_resolution_with_two_no_glue_nested_lookups(self):
        root_ip = "198.41.0.4"
        in_addr_ip = "192.0.2.10"
        apnic_ip = "192.0.2.20"
        net_ip = "192.0.2.30"
        cloudflare_ip = "192.0.2.40"
        com_ip = "192.0.2.50"
        ptr_name = "1.1.1.1.in-addr.arpa."

        def resolve(candidate_ips, current_question, *_args, **_kwargs):
            key = (tuple(candidate_ips), current_question.qname, current_question.qtype)
            responses = {
                ((root_ip,), ptr_name, 12): message(
                    questions=[current_question],
                    authority=[rr("in-addr.arpa.", 2, "a.in-addr.example.")],
                    additional=[rr("a.in-addr.example.", 1, in_addr_ip)],
                ),
                ((in_addr_ip,), ptr_name, 12): message(
                    questions=[current_question],
                    authority=[rr("1.in-addr.arpa.", 2, "ns1.apnic.net.")],
                ),
                ((root_ip,), "ns1.apnic.net.", 1): message(
                    questions=[current_question],
                    authority=[rr("net.", 2, "a.gtld.example.")],
                    additional=[rr("a.gtld.example.", 1, net_ip)],
                ),
                ((net_ip,), "ns1.apnic.net.", 1): message(
                    flags=0x8400,
                    questions=[current_question],
                    answers=[rr("ns1.apnic.net.", 1, apnic_ip)],
                ),
                ((apnic_ip,), ptr_name, 12): message(
                    questions=[current_question],
                    authority=[
                        rr("1.1.1.in-addr.arpa.", 2, "mira.ns.cloudflare.com.")
                    ],
                ),
                ((root_ip,), "mira.ns.cloudflare.com.", 1): message(
                    questions=[current_question],
                    authority=[rr("com.", 2, "a.gtld.example.")],
                    additional=[rr("a.gtld.example.", 1, com_ip)],
                ),
                ((com_ip,), "mira.ns.cloudflare.com.", 1): message(
                    flags=0x8400,
                    questions=[current_question],
                    answers=[rr("mira.ns.cloudflare.com.", 1, cloudflare_ip)],
                ),
                ((cloudflare_ip,), ptr_name, 12): message(
                    flags=0x8400,
                    questions=[current_question],
                    answers=[rr(ptr_name, 12, "one.one.one.one.")],
                ),
            }
            return upstream(responses[key])

        with patch(
            "resolver_core.iterative.query_upstream_candidate",
            side_effect=resolve,
        ) as query:
            result = iterative_resolve(
                question(ptr_name, 12),
                [root_ip],
                1,
                ResolutionBudget(1),
            )

        self.assertEqual(result["rcode"], 0)
        self.assertEqual(result["answers"][0].rdata, "one.one.one.one.")
        self.assertEqual(query.call_count, 8)

    def test_all_supported_types_return_authoritative_answers(self):
        cases = [
            (question("host.example.", 1), rr("host.example.", 1, "192.0.2.1")),
            (question("example.", 2), rr("example.", 2, "ns.example.")),
            (
                question("example.", 15),
                rr(
                    "example.",
                    15,
                    {"preference": 10, "exchange": "mail.example."},
                ),
            ),
            (
                question("1.2.0.192.in-addr.arpa.", 12),
                rr("1.2.0.192.in-addr.arpa.", 12, "host.example."),
            ),
            (
                question("alias.example.", 5),
                rr("alias.example.", 5, "target.example."),
            ),
        ]

        for q, answer_record in cases:
            with self.subTest(qtype=q.qtype), patch(
                "resolver_core.iterative.query_upstream_candidate",
                return_value=upstream(
                    message(
                        flags=0x8400,
                        questions=[q],
                        answers=[answer_record],
                    )
                ),
            ):
                result = iterative_resolve(
                    q,
                    ["198.41.0.4"],
                    1,
                    ResolutionBudget(1),
                )

            self.assertEqual(result["answers"], [answer_record])
            self.assertEqual(result["rcode"], 0)
            self.assertEqual(result["aa"], 1)

    def test_cname_is_chased_from_root_and_included_before_final_answer(self):
        cname = message(flags=0x8400, answers=[rr("alias.example.", 5, "target.example.")])
        final = message(flags=0x8400, answers=[rr("target.example.", 1, "192.0.2.9")])
        budget = ResolutionBudget(1)
        with patch("resolver_core.iterative.query_upstream_candidate", side_effect=[upstream(cname), upstream(final)]) as query:
            result = iterative_resolve(question("alias.example."), ["198.41.0.4"], 1, budget)
        self.assertEqual([r.rtype for r in result["answers"]], [5, 1])
        self.assertEqual(result["aa"], 0)
        self.assertEqual(query.call_args_list[1].args[0], ["198.41.0.4"])
        self.assertEqual(query.call_args_list[1].args[1].qname, "target.example.")

    def test_same_authoritative_response_cname_chain_preserves_aa(self):
        answer = message(
            flags=0x8400,
            answers=[
                rr("alias.example.", 5, "target.example."),
                rr("target.example.", 1, "192.0.2.9"),
            ],
        )

        with patch(
            "resolver_core.iterative.query_upstream_candidate",
            return_value=upstream(answer),
        ):
            result = iterative_resolve(
                question("alias.example."),
                ["198.41.0.4"],
                1,
                ResolutionBudget(1),
            )

        self.assertEqual([record.rtype for record in result["answers"]], [5, 1])
        self.assertEqual(result["aa"], 1)

    def test_cname_limit_and_cross_response_loop_fail(self):
        records = []
        for index in range(11):
            records.append(
                rr(f"n{index}.example.", 5, f"n{index + 1}.example.")
            )
        records.append(rr("n11.example.", 1, "192.0.2.11"))

        with patch(
            "resolver_core.iterative.query_upstream_candidate",
            return_value=upstream(message(flags=0x8400, answers=records)),
        ), self.assertRaises(ResolutionLimitError):
            iterative_resolve(
                question("n0.example."),
                ["198.41.0.4"],
                1,
                ResolutionBudget(1),
            )

        first = message(
            flags=0x8400,
            answers=[rr("a.example.", 5, "b.example.")],
        )
        second = message(
            flags=0x8400,
            answers=[rr("b.example.", 5, "a.example.")],
        )

        with patch(
            "resolver_core.iterative.query_upstream_candidate",
            side_effect=[upstream(first), upstream(second)],
        ), self.assertRaises(ResolutionLimitError):
            iterative_resolve(
                question("a.example."),
                ["198.41.0.4"],
                1,
                ResolutionBudget(1),
            )

    def test_negative_and_incomplete_answers_are_not_cached(self):
        class Cache:
            def __init__(self):
                self.puts = []

            def get(self, _question):
                return None

            def put(self, q, records):
                self.puts.append((q, records))

        results = [
            {
                "answers": [],
                "authorities": [],
                "additional": [],
                "rcode": 3,
                "aa": 1,
            },
            {
                "answers": [],
                "authorities": [],
                "additional": [],
                "rcode": 0,
                "aa": 1,
            },
            {
                "answers": [rr("alias.example.", 5, "target.example.")],
                "authorities": [],
                "additional": [],
                "rcode": 0,
                "aa": 0,
            },
        ]

        for resolution_result in results:
            cache = Cache()
            with self.subTest(result=resolution_result), patch(
                "resolver_core.iterative.iterative_resolve",
                return_value=resolution_result,
            ):
                resolve_client_question(
                    question("alias.example."),
                    ["198.41.0.4"],
                    1,
                    cache,
                )

            self.assertEqual(cache.puts, [])

    def test_authoritative_nxdomain_and_nodata_are_terminal(self):
        nxdomain = message(flags=0x8403)
        nodata = message(flags=0x8400)
        for msg, rcode in ((nxdomain, 3), (nodata, 0)):
            with self.subTest(rcode=rcode), patch("resolver_core.iterative.query_upstream_candidate", return_value=upstream(msg)):
                result = iterative_resolve(question(), ["198.41.0.4"], 1, ResolutionBudget(1))
                self.assertEqual(result["rcode"], rcode)
                self.assertEqual(result["answers"], [])
                self.assertEqual(result["aa"], 1)

    def test_referral_then_authoritative_negative_response_preserves_aa(self):
        referral = message(
            authority=[rr("example.com.", 2, "ns.example.com.")],
            additional=[rr("ns.example.com.", 1, "192.0.2.53")],
        )

        for terminal, rcode in (
            (message(flags=0x8403), 3),
            (message(flags=0x8400), 0),
        ):
            with self.subTest(rcode=rcode), patch(
                "resolver_core.iterative.query_upstream_candidate",
                side_effect=[upstream(referral), upstream(terminal)],
            ):
                result = iterative_resolve(
                    question(),
                    ["198.41.0.4"],
                    1,
                    ResolutionBudget(1),
                )

            self.assertEqual(result["rcode"], rcode)
            self.assertEqual(result["aa"], 1)

    def test_cache_hit_avoids_upstream_and_cache_miss_populates(self):
        class Cache:
            def __init__(self, hit=None): self.hit, self.puts = hit, []
            def get(self, unused): return self.hit
            def put(self, q, records): self.puts.append((q, records))
        hit_cache = Cache([rr("www.example.com.", 1, "192.0.2.1")])
        with patch("resolver_core.iterative.iterative_resolve") as resolve:
            result = resolve_client_question(question(), ["198.41.0.4"], 1, hit_cache)
        resolve.assert_not_called()
        self.assertEqual(result["answers"][0].rdata, "192.0.2.1")
        self.assertEqual(result["aa"], 0)

        miss_cache = Cache()
        positive = {"answers": [rr("www.example.com.", 1, "192.0.2.2")], "authorities": [], "additional": [], "rcode": 0, "aa": 1}
        with patch("resolver_core.iterative.iterative_resolve", return_value=positive):
            resolve_client_question(question(), ["198.41.0.4"], 1, miss_cache)
        self.assertEqual(len(miss_cache.puts), 1)

    def test_budget_enforces_attempt_referral_and_wall_clock_limits(self):
        budget = ResolutionBudget(1)
        budget.outbound_attempts = 50
        with self.assertRaises(ResolutionLimitError):
            budget.use_outbound_attempt()
        budget = ResolutionBudget(1)
        budget.referral_levels = 10
        with self.assertRaises(ResolutionLimitError):
            budget.use_referral_level()
        with patch("resolver_core.models.time.monotonic", side_effect=[100.0, 150.0]):
            expired = ResolutionBudget(1)
            with self.assertRaises(ResolutionLimitError):
                expired.ensure_time_remaining()


if __name__ == "__main__":
    unittest.main()
