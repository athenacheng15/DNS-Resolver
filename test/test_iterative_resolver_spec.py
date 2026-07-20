import unittest
from unittest.mock import patch

from resolver_core.iterative import iterative_resolve, resolve_client_question
from resolver_core.models import ResolutionBudget, ResolutionLimitError
from test.helpers import message, question, rr


def upstream(msg):
    return {"message": msg}


class IterativeResolverSpecificationTests(unittest.TestCase):
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
        self.assertEqual(result["aa"], 0)  # assembled through a referral
        self.assertEqual(query.call_args_list[1].args[0], ["192.0.2.53"])

    def test_no_glue_referral_resolves_ns_address_from_root(self):
        referral = message(authority=[rr("example.com.", 2, "ns.example.net.")])
        answer = message(flags=0x8400, answers=[rr("www.example.com.", 1, "192.0.2.80")])
        budget = ResolutionBudget(1)
        with patch("resolver_core.iterative.query_upstream_candidate", side_effect=[upstream(referral), upstream(answer)]), patch(
            "resolver_core.iterative.resolve_name_server_addresses", return_value=["192.0.2.53"]
        ) as nested:
            result = iterative_resolve(question(), ["198.41.0.4"], 1, budget)
        self.assertEqual(result["answers"][0].rdata, "192.0.2.80")
        nested.assert_called_once()

    def test_cname_is_chased_from_root_and_included_before_final_answer(self):
        cname = message(flags=0x8400, answers=[rr("alias.example.", 5, "target.example.")])
        final = message(flags=0x8400, answers=[rr("target.example.", 1, "192.0.2.9")])
        budget = ResolutionBudget(1)
        with patch("resolver_core.iterative.query_upstream_candidate", side_effect=[upstream(cname), upstream(final)]) as query:
            result = iterative_resolve(question("alias.example."), ["198.41.0.4"], 1, budget)
        self.assertEqual([r.rtype for r in result["answers"]], [5, 1])
        self.assertEqual(query.call_args_list[1].args[0], ["198.41.0.4"])
        self.assertEqual(query.call_args_list[1].args[1].qname, "target.example.")

    def test_authoritative_nxdomain_and_nodata_are_terminal(self):
        nxdomain = message(flags=0x8403)
        nodata = message(flags=0x8400)
        for msg, rcode in ((nxdomain, 3), (nodata, 0)):
            with self.subTest(rcode=rcode), patch("resolver_core.iterative.query_upstream_candidate", return_value=upstream(msg)):
                result = iterative_resolve(question(), ["198.41.0.4"], 1, ResolutionBudget(1))
                self.assertEqual(result["rcode"], rcode)
                self.assertEqual(result["answers"], [])

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
