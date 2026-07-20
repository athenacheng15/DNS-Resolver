import unittest

from resolver_core.helpers import (
    extract_cname_chain_and_final_answers,
    get_matching_glue_ips,
    get_referral_records,
    has_complete_positive_answer,
    is_authoritative_nodata_response,
    is_referral_response,
    is_supported_client_question,
)
from resolver_core.models import ResolutionLimitError
from test.helpers import message, question, rr


class ResolutionHelperSpecificationTests(unittest.TestCase):
    def test_all_five_client_query_types_are_supported(self):
        supported = [
            is_supported_client_question(question(qtype=qtype))
            for qtype in (1, 2, 5, 12, 15)
        ]
        self.assertEqual(supported, [True] * 5)

    def test_referral_uses_most_specific_zone_and_wire_order(self):
        q = question("www.sub.example.com.")
        msg = message(authority=[
            rr("com.", 2, "ns.com."),
            rr("example.com.", 2, "ns1.example.com."),
            rr("example.com.", 2, "ns2.example.com."),
            rr("unrelated.net.", 2, "ns.unrelated.net."),
        ])
        selected = get_referral_records(msg, q)
        self.assertEqual([r.rdata for r in selected], ["ns1.example.com.", "ns2.example.com."])
        self.assertTrue(is_referral_response(msg, q))

    def test_only_matching_in_class_a_glue_is_used_in_ns_order(self):
        ns = [rr("example.", 2, "ns2.example."), rr("example.", 2, "ns1.example.")]
        msg = message(additional=[
            rr("ns1.example.", 1, "192.0.2.1"),
            rr("evil.example.", 1, "192.0.2.66"),
            rr("ns2.example.", 28, b"ignored"),
            rr("NS2.EXAMPLE.", 1, "192.0.2.2"),
        ])
        self.assertEqual(get_matching_glue_ips(msg, ns), ["192.0.2.2", "192.0.2.1"])

    def test_authoritative_empty_answer_is_nodata_not_referral(self):
        q = question()
        msg = message(flags=0x8400, authority=[rr("example.com.", 2, "ns.example.com.")])
        self.assertTrue(is_authoritative_nodata_response(msg, q))
        self.assertFalse(is_referral_response(msg, q))

    def test_cname_chain_and_final_rrset_are_returned_in_order(self):
        q = question("a.example.")
        records = [
            rr("a.example.", 5, "b.example."),
            rr("b.example.", 5, "c.example."),
            rr("c.example.", 1, "192.0.2.3"),
        ]
        chain, final, terminal = extract_cname_chain_and_final_answers(message(answers=records), q)
        self.assertEqual([r.rdata for r in chain], ["b.example.", "c.example."])
        self.assertEqual(final[0].rdata, "192.0.2.3")
        self.assertEqual(terminal, "c.example.")
        self.assertTrue(has_complete_positive_answer(q, records))

    def test_direct_cname_query_does_not_chase(self):
        q = question("a.example.", 5)
        records = [rr("a.example.", 5, "b.example."), rr("b.example.", 5, "c.example.")]
        chain, final, terminal = extract_cname_chain_and_final_answers(message(answers=records), q)
        self.assertEqual(chain, [])
        self.assertEqual([r.name for r in final], ["a.example."])
        self.assertEqual(terminal, "a.example.")

    def test_cname_loop_is_rejected(self):
        q = question("a.example.")
        records = [rr("a.example.", 5, "b.example."), rr("b.example.", 5, "a.example.")]
        with self.assertRaises(ResolutionLimitError):
            extract_cname_chain_and_final_answers(message(answers=records), q)


if __name__ == "__main__":
    unittest.main()
