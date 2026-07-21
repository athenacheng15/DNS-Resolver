import os
import tempfile
import unittest

from dns.records import DNSQuestion
from resolver_core.helpers import build_root_hints_response, get_root_server_ips
from root_hints import parse_root_hints


class RootHintsSpecificationTests(unittest.TestCase):
    def parse(self, contents):
        handle, path = tempfile.mkstemp(text=True)
        try:
            with os.fdopen(handle, "w") as stream:
                stream.write(contents)
            return parse_root_hints(path)
        finally:
            os.unlink(path)

    def test_subset_comments_ttl_field_order_and_unsupported_records(self):
        ns, addresses, mapping = self.parse(
            "; comment\n$TTL 60\n. 518400 IN NS A.ROOT.\n"
            ". IN 42 NS b.root. ; trailing\n"
            "A.ROOT. IN A 192.0.2.1\nb.root. A 192.0.2.2\n"
            "a.root. IN AAAA 2001:db8::1\n"
        )
        self.assertEqual([r.ttl for r in ns], [518400, 42])
        self.assertEqual([r.ttl for r in addresses], [60, 60])
        self.assertEqual(list(mapping), ["a.root.", "b.root."])

    def test_root_ns_local_response_preserves_order_and_matching_glue(self):
        ns, addresses, mapping = self.parse(
            ". 10 IN NS b.root.\n. 20 IN NS a.root.\n"
            "a.root. 30 IN A 192.0.2.1\nb.root. 40 IN A 192.0.2.2\n"
        )
        result = build_root_hints_response(DNSQuestion(".", 2, 1), ns, addresses, mapping)
        self.assertEqual([r.rdata for r in result["answers"]], ["b.root.", "a.root."])
        self.assertEqual([r.rdata for r in result["additional"]], ["192.0.2.2", "192.0.2.1"])
        self.assertEqual(result["authorities"], [])
        self.assertEqual(result["aa"], 0)

    def test_root_server_a_lookup_is_case_insensitive_and_returns_all(self):
        ns, addresses, mapping = self.parse(
            ". IN NS A.Root.\nA.Root. 5 IN A 192.0.2.1\na.root. 6 IN A 192.0.2.2\n"
        )
        result = build_root_hints_response(DNSQuestion("a.ROOT.", 1, 1), ns, addresses, mapping)
        self.assertEqual([r.rdata for r in result["answers"]], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(get_root_server_ips(ns, addresses), ["192.0.2.1", "192.0.2.2"])

    def test_non_local_question_returns_none(self):
        ns, addresses, mapping = self.parse(". IN NS a.root.\na.root. IN A 192.0.2.1\n")
        self.assertIsNone(build_root_hints_response(DNSQuestion("example.com.", 1, 1), ns, addresses, mapping))

    def test_omitted_ttl_defaults_to_zero_then_tracks_latest_directive(self):
        ns, addresses, _mapping = self.parse(
            ". IN NS a.root.\n"
            "$TTL 60\n"
            "a.root. IN A 192.0.2.1\n"
            "$TTL 120\n"
            "a.root. IN A 192.0.2.2\n"
        )
        self.assertEqual(ns[0].ttl, 0)
        self.assertEqual([record.ttl for record in addresses], [60, 120])

    def test_local_records_preserve_owner_ttl_and_class(self):
        ns, addresses, mapping = self.parse(
            ". 111 IN NS A.Root.\nA.Root. 222 IN A 192.0.2.1\n"
        )
        result = build_root_hints_response(
            DNSQuestion(".", 2, 1),
            ns,
            addresses,
            mapping,
        )

        self.assertEqual(
            (result["answers"][0].name, result["answers"][0].ttl, result["answers"][0].rclass),
            (".", 111, 1),
        )
        self.assertEqual(
            (
                result["additional"][0].name,
                result["additional"][0].ttl,
                result["additional"][0].rclass,
            ),
            ("A.Root.", 222, 1),
        )


if __name__ == "__main__":
    unittest.main()
