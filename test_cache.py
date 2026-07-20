import time
import unittest

from cache import DNSCache, make_cache_key
from dns.records import DNSQuestion, ResourceRecord


class DNSCacheTests(unittest.TestCase):
    def setUp(self):
        self.cache = DNSCache()

    def test_cache_key_normalises_dns_name(self):
        question_one = DNSQuestion(
            qname="Example.COM",
            qtype=1,
            qclass=1,
        )

        question_two = DNSQuestion(
            qname="example.com.",
            qtype=1,
            qclass=1,
        )

        self.assertEqual(
            make_cache_key(question_one),
            make_cache_key(question_two),
        )

    def test_cache_returns_decreasing_ttl(self):
        question = DNSQuestion(
            qname="example.com.",
            qtype=1,
            qclass=1,
        )

        original_record = ResourceRecord(
            name="example.com.",
            rtype=1,
            rclass=1,
            ttl=3,
            rdlength=4,
            rdata="192.0.2.1",
        )

        self.cache.put(
            question,
            [original_record],
        )

        first_result = self.cache.get(question)

        self.assertIsNotNone(first_result)
        self.assertEqual(len(first_result), 1)

        first_ttl = first_result[0].ttl

        time.sleep(1.1)

        second_result = self.cache.get(question)

        self.assertIsNotNone(second_result)
        self.assertEqual(len(second_result), 1)

        second_ttl = second_result[0].ttl

        self.assertLess(second_ttl, first_ttl)
        self.assertEqual(original_record.ttl, 3)

    def test_expired_entry_is_not_returned(self):
        question = DNSQuestion(
            qname="short.example.",
            qtype=1,
            qclass=1,
        )

        record = ResourceRecord(
            name="short.example.",
            rtype=1,
            rclass=1,
            ttl=1,
            rdlength=4,
            rdata="192.0.2.2",
        )

        self.cache.put(
            question,
            [record],
        )

        time.sleep(1.1)

        result = self.cache.get(question)

        self.assertIsNone(result)

    def test_zero_ttl_record_is_not_cached(self):
        question = DNSQuestion(
            qname="zero.example.",
            qtype=1,
            qclass=1,
        )

        record = ResourceRecord(
            name="zero.example.",
            rtype=1,
            rclass=1,
            ttl=0,
            rdlength=4,
            rdata="192.0.2.3",
        )

        self.cache.put(
            question,
            [record],
        )

        result = self.cache.get(question)

        self.assertIsNone(result)

    def test_expired_cname_link_invalidates_whole_entry(self):
        question = DNSQuestion(
            qname="alias.example.",
            qtype=1,
            qclass=1,
        )

        cname_record = ResourceRecord(
            name="alias.example.",
            rtype=5,
            rclass=1,
            ttl=2,
            rdlength=0,
            rdata="target.example.",
        )

        address_record = ResourceRecord(
            name="target.example.",
            rtype=1,
            rclass=1,
            ttl=10,
            rdlength=4,
            rdata="192.0.2.4",
        )

        self.cache.put(
            question,
            [
                cname_record,
                address_record,
            ],
        )

        initial_result = self.cache.get(question)

        self.assertIsNotNone(initial_result)
        self.assertEqual(len(initial_result), 2)

        time.sleep(2.1)

        expired_result = self.cache.get(question)

        self.assertIsNone(expired_result)


if __name__ == "__main__":
    unittest.main()
