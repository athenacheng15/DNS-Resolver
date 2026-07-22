import threading
import unittest
from unittest.mock import patch

from cache import DNSCache
from test.helpers import question, rr


class CacheSpecificationTests(unittest.TestCase):
    def test_key_is_case_insensitive_and_fully_qualified(self):
        cache = DNSCache()
        with patch("cache.time.monotonic", return_value=100.0):
            cache.put(question("Example.COM", 1), [rr("Example.COM.", 1, "192.0.2.1", ttl=10)])
        with patch("cache.time.monotonic", return_value=101.0):
            hit = cache.get(question("example.com.", 1))
        self.assertEqual(hit[0].rdata, "192.0.2.1")
        self.assertEqual(hit[0].ttl, 9)

    def test_ttl_is_floored(self):
        cache = DNSCache()
        with patch("cache.time.monotonic", return_value=20.0):
            cache.put(question(), [rr("www.example.com.", 1, "192.0.2.1", ttl=2)])
        with patch("cache.time.monotonic", return_value=20.2):
            self.assertEqual(cache.get(question())[0].ttl, 1)

    def test_expired_or_zero_ttl_entries_miss(self):
        cache = DNSCache()
        with patch("cache.time.monotonic", return_value=20.0):
            cache.put(question(), [rr("www.example.com.", 1, "192.0.2.1", ttl=1)])
        with patch("cache.time.monotonic", return_value=21.0):
            self.assertIsNone(cache.get(question()))
        cache.put(question(), [rr("www.example.com.", 1, "192.0.2.1", ttl=0)])
        self.assertIsNone(cache.get(question()))

    def test_cname_chain_is_atomic_when_one_link_expires(self):
        cache = DNSCache()
        chain = [
            rr("alias.example.", 5, "target.example.", ttl=1),
            rr("target.example.", 1, "192.0.2.8", ttl=10),
        ]
        with patch("cache.time.monotonic", return_value=5.0):
            cache.put(question("alias.example."), chain)
        with patch("cache.time.monotonic", return_value=6.0):
            self.assertIsNone(cache.get(question("alias.example.")))

    def test_concurrent_access_does_not_corrupt_entries(self):
        cache = DNSCache()
        errors = []
        def worker(index):
            try:
                q = question(f"n{index}.example.")
                cache.put(q, [rr(q.qname, 1, f"192.0.2.{index + 1}", ttl=30)])
                self.assertIsNotNone(cache.get(q))
            except BaseException as error:
                errors.append(error)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])

    def test_type_and_class_are_distinct_cache_keys(self):
        cache = DNSCache()
        with patch("cache.time.monotonic", return_value=10.0):
            cache.put(
                question("example.", 1, 1),
                [rr("example.", 1, "192.0.2.1", ttl=30)],
            )

        with patch("cache.time.monotonic", return_value=11.0):
            self.assertIsNone(cache.get(question("example.", 15, 1)))
            self.assertIsNone(cache.get(question("example.", 1, 3)))

    def test_zero_ttl_record_prevents_partial_cache_entry(self):
        cache = DNSCache()
        cache.put(
            question("alias.example."),
            [
                rr("alias.example.", 5, "target.example.", ttl=30),
                rr("target.example.", 1, "192.0.2.1", ttl=0),
            ],
        )
        self.assertIsNone(cache.get(question("alias.example.")))


if __name__ == "__main__":
    unittest.main()
