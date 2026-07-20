import threading
import time

from dns_records import ResourceRecord
from utils import normalize_name


def make_cache_key(question):
    return (normalize_name(question.qname), question.qtype, question.qclass)


def clone_record_with_ttl(record, ttl):
    return ResourceRecord(
        name=record.name,
        rtype=record.rtype,
        rclass=record.rclass,
        ttl=ttl,
        rdlength=record.rdlength,
        rdata=record.rdata,
    )


class DNSCache:
    """
    Thread-safe positive DNS cache.

    Each question key maps to an ordered list of cached records. Every record
    has its own expiry time because records in the same answer, including a
    CNAME chain, may have different TTL values.
    """

    def __init__(self):
        self._entries = {}
        self._lock = threading.Lock()

    def put(self, question, records):
        """
        Cache positive answer records for a DNS question.

        Records with TTL <= 0 are ignored. If no usable records remain, any
        existing entry for the key is removed.
        """
        key = make_cache_key(question)
        now = time.monotonic()
        cached_records = []

        for record in records:
            if record.ttl <= 0:
                continue

            expiry_time = now + record.ttl
            cached_records.append((record, expiry_time))

        with self._lock:
            if cached_records:
                self._entries[key] = cached_records
            else:
                self._entries.pop(key, None)

    def get(self, question):
        """
        Return a complete unexpired cached answer with decreasing TTL values.

        The cache entry is treated as one logical answer. If any record has
        expired, the whole entry is removed and this method returns None.

        This is important for CNAME chains because returning only the final
        target record without every preceding CNAME link would produce an
        incomplete answer for the original query.

        Returns:
            A new list of ResourceRecord objects, or None when the entry is
            missing or no longer complete.
        """
        key = make_cache_key(question)
        now = time.monotonic()

        with self._lock:
            cached_records = self._entries.get(key)

            if cached_records is None:
                return None

            result_records = []

            for record, expiry_time in cached_records:
                remaining_ttl = int(expiry_time - now)

                if remaining_ttl <= 0:
                    del self._entries[key]
                    return None

                result_records.append(clone_record_with_ttl(record, remaining_ttl))

            return result_records

    def clear(self):
        """
        Remove all cache entries.
        """
        with self._lock:
            self._entries.clear()
