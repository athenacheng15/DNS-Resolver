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
        Return unexpired cached records with decreasing TTL values.

        Returns:
            A new list of ResourceRecord objects, or None when the key is not
            cached or every record in the entry has expired.
        """
        key = make_cache_key(question)
        now = time.monotonic()
        with self._lock:
            cached_records = self._entries.get(key)

            if cached_records is None:
                return None

            live_cached_records = []
            result_records = []

            for record, expiry_time in cached_records:
                remaining_ttl = int(expiry_time - now)

                if remaining_ttl <= 0:
                    continue

                live_cached_records.append((record, expiry_time))
                result_records.append(clone_record_with_ttl(record, remaining_ttl))

            if not live_cached_records:
                del self._entries[key]
                return None

            # Remove individually expired records while preserving the order
            # of the remaining CNAME chain and final answers.
            self._entries[key] = live_cached_records
            return result_records

    def clear(self):
        """
        Remove all cache entries.
        """
        with self._lock:
            self._entries.clear()
