import threading
import time

from dns.records import ResourceRecord
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

    def __init__(self):
        self._entries = {}
        self._lock = threading.Lock()

    def put(self, question, records):

        key = make_cache_key(question)

        if not records:
            with self._lock:
                self._entries.pop(key, None)
            return

        for record in records:
            if record.ttl <= 0:
                with self._lock:
                    self._entries.pop(key, None)
                return

        now = time.monotonic()
        cached_records = []

        for record in records:
            expiry_time = now + record.ttl
            cached_records.append((record, expiry_time))

        with self._lock:
            self._entries[key] = cached_records

    def get(self, question):

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

        with self._lock:
            self._entries.clear()
