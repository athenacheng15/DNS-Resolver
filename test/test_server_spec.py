import threading
import unittest
from unittest.mock import MagicMock, patch

from cache import DNSCache
from dns.encoder import encode_header, encode_question
from dns.message import parse_dns_message
from resolver import create_server_socket, handle_client_query
from resolver_core.helpers import make_resolution_result
from test.helpers import question, rr


class FakeSocket:
    def __init__(self):
        self.sent = []
        self.lock = threading.Lock()
    def sendto(self, data, address):
        with self.lock:
            self.sent.append((data, address))


def query_wire(message_id, q=None):
    q = q or question()
    return encode_header(message_id, 0x0100, 1, 0, 0, 0) + encode_question(q)


class ServerSpecificationTests(unittest.TestCase):
    def test_server_binds_ipv4_loopback(self):
        server = MagicMock()
        with patch("resolver.socket.socket", return_value=server) as constructor:
            result = create_server_socket(53000)
        constructor.assert_called_once_with(2, 2)  # AF_INET, SOCK_DGRAM
        server.bind.assert_called_once_with(("127.0.0.1", 53000))
        self.assertIs(result, server)

    def test_client_response_restores_each_clients_id_and_address(self):
        fake = FakeSocket()
        cache = DNSCache()
        positive = make_resolution_result(answers=[rr("www.example.com.", 1, "192.0.2.9")], aa=1)
        def run(message_id, address):
            handle_client_query(fake, query_wire(message_id), address, [], [], {}, ["198.41.0.4"], 1, cache)
        with patch("resolver.is_supported_client_question", return_value=True), patch("resolver.resolve_client_question", return_value=positive):
            threads = [threading.Thread(target=run, args=(0x1000 + i, ("127.0.0.1", 50000 + i))) for i in range(8)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
        self.assertEqual(len(fake.sent), 8)
        observed = {(parse_dns_message(data).header.message_id, address) for data, address in fake.sent}
        expected = {(0x1000 + i, ("127.0.0.1", 50000 + i)) for i in range(8)}
        self.assertEqual(observed, expected)

    def test_slow_resolution_does_not_force_other_worker_to_wait(self):
        fake = FakeSocket()
        slow_started = threading.Event()
        release_slow = threading.Event()
        def resolve(q, *_args):
            if q.qname == "slow.example.":
                slow_started.set()
                release_slow.wait(1)
            return make_resolution_result(answers=[rr(q.qname, 1, "192.0.2.1")])
        def invoke(name, message_id, port):
            handle_client_query(fake, query_wire(message_id, question(name)), ("127.0.0.1", port), [], [], {}, ["198.41.0.4"], 1, DNSCache())
        with patch("resolver.is_supported_client_question", return_value=True), patch("resolver.resolve_client_question", side_effect=resolve):
            slow = threading.Thread(target=invoke, args=("slow.example.", 1, 50001))
            fast = threading.Thread(target=invoke, args=("fast.example.", 2, 50002))
            slow.start(); self.assertTrue(slow_started.wait(0.5)); fast.start(); fast.join(0.5)
            self.assertFalse(fast.is_alive())
            self.assertEqual(len(fake.sent), 1)
            release_slow.set(); slow.join(0.5)

    def test_upstream_socket_errors_return_servfail_to_client(self):
        fake = FakeSocket()
        client_address = ("127.0.0.1", 50001)

        with patch(
            "resolver_core.upstream.query_upstream_server",
            side_effect=OSError("network unreachable"),
        ):
            handle_client_query(
                fake,
                query_wire(0xCAFE),
                client_address,
                [],
                [],
                {},
                ["192.0.2.1", "192.0.2.2"],
                1,
                DNSCache(),
            )

        self.assertEqual(len(fake.sent), 1)
        response_data, response_address = fake.sent[0]
        parsed = parse_dns_message(response_data)

        self.assertEqual(response_address, client_address)
        self.assertEqual(parsed.header.message_id, 0xCAFE)
        self.assertEqual(parsed.header.rcode, 2)
        self.assertEqual(parsed.header.aa, 0)
        self.assertEqual(parsed.header.tc, 0)
        self.assertEqual(
            (parsed.header.ancount, parsed.header.nscount, parsed.header.arcount),
            (0, 0, 0),
        )
        self.assertEqual(parsed.questions[0].qname, "www.example.com.")


if __name__ == "__main__":
    unittest.main()
