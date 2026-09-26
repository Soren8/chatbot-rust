"""Unit tests for the UDP/TCP relay in forwarder.py.

Fake upstreams and the forwarder under test all bind loopback ephemeral
ports; the forwarder's upstream port is injectable (production uses 53).
No engine or external network is involved.
"""

import socket
import socketserver
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import forwarder
from forwarder import SharedState, forward_tcp, forward_udp, make_servers

CANNED_SUFFIX = b"\x81\x80\x00\x01canned"


def canned_response(query: bytes) -> bytes:
    return query[:2] + CANNED_SUFFIX


class FakeUdpUpstream(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        self.server.hits.append(data)
        try:
            sock.sendto(canned_response(data), self.client_address)
        except OSError:
            pass


class BadTxidUdpUpstream(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        _, sock = self.request
        try:
            sock.sendto(b"\x00\x00" + CANNED_SUFFIX, self.client_address)
        except OSError:
            pass


class ShortTcpUpstream(socketserver.BaseRequestHandler):
    """Advertises a longer response than it sends, then closes."""

    def handle(self) -> None:
        conn = self.request
        conn.settimeout(2)
        try:
            header = conn.recv(2)
            if len(header) != 2:
                return
            (length,) = struct.unpack("!H", header)
            query = b""
            while len(query) < length:
                chunk = conn.recv(length - len(query))
                if not chunk:
                    return
                query += chunk
            short = canned_response(query)
            conn.sendall(struct.pack("!H", len(short) + 10) + short)
        except OSError:
            pass


class FakeTcpUpstream(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        conn = self.request
        conn.settimeout(2)
        while True:
            header = conn.recv(2)
            if len(header) != 2:
                return
            (length,) = struct.unpack("!H", header)
            query = b""
            while len(query) < length:
                chunk = conn.recv(length - len(query))
                if not chunk:
                    return
                query += chunk
            try:
                conn.sendall(
                    struct.pack("!H", len(canned_response(query)))
                    + canned_response(query)
                )
            except OSError:
                return


class UdpServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class TcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def start(server, **attrs):
    for key, value in attrs.items():
        setattr(server, key, value)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


DEAD = "127.0.0.2"  # loopback with nothing listening: fast refusal


class FailoverTests(unittest.TestCase):
    def setUp(self):
        self.upstream = UdpServer(("127.0.0.1", 0), FakeUdpUpstream)
        start(self.upstream, hits=[])
        self.addCleanup(self.upstream.shutdown)
        self.addCleanup(self.upstream.server_close)
        self.port = self.upstream.server_address[1]

    def test_relay_returns_upstream_bytes(self):
        query = b"\x12\x34\x01\x00question"
        response = forward_udp(query, ["127.0.0.1"], timeout=2, port=self.port)
        self.assertEqual(response, canned_response(query))

    def test_query_sent_to_first_live_upstream_only(self):
        query = b"\x12\x35\x01\x00question"
        response = forward_udp(
            query, ["127.0.0.1", "127.0.0.1"], timeout=2, port=self.port
        )
        self.assertEqual(response, canned_response(query))
        # Ordered failover sends exactly one query: the second upstream is
        # never contacted, so no split-DNS name leaks and answers stay
        # deterministic. (A racing forwarder would record two hits here.)
        self.assertEqual(len(self.upstream.hits), 1)

    def test_dead_first_upstream_fails_over(self):
        query = b"\xab\xcd\x01\x00question"
        response = forward_udp(
            query, [DEAD, "127.0.0.1"], timeout=2, port=self.port
        )
        self.assertEqual(response, canned_response(query))

    def test_all_dead_upstreams_answer_nothing(self):
        query = b"\xab\xcd\x01\x00question"
        self.assertIsNone(forward_udp(query, [DEAD], timeout=0.3))

    def test_foreign_txid_replies_are_ignored(self):
        bad = UdpServer(("127.0.0.1", 0), BadTxidUdpUpstream)
        start(bad)
        self.addCleanup(bad.shutdown)
        self.addCleanup(bad.server_close)
        query = b"\x11\x11\x01\x00question"
        self.assertIsNone(
            forward_udp(query, ["127.0.0.1"], timeout=0.3, port=bad.server_address[1])
        )

    def test_udp_socket_connected_to_queried_upstream(self):
        # Regression guard for source enforcement: the query socket must be
        # connected to the upstream so the kernel drops off-path replies
        # instead of the forwarder accepting any TXID match via recvfrom.
        peers = []
        real_socket = socket.socket

        class RecordingSocket(real_socket):
            def connect(self, address):
                peers.append(address)
                return super().connect(address)

        query = b"\x77\x00\x01\x00question"
        with mock.patch.object(socket, "socket", RecordingSocket):
            response = forward_udp(
                query, [DEAD, "127.0.0.1"], timeout=2, port=self.port
            )
        self.assertEqual(response, canned_response(query))
        self.assertIn((DEAD, self.port), peers)
        self.assertIn(("127.0.0.1", self.port), peers)

    def test_empty_query_and_no_upstreams(self):
        self.assertIsNone(forward_udp(b"", ["127.0.0.1"], timeout=0.3, port=self.port))
        self.assertIsNone(forward_udp(b"\x00\x01", [], timeout=0.3))


class TcpFailoverTests(unittest.TestCase):
    def setUp(self):
        self.upstream = TcpServer(("127.0.0.1", 0), FakeTcpUpstream)
        start(self.upstream)
        self.addCleanup(self.upstream.shutdown)
        self.addCleanup(self.upstream.server_close)
        self.port = self.upstream.server_address[1]

    def test_tcp_relay(self):
        query = b"\x99\x00\x01\x00question"
        response = forward_tcp(
            query, ["127.0.0.1"], timeout=2, port=self.port
        )
        self.assertEqual(response, canned_response(query))

    def test_tcp_skips_dead_first_upstream(self):
        query = b"\x99\x01\x01\x00question"
        response = forward_tcp(
            query, [DEAD, "127.0.0.1"], timeout=2, port=self.port
        )
        self.assertEqual(response, canned_response(query))

    def test_tcp_all_dead_returns_nothing(self):
        self.assertIsNone(forward_tcp(b"\x99\x02\x01\x00q", [DEAD], timeout=0.3))

    def test_tcp_short_response_is_rejected(self):
        short = TcpServer(("127.0.0.1", 0), ShortTcpUpstream)
        start(short)
        self.addCleanup(short.shutdown)
        self.addCleanup(short.server_close)
        query = b"\x99\x03\x01\x00question"
        self.assertIsNone(
            forward_tcp(
                query, ["127.0.0.1"], timeout=2, port=short.server_address[1]
            )
        )


class ForwarderServerTests(unittest.TestCase):
    """End-to-end relay through the real handlers and failover layer."""

    def _serve(self, upstreams, udp_port, tcp_port):
        udp, unused_tcp = make_servers(
            "127.0.0.1", 0, SharedState(upstreams, timeout=1, port=udp_port)
        )
        unused_tcp.server_close()
        unused_udp, tcp = make_servers(
            "127.0.0.1", 0, SharedState(upstreams, timeout=1, port=tcp_port)
        )
        unused_udp.server_close()
        start(udp)
        start(tcp)
        self.addCleanup(udp.shutdown)
        self.addCleanup(tcp.shutdown)
        self.addCleanup(udp.server_close)
        self.addCleanup(tcp.server_close)
        return udp, tcp

    def setUp(self):
        self.udp_up = UdpServer(("127.0.0.1", 0), FakeUdpUpstream)
        start(self.udp_up, hits=[])
        self.addCleanup(self.udp_up.shutdown)
        self.addCleanup(self.udp_up.server_close)
        self.tcp_up = TcpServer(("127.0.0.1", 0), FakeTcpUpstream)
        start(self.tcp_up)
        self.addCleanup(self.tcp_up.shutdown)
        self.addCleanup(self.tcp_up.server_close)

    def test_udp_end_to_end_with_dead_first(self):
        udp, _ = self._serve(
            [DEAD, "127.0.0.1"],
            self.udp_up.server_address[1],
            self.tcp_up.server_address[1],
        )
        query = b"\x12\x34\x01\x00question"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(query, ("127.0.0.1", udp.server_address[1]))
            data, _ = sock.recvfrom(65535)
        self.assertEqual(data, canned_response(query))

    def test_tcp_end_to_end(self):
        _, tcp = self._serve(
            ["127.0.0.1"],
            self.udp_up.server_address[1],
            self.tcp_up.server_address[1],
        )
        query = b"\x56\x78\x01\x00question"
        with socket.create_connection(
            ("127.0.0.1", tcp.server_address[1]), timeout=3
        ) as conn:
            conn.settimeout(3)
            conn.sendall(struct.pack("!H", len(query)) + query)
            header = conn.recv(2)
            (length,) = struct.unpack("!H", header)
            data = b""
            while len(data) < length:
                chunk = conn.recv(length - len(data))
                self.assertTrue(chunk)
                data += chunk
        self.assertEqual(data, canned_response(query))

    def test_no_upstream_means_no_answer(self):
        udp, _ = self._serve(
            [DEAD],
            self.udp_up.server_address[1],
            self.tcp_up.server_address[1],
        )
        query = b"\x12\x35\x01\x00question"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.sendto(query, ("127.0.0.1", udp.server_address[1]))
            with self.assertRaises(socket.timeout):
                sock.recvfrom(65535)


class MainSmokeTests(unittest.TestCase):
    """main() binds, polls empty host dirs, and serves without crashing."""

    def test_main_listens_with_no_host_upstreams(self):
        errors = []
        old_hook = threading.excepthook
        threading.excepthook = lambda args: errors.append(args.exc_value)
        try:
            with tempfile.TemporaryDirectory(prefix="dns-main-") as tmp:
                base = Path(tmp)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.bind(("127.0.0.1", 0))
                    port = probe.getsockname()[1]
                env = {
                    "DNS_LISTEN": "127.0.0.1",
                    "DNS_PORT": str(port),
                    "DNS_TIMEOUT": "0.2",
                    "DNS_POLL_INTERVAL": "0.05",
                    "HOST_ETC": str(base / "etc"),
                    "HOST_RUN": str(base / "run"),
                }
                with mock.patch.dict("os.environ", env):
                    thread = threading.Thread(
                        target=forwarder.main, daemon=True
                    )
                    thread.start()
                    deadline = time.time() + 5
                    while True:
                        try:
                            socket.create_connection(
                                ("127.0.0.1", port), timeout=0.5
                            ).close()
                            break
                        except OSError:
                            if time.time() > deadline:
                                self.fail("forwarder did not start listening")
                            time.sleep(0.05)
                    time.sleep(0.3)  # let several poll cycles run
        finally:
            threading.excepthook = old_hook
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
