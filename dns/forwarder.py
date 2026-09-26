"""Bridge-local DNS forwarder that tracks the host resolver.

The agent container keeps Docker bridge isolation and points its embedded
resolver at this sidecar (compose ``dns:``). The sidecar reads the host's
resolver files through read-only bind mounts and re-reads them on a short
poll, so host Wi-Fi DNS changes apply without recreating the agent.

Linux-specific: the host paths below are the systemd-resolved /
NetworkManager resolver state. No portability beyond Linux is claimed.

Behaviour notes:

* Host absolute paths are remapped into the sidecar mounts: ``/etc/...``
  reads through ``HOST_ETC`` and ``/run/...`` (plus ``/var/run/...``)
  through ``HOST_RUN``. Anything else (e.g. a distro linking
  ``/etc/resolv.conf`` outside ``/etc`` and ``/run``) is unreadable and
  yields no upstreams. Symlinks are resolved manually, link by link, so an
  absolute ``/run/...`` symlink target is remapped instead of escaping
  into the sidecar's own ``/run``.
* Only real (non-loopback) upstreams are used. A loopback entry such as the
  systemd-resolved stub (127.0.0.53) would point at this container itself,
  so when the primary file is loopback-only the real uplink lists are
  used instead, in order: ``/run/systemd/resolve/resolv.conf``,
  ``/run/NetworkManager/no-stub-resolv.conf`` (the actual uplinks when NM
  runs a caching plugin), then ``/run/NetworkManager/resolv.conf``.
* There is deliberately no public-DNS fallback: inventing one would leak
  split-horizon (Tailscale/VPN) names to a third party. With no usable
  upstream the forwarder drops queries. Every detected resolver change is
  adopted wholesale — including a change to nothing usable, which clears
  the old addresses rather than serving stale servers as if split DNS
  still worked.
* Queries use ordered failover over UDP. Truncated (TC) replies are
  relayed untouched; the caller retries over TCP, which is forwarded the
  same way. Upstreams are never queried in parallel: fanning every server
  with each query would leak split-DNS names to all of them and make
  NXDOMAIN answers nondeterministic. A dead first upstream costs one
  per-upstream timeout per query until the host files change.
* The UDP socket is connected before sending, so the kernel only delivers
  replies from the queried upstream; off-path packets with a guessed TXID
  are dropped instead of relayed.
* Host files are polled, not watched with inotify: polling also follows
  atomic renames (write-temp-and-rename) and symlink swaps through the
  bind-mounted directories, and needs only the standard library.

Environment:

  DNS_PORT            listen port (default 53; tests use an ephemeral port)
  DNS_LISTEN          listen address (default 0.0.0.0)
  DNS_TIMEOUT         per-upstream seconds (default 2)
  DNS_POLL_INTERVAL   host-file poll seconds (default 2)
  HOST_ETC            host /etc bind (default /host/etc)
  HOST_RUN            host /run bind (default /host/run)
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import posixpath
import socket
import socketserver
import struct
import threading
import time

MAX_UPSTREAMS = 3  # match glibc MAXNS
READ_BYTES = 1 << 20
_LINK_DEPTH = 8

# Uplink lists consulted when the primary file is loopback-only, in order.
# no-stub-resolv.conf holds the actual upstreams when NetworkManager runs a
# caching plugin; resolv.conf there may just repeat the loopback cache.
_STUB_FALLBACKS = (
    "/run/systemd/resolve/resolv.conf",
    "/run/NetworkManager/no-stub-resolv.conf",
    "/run/NetworkManager/resolv.conf",
)


def parse_resolv_conf(text: str) -> list[str]:
    """Return validated ``nameserver`` IPs in file order, capped."""
    servers: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2 or parts[0] != "nameserver":
            continue
        try:
            addr = ipaddress.ip_address(parts[1])
        except ValueError:
            continue
        if addr.is_unspecified:
            continue
        text_addr = str(addr)
        if text_addr not in servers:
            servers.append(text_addr)
        if len(servers) >= MAX_UPSTREAMS:
            break
    return servers


def _remap(host_abs: str, host_etc: str, host_run: str) -> str | None:
    """Map an absolute host path into the sidecar's bind mounts."""
    if host_abs == "/etc" or host_abs.startswith("/etc/"):
        return host_etc + host_abs[4:]
    if host_abs == "/run" or host_abs.startswith("/run/"):
        return host_run + host_abs[4:]
    if host_abs == "/var/run" or host_abs.startswith("/var/run/"):
        return host_run + host_abs[8:]
    return None


def _resolve_container_path(
    host_etc: str, host_run: str, host_start: str
) -> tuple[list[tuple[str, str]], str | None]:
    """Follow symlinks manually so absolute targets stay remapped.

    Returns the (container path, link target) chain and the final container
    path, or None when a target escapes the binds or links run too deep.
    A path that is not a link (or cannot be read) ends the chain and is
    returned as-is; opening it decides readability.
    """
    chain: list[tuple[str, str]] = []
    host_cur = posixpath.normpath(host_start)
    for _ in range(_LINK_DEPTH):
        container = _remap(host_cur, host_etc, host_run)
        if container is None:
            return chain, None
        try:
            target = os.readlink(container)
        except OSError:
            return chain, container
        chain.append((container, target))
        if posixpath.isabs(target):
            host_cur = posixpath.normpath(target)
        else:
            host_cur = posixpath.normpath(
                posixpath.join(posixpath.dirname(host_cur), target)
            )
    return chain, None


def read_host_nameservers(host_etc: str, host_run: str, host_abs: str) -> list[str]:
    """Read one host resolver file through the remapped binds."""
    _, container = _resolve_container_path(host_etc, host_run, host_abs)
    if container is None:
        return []
    try:
        with open(container, "r", encoding="utf-8", errors="replace") as handle:
            return parse_resolv_conf(handle.read())
    except OSError:
        return []


def _is_loopback(server: str) -> bool:
    try:
        return ipaddress.ip_address(server).is_loopback
    except ValueError:
        return True


def load_upstreams(host_etc: str, host_run: str) -> list[str]:
    """Return usable host upstreams, resolving loopback stubs to uplinks."""
    direct = [
        s
        for s in read_host_nameservers(host_etc, host_run, "/etc/resolv.conf")
        if not _is_loopback(s)
    ]
    if direct:
        return direct[:MAX_UPSTREAMS]
    for alt in _STUB_FALLBACKS:
        found = [
            s
            for s in read_host_nameservers(host_etc, host_run, alt)
            if not _is_loopback(s)
        ]
        if found:
            return found[:MAX_UPSTREAMS]
    return []


class UpstreamTracker:
    """Poll host resolver files; adopt every detected change wholesale."""

    _ALTS = _STUB_FALLBACKS

    def __init__(
        self,
        host_etc: str = "/host/etc",
        host_run: str = "/host/run",
    ) -> None:
        self.host_etc = host_etc
        self.host_run = host_run
        self.starts = ["/etc/resolv.conf", *self._ALTS]
        self.current: list[str] = []
        self._fingerprint = None

    def _mark(self, container: str | None):
        if container is None:
            return None
        try:
            stat = os.stat(container)
            ident = (stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_size)
        except OSError:
            return None
        try:
            with open(container, "rb") as handle:
                digest = hashlib.sha256(handle.read(READ_BYTES)).hexdigest()
        except OSError:
            digest = None
        return (ident, digest)

    def fingerprint(self):
        marks = []
        for start in self.starts:
            chain, final = _resolve_container_path(
                self.host_etc, self.host_run, start
            )
            marks.append((tuple(chain), self._mark(final) if final else None))
        return tuple(marks)

    def poll(self) -> list[str] | None:
        """Return the new upstream list once per change, else None.

        Any change is adopted as-is, including a change to no usable
        upstream (returns [] and clears ``current``) so stale servers are
        never served as if split DNS still worked. Unchanged files return
        None and ``current`` is kept.
        """
        fingerprint = self.fingerprint()
        if fingerprint == self._fingerprint:
            return None
        self._fingerprint = fingerprint
        upstreams = load_upstreams(self.host_etc, self.host_run)
        if upstreams == self.current:
            return None
        self.current = upstreams
        return upstreams


class SharedState:
    def __init__(
        self, upstreams: list[str], timeout: float, port: int = 53
    ) -> None:
        self._lock = threading.Lock()
        self._upstreams = list(upstreams)
        self.timeout = timeout
        self.port = port

    def get(self) -> list[str]:
        with self._lock:
            return list(self._upstreams)

    def set(self, upstreams: list[str]) -> None:
        with self._lock:
            self._upstreams = list(upstreams)


def _family(server: str) -> int:
    return socket.AF_INET6 if ":" in server else socket.AF_INET


def _txid_ok(data: bytes, txid: bytes) -> bool:
    return len(data) >= 2 and data[:2] == txid


def forward_udp(
    query: bytes, upstreams: list[str], timeout: float, port: int = 53
) -> bytes | None:
    """Forward one query over UDP with ordered failover."""
    if len(query) < 2 or not upstreams:
        return None
    txid = query[:2]
    for server in upstreams:
        try:
            # Connected socket: the kernel only delivers replies from the
            # queried upstream, so off-path spoofs with a guessed TXID are
            # dropped instead of relayed.
            with socket.socket(_family(server), socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.connect((server, port))
                sock.sendall(query)
                data = sock.recv(65535)
            if _txid_ok(data, txid):
                return data
        except OSError:
            continue
    return None


def _recvn(conn: socket.socket, count: int) -> bytes:
    chunks = []
    while sum(len(part) for part in chunks) < count:
        try:
            part = conn.recv(count - sum(len(p) for p in chunks))
        except OSError:
            return b""
        if not part:
            return b""
        chunks.append(part)
    return b"".join(chunks)


def forward_tcp(
    query: bytes, upstreams: list[str], timeout: float, port: int = 53
) -> bytes | None:
    """Forward one query over TCP with ordered failover."""
    if len(query) < 2 or not upstreams:
        return None
    txid = query[:2]
    frame = struct.pack("!H", len(query)) + query
    for server in upstreams:
        try:
            with socket.create_connection(
                (server, port), timeout=timeout
            ) as conn:
                conn.settimeout(timeout)
                conn.sendall(frame)
                header = _recvn(conn, 2)
                if len(header) != 2:
                    continue
                (length,) = struct.unpack("!H", header)
                if length < 2:
                    continue
                data = _recvn(conn, length)
            # A short read is a corrupt response, never a relayable one.
            if len(data) != length:
                continue
            if _txid_ok(data, txid):
                return data
        except OSError:
            continue
    return None


class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        state: SharedState = self.server.state  # type: ignore[attr-defined]
        response = forward_udp(data, state.get(), state.timeout, state.port)
        if response is not None:
            try:
                sock.sendto(response, self.client_address)
            except OSError:
                pass


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        state: SharedState = self.server.state  # type: ignore[attr-defined]
        conn = self.request
        conn.settimeout(state.timeout + 5)
        while True:
            header = _recvn(conn, 2)
            if len(header) != 2:
                return
            (length,) = struct.unpack("!H", header)
            if length < 12 or length > 65535:
                return
            query = _recvn(conn, length)
            if len(query) != length:
                return
            response = forward_tcp(query, state.get(), state.timeout, state.port)
            if response is None:
                return
            try:
                conn.sendall(struct.pack("!H", len(response)) + response)
            except OSError:
                return


class _UdpServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class _TcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_servers(host: str, port: int, state: SharedState):
    udp = _UdpServer((host, port), _UdpHandler)
    tcp = _TcpServer((host, port), _TcpHandler)
    udp.state = state  # type: ignore[attr-defined]
    tcp.state = state  # type: ignore[attr-defined]
    return udp, tcp


def _log(message: str) -> None:
    print(f"[dns] {message}", flush=True)


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def main() -> None:
    host = _env("DNS_LISTEN", "0.0.0.0")
    port = int(_env("DNS_PORT", "53"))
    timeout = float(_env("DNS_TIMEOUT", "2"))
    interval = float(_env("DNS_POLL_INTERVAL", "2"))
    tracker = UpstreamTracker(
        host_etc=_env("HOST_ETC", "/host/etc"),
        host_run=_env("HOST_RUN", "/host/run"),
    )
    upstreams = tracker.poll()
    state = SharedState(tracker.current, timeout)
    if upstreams:
        _log(f"initial upstreams: {' '.join(upstreams)}")
    else:
        _log("no usable host upstreams yet; waiting for host resolver files")
    udp, tcp = make_servers(host, port, state)
    for server in (udp, tcp):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    _log(f"listening on {host}:{port}")
    try:
        while True:
            time.sleep(interval)
            changed = tracker.poll()
            if changed is not None:
                state.set(changed)
                if changed:
                    _log(f"upstreams now: {' '.join(changed)}")
                else:
                    _log("upstreams cleared: host resolver has no usable servers")
    except KeyboardInterrupt:
        pass
    finally:
        udp.shutdown()
        tcp.shutdown()


if __name__ == "__main__":
    main()
