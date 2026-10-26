"""
Connection Manager: a single TLS connection to a single TAK server (GoATAK
and compatible), with auto-reconnect, reading the incoming CoT stream, and
writing outbound data with uid-coalescing.
"""

from __future__ import annotations

import logging
import os
import socket
import ssl
import threading
import time
from typing import Callable, Optional

from certs import is_p12, p12_to_temp_pem_cert_key, p12_truststore_to_temp_pem
from cot import CoTStreamParser, CotEvent, build_presence_xml, parse_cot_event

log = logging.getLogger("relay.connection")

RECONNECT_DELAY_S = 3
SOCKET_TIMEOUT_S = 30
ECHO_SUPPRESS_WINDOW_S = 180  # must comfortably outlast the gap between two of our
# own forwards of the same object (heartbeat_interval_s, default 60s) AND any
# periodic full-resync a server might do on its own (documented at ~30s for at
# least one real TAK-adjacent server implementation) - 20s was too short: it
# expired between our own heartbeat-spaced re-sends, so a server-side resync
# landing in that gap would slip past the echo check and get re-namespaced
# under a second name for the same real object.
WRITER_IDLE_TIMEOUT_S = 45  # if there's nothing to send for this many seconds, send a self-presence marker (also serves as keep-alive)


class CoalescingQueue:
    """
    An "outbound" queue where a new value for the same key (namespaced
    uid) REPLACES the previous pending one instead of queuing behind it.
    This way the relay doesn't pile up stale intermediate positions for a
    slow receiver — it only ever sees the freshest state of the object.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._items: dict[str, bytes] = {}
        self._closed = False

    def put(self, key: str, value: bytes) -> None:
        with self._cond:
            if self._closed:
                return
            self._items[key] = value
            self._cond.notify()

    def drain(self, timeout: Optional[float] = None) -> list[bytes]:
        with self._cond:
            if not self._items and not self._closed:
                self._cond.wait(timeout=timeout)
            items = list(self._items.values())
            self._items.clear()
            return items

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()


class ServerConnection:
    """
    direction: "in" (receive only), "out" (send only), or "both". The
    socket is always read (needed to detect a dropped connection), but
    events are only handed off via on_event if direction allows receiving.
    """

    def __init__(
        self,
        name: str,
        host: str,
        port: int,
        cert: str,
        key: Optional[str] = None,
        ca: Optional[str] = None,
        verify: bool = True,
        direction: str = "both",
        cert_password: Optional[str] = None,
        ca_password: Optional[str] = None,
        identity_uid: Optional[str] = None,
        identity_callsign: Optional[str] = None,
        identity_lat: float = 0.0,
        identity_lon: float = 0.0,
        identity_stale_s: int = 90,
        echo_suppress_window_s: Optional[float] = None,
        on_event: Optional[Callable[[CotEvent], None]] = None,
    ) -> None:
        self.name = name
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.verify = verify
        self.direction = direction
        self.cert_password = cert_password  # client.p12 password, if cert is PKCS#12
        self.ca_password = ca_password       # truststore.p12 password, if ca is PKCS#12
        self.identity_uid = identity_uid or f"relay-{name}"
        self.identity_callsign = identity_callsign or f"CoT-Relay ({name})"
        self.identity_lat = identity_lat
        self.identity_lon = identity_lon
        self.identity_stale_s = identity_stale_s
        # falls back to the module default (already generous) if the caller
        # doesn't pass one derived from the configured heartbeat_interval_s
        self.echo_suppress_window_s = echo_suppress_window_s or ECHO_SUPPRESS_WINDOW_S
        self.on_event = on_event

        self.outbound = CoalescingQueue()
        self.connected = threading.Event()

        self._sock: Optional[ssl.SSLSocket] = None
        self._sock_lock = threading.Lock()
        self._write_lock = threading.Lock()  # sendall() can be hit from the reader (initial presence) and the writer at the same time
        self._running = threading.Event()
        self._threads: list[threading.Thread] = []

        # "small memory" of uids we ourselves recently wrote OUT on this
        # exact connection. If a server broadcasts to the whole scope
        # without excluding the sender, whatever we forward comes straight
        # back to us on our own inbound side, and without this check the
        # relay would treat its own echo as a brand-new object from this
        # server, re-namespace it (uid growing another "<name>-" prefix),
        # and potentially forward it onward again - a real amplification
        # risk in any bidirectional (A<->B) routing setup, not just a
        # cosmetic duplicate marker.
        self._recently_sent: dict[str, float] = {}
        self._recently_sent_lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------

    def start(self) -> None:
        self._running.set()
        reader = threading.Thread(target=self._reader_loop, name=f"reader-{self.name}", daemon=True)
        reader.start()
        self._threads.append(reader)

        # the writer thread always starts, regardless of direction: besides
        # forwarding data (which send() filters by direction anyway) it's
        # responsible for keep-alive and the self-presence marker — the
        # relay being "visible" on the server shouldn't depend on whether
        # we're also sending it anything else.
        writer = threading.Thread(target=self._writer_loop, name=f"writer-{self.name}", daemon=True)
        writer.start()
        self._threads.append(writer)

    def stop(self) -> None:
        self._running.clear()
        self.outbound.close()
        self._close_socket()

    def send(self, uid: str, raw: bytes) -> None:
        if self.direction not in ("out", "both"):
            return
        self._mark_sent(uid)
        self.outbound.put(uid, raw)

    def _is_recent_echo(self, uid: str) -> bool:
        now = time.time()
        with self._recently_sent_lock:
            # opportunistic cleanup so this dict never grows unbounded
            if len(self._recently_sent) > 2000:
                self._recently_sent = {
                    u: t for u, t in self._recently_sent.items()
                    if now - t < self.echo_suppress_window_s
                }
            sent_at = self._recently_sent.get(uid)
        return sent_at is not None and (now - sent_at) < self.echo_suppress_window_s

    # -- internals -----------------------------------------------------

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # we usually connect by IP or by an enrollment domain that doesn't
        # always match the CN/SAN in the certificate itself
        ctx.check_hostname = False

        temp_files: list[str] = []
        try:
            if is_p12(self.cert):
                cert_path, key_path = p12_to_temp_pem_cert_key(self.cert, self.cert_password)
                temp_files += [cert_path, key_path]
            else:
                cert_path, key_path = self.cert, self.key
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

            if self.ca:
                if is_p12(self.ca):
                    ca_path = p12_truststore_to_temp_pem(self.ca, self.ca_password)
                    temp_files.append(ca_path)
                else:
                    ca_path = self.ca
                ctx.load_verify_locations(cafile=ca_path)
                ctx.verify_mode = ssl.CERT_REQUIRED if self.verify else ssl.CERT_NONE
            else:
                # no CA set at all — a deliberate but LOUD downgrade: warn
                # on every connection attempt, not just silently once
                ctx.verify_mode = ssl.CERT_NONE
                log.warning(
                    "[%s] no CA set - server certificate is NOT verified (MITM possible)",
                    self.name,
                )
        finally:
            for p in temp_files:
                try:
                    os.remove(p)
                except OSError:
                    pass

        return ctx

    def _presence_bytes(self) -> bytes:
        return build_presence_xml(
            self.identity_uid, self.identity_callsign,
            self.identity_lat, self.identity_lon, self.identity_stale_s,
        )

    def _mark_sent(self, uid: str) -> None:
        with self._recently_sent_lock:
            self._recently_sent[uid] = time.time()

    def _close_socket(self) -> None:
        with self._sock_lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
        self.connected.clear()

    def _reader_loop(self) -> None:
        parser = CoTStreamParser()
        while self._running.is_set():
            try:
                ctx = self._build_ssl_context()
                raw_sock = socket.create_connection((self.host, self.port), timeout=10)
                sock = ctx.wrap_socket(raw_sock)
                sock.settimeout(SOCKET_TIMEOUT_S)
                with self._sock_lock:
                    self._sock = sock
                self.connected.set()
                log.info("[%s] connected (%s:%s)", self.name, self.host, self.port)

                # announce ourselves immediately, without waiting for the
                # writer's first cycle (otherwise for up to
                # WRITER_IDLE_TIMEOUT_S seconds the relay would show up on
                # the server as a bare, nameless TCP client)
                try:
                    with self._write_lock:
                        sock.sendall(self._presence_bytes())
                    self._mark_sent(self.identity_uid)
                except OSError as exc:
                    log.debug("[%s] initial presence send failed: %s", self.name, exc)

                while self._running.is_set():
                    try:
                        data = sock.recv(65536)
                    except socket.timeout:
                        continue
                    if not data:
                        raise ConnectionError("server closed connection")

                    events = parser.feed(data)
                    if self.direction in ("in", "both") and self.on_event:
                        for raw_event in events:
                            cot = parse_cot_event(raw_event, source=self.name)
                            if cot is not None:
                                if self._is_recent_echo(cot.uid):
                                    log.debug(
                                        "[%s] dropping echo of our own forwarded event, uid=%s",
                                        self.name, cot.uid,
                                    )
                                    continue
                                self.on_event(cot)

            except Exception as exc:  # noqa: BLE001 - must survive any socket error and reconnect
                if self._running.is_set():
                    log.warning("[%s] connection error: %s - reconnecting in %ss", self.name, exc, RECONNECT_DELAY_S)
                self._close_socket()
                if self._running.is_set():
                    time.sleep(RECONNECT_DELAY_S)

    def _writer_loop(self) -> None:
        while self._running.is_set():
            items = self.outbound.drain(timeout=WRITER_IDLE_TIMEOUT_S)
            with self._sock_lock:
                sock = self._sock
            if sock is None:
                # no connection yet/anymore - don't silently drop items:
                # wait for the reader to reconnect, the coalescing queue
                # keeps them (the next put with the same uid just
                # overwrites the value)
                time.sleep(0.5)
                continue

            if not items:
                try:
                    with self._write_lock:
                        sock.sendall(self._presence_bytes())
                    self._mark_sent(self.identity_uid)
                except OSError as exc:
                    log.debug("[%s] presence/keepalive send failed: %s", self.name, exc)
                continue

            for raw in items:
                try:
                    with self._write_lock:
                        sock.sendall(raw)
                except OSError as exc:
                    log.warning("[%s] send failed: %s", self.name, exc)
                    break
