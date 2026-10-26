from __future__ import annotations

import logging
import threading
import time

from connection import ServerConnection
from cot import CotEvent
from router import Route, Router
from state import ChatLog, StateStore

log = logging.getLogger("relay.core")

PURGE_INTERVAL_S = 30

# TAK protocol control/negotiation messages (protocol version handshake,
# pings, deletes, etc.) - never real trackable objects and never meant to
# be forwarded to a third party. Seen in practice from takserver.ru:
# uid "protouid", type "t-x-takp-v" (version negotiation), sent by the
# SERVER to us right after connecting.
CONTROL_TYPE_PREFIXES = ("t-x-",)


class Relay:
    def __init__(self, config: dict) -> None:
        filter_cfg = config.get("filter", {})
        state_cfg = config.get("state", {})
        self.state = StateStore(
            distance_threshold_m=filter_cfg.get("distance_threshold_m", 25.0),
            heartbeat_interval_s=filter_cfg.get("heartbeat_interval_s", 60.0),
            stale_after_s=state_cfg.get("stale_after_s", 120.0),
        )
        self.chat = ChatLog()

        # echo-suppression window must comfortably outlast the gap between
        # our own re-sends of an unchanged object (heartbeat_interval_s) -
        # 3x that, floored at the module default, so it stays safe even if
        # heartbeat_interval_s is configured much longer than the default
        heartbeat_interval_s = filter_cfg.get("heartbeat_interval_s", 60.0)
        echo_suppress_window_s = max(180.0, heartbeat_interval_s * 3)

        routes = [
            Route(
                source=r["from"],
                targets=list(r["to"]),
                cot_type_prefix=r.get("cot_type_prefix"),
                exclude_uid_prefix=r.get("exclude_uid_prefix"),
            )
            for r in config.get("routes", [])
        ]
        self.router = Router(routes)

        self.connections: dict[str, ServerConnection] = {}
        self._last_routed: dict[str, list[str]] = {}
        self._last_routed_lock = threading.Lock()
        # per-source uid trust: True (default) merges an object seen with
        # the same uid from multiple sources into one - matching how a
        # real ATAK client behaves. Set false per-server for sources whose
        # uid scheme isn't guaranteed globally unique (generated/sensor
        # feeds with predictable ids), so they instead get namespaced
        # ("<source>-<uid>") and can never collide with anything else.
        self.trust_uid: dict[str, bool] = {s["name"]: s.get("trust_uid", True) for s in config["servers"]}
        identity_cfg = config.get("identity", {})
        callsign_prefix = identity_cfg.get("callsign_prefix", "CoT-Relay")
        identity_lat = identity_cfg.get("lat") or 0.0
        identity_lon = identity_cfg.get("lon") or 0.0
        identity_stale_s = identity_cfg.get("stale_seconds", 90)

        for s in config["servers"]:
            self.connections[s["name"]] = ServerConnection(
                name=s["name"],
                host=s["host"],
                port=s["port"],
                cert=s["cert"],
                key=s.get("key"),
                ca=s.get("ca"),
                verify=s.get("verify_ca", True),
                direction=s.get("direction", "both"),
                cert_password=s.get("cert_password"),
                ca_password=s.get("ca_password"),
                identity_uid=f"relay-{s['name']}",
                identity_callsign=f"{callsign_prefix} ({s['name']})",
                identity_lat=identity_lat,
                identity_lon=identity_lon,
                identity_stale_s=identity_stale_s,
                echo_suppress_window_s=echo_suppress_window_s,
                on_event=self._on_event,
            )

        self._running = threading.Event()
        self._purge_thread: threading.Thread | None = None

    def _on_event(self, cot: CotEvent) -> None:
        if cot.type.startswith(CONTROL_TYPE_PREFIXES):
            log.debug(
                "skipping protocol control message %s (type=%s) from %s - not a trackable object",
                cot.uid, cot.type, cot.source,
            )
            return

        change = self.state.ingest(cot, trust_uid=self.trust_uid.get(cot.source, True))
        if change is None:
            return

        if cot.type == "b-t-f":  # exact match: excludes b-t-f-d/b-t-f-r receipts
            self.chat.add(cot)

        targets = self.router.targets_for(change)
        with self._last_routed_lock:
            self._last_routed[change.namespaced_uid] = sorted(targets)

        if not targets:
            log.debug(
                "no route matches for %s (from %s, type %s) - check Routes in the panel",
                change.namespaced_uid, change.origin_source, change.cot.type,
            )
            return

        log.debug(
            "routing %s (type=%s) from %s -> %s",
            change.namespaced_uid, change.cot.type, change.origin_source, targets,
        )
        for target_name in targets:
            conn = self.connections.get(target_name)
            if conn is None:
                log.warning("route references unknown server %r", target_name)
                continue
            conn.send(change.namespaced_uid, change.raw)

    def get_last_routed(self, namespaced_uid: str) -> list[str]:
        with self._last_routed_lock:
            return self._last_routed.get(namespaced_uid, [])

    def start(self) -> None:
        self._running.set()
        for conn in self.connections.values():
            conn.start()
        self._purge_thread = threading.Thread(target=self._purge_loop, daemon=True, name="purge")
        self._purge_thread.start()
        log.info("relay started with %d server connection(s)", len(self.connections))

    def stop(self) -> None:
        self._running.clear()
        for conn in self.connections.values():
            conn.stop()
        log.info("relay stopped")

    def _purge_loop(self) -> None:
        while self._running.is_set():
            time.sleep(PURGE_INTERVAL_S)
            removed = self.state.purge_stale()
            if removed:
                log.debug("purged %d stale object(s) from state store", removed)
