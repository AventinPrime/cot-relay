"""
State Store = Merge Engine + Change Filter in one module.

- Merge: by default (trust_uid=True, per-source), an object's uid is
  taken as-is and treated as globally unique - matching how a real ATAK
  client behaves (it merges by uid regardless of which server told it).
  Two different servers reporting the same uid are treated as THE SAME
  object and coalesced into one State Store entry. For sources where uid
  uniqueness can't be trusted (predictable/generated schemes - sensor or
  detection feeds, not human-carried ATAK devices), pass trust_uid=False
  for that source's events: the uid gets namespaced as
  "<source>-<original_uid>" so it can never collide with anything from
  another source, at the cost of never being merged with a genuinely
  matching object elsewhere either.
- Filter: an event counts as "significant" (and moves on to the Router)
  if the object is new, has moved past the threshold, hasn't been updated
  in longer than the heartbeat interval, or its type/callsign changed.
  The comparison is against the last PUSHED state, not the last received
  one - otherwise small movements would never accumulate to the threshold.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

from cot import CotEvent, haversine_m, namespace_uid


@dataclass
class ChangeEvent:
    namespaced_uid: str  # the merge key actually used - the raw uid when trusted, "<source>-<uid>" otherwise
    origin_source: str
    raw: bytes          # bytes ready to forward - unchanged when trusted, uid-rewritten otherwise
    cot: CotEvent


@dataclass
class _Tracked:
    source: str
    uid: str
    lat: float
    lon: float
    callsign: Optional[str]
    type: str
    last_pushed_ts: float
    last_seen_ts: float


class StateStore:
    def __init__(
        self,
        distance_threshold_m: float = 25.0,
        heartbeat_interval_s: float = 60.0,
        stale_after_s: float = 120.0,
    ) -> None:
        self.distance_threshold_m = distance_threshold_m
        self.heartbeat_interval_s = heartbeat_interval_s
        self.stale_after_s = stale_after_s
        self._lock = threading.Lock()
        self._states: dict[str, _Tracked] = {}

    def ingest(self, cot: CotEvent, trust_uid: bool = True) -> Optional[ChangeEvent]:
        key = cot.uid if trust_uid else f"{cot.source}-{cot.uid}"
        now = time.time()

        with self._lock:
            prev = self._states.get(key)
            significant = prev is None

            if prev is not None:
                dist = haversine_m(prev.lat, prev.lon, cot.lat, cot.lon)
                elapsed = now - prev.last_pushed_ts
                if (
                    dist >= self.distance_threshold_m
                    or elapsed >= self.heartbeat_interval_s
                    or cot.callsign != prev.callsign
                    or cot.type != prev.type
                ):
                    significant = True

            if significant:
                self._states[key] = _Tracked(
                    source=cot.source, uid=cot.uid,
                    lat=cot.lat, lon=cot.lon, callsign=cot.callsign, type=cot.type,
                    last_pushed_ts=now, last_seen_ts=now,
                )
            elif prev is not None:
                # not significant enough to push, but still update "last
                # seen" for future TTL cleanup
                prev.last_seen_ts = now

        if not significant:
            return None

        raw = cot.raw if trust_uid else namespace_uid(cot.raw, key)
        return ChangeEvent(namespaced_uid=key, origin_source=cot.source, raw=raw, cot=cot)

    def snapshot(self) -> list[dict]:
        """Current state of every tracked POSITIONAL object - for the live
        panel ("what the relay is actually pulling from the servers right
        now"). Text/chat events (type "b-t-*") are excluded here - they
        aren't objects with a position, they go through ChatLog instead."""
        now = time.time()
        with self._lock:
            return [
                {
                    "namespaced_uid": ns_uid,
                    "source": t.source,
                    "uid": t.uid,
                    "type": t.type,
                    "callsign": t.callsign,
                    "lat": t.lat,
                    "lon": t.lon,
                    "age_seconds": round(now - t.last_seen_ts, 1),
                    "pushed_seconds_ago": round(now - t.last_pushed_ts, 1),
                }
                for ns_uid, t in self._states.items()
                if not t.type.startswith("b-t-")
            ]

    def purge_stale(self) -> int:
        """Removes objects nothing has been heard from in a long time. Returns the count removed."""
        now = time.time()
        removed = 0
        with self._lock:
            stale_uids = [
                uid for uid, t in self._states.items()
                if now - t.last_seen_ts > self.stale_after_s
            ]
            for uid in stale_uids:
                del self._states[uid]
                removed += 1
        return removed


class ChatLog:
    """
    A rolling log of GeoChat (type "b-t-f") messages seen across all
    connections. Unlike StateStore, this is NOT keyed/merged by uid -
    every message is its own distinct event, not a "current state" to
    overwrite. Kept separate from position tracking on purpose (see
    StateStore.snapshot's exclusion of "b-t-*" types).
    """

    def __init__(self, max_messages: int = 500) -> None:
        self._lock = threading.Lock()
        self._messages: deque[dict] = deque(maxlen=max_messages)

    def add(self, cot: CotEvent) -> None:
        with self._lock:
            self._messages.append({
                "uid": cot.uid,
                "source": cot.source,
                "room": cot.chat_room or "",
                "sender": cot.chat_sender or cot.callsign or "",
                "message": cot.chat_message or "",
                "cot_time": cot.time,
                "age_seconds": 0.0,  # filled in on snapshot()
                "_received_at": time.time(),
            })

    def snapshot(self) -> list[dict]:
        now = time.time()
        with self._lock:
            out = []
            for m in self._messages:
                item = {k: v for k, v in m.items() if not k.startswith("_")}
                item["age_seconds"] = round(now - m["_received_at"], 1)
                out.append(item)
            return out
