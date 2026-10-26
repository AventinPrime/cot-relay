"""
Parsing the CoT event stream (TAK protocol v1 / plain XML) and low-level
operations on the "raw" event bytes.

Key architectural decision: the relay does NOT rebuild a CoT event from
scratch via ElementTree on the way out. It only parses the fields it needs
to make decisions (uid, type, coordinates, callsign), and forwards the
original event bytes with a surgical uid substitution in the opening
<event ...> tag. This is safer than a full rebuild: event details (chat,
attachments, arbitrary plugin extensions) that the relay doesn't understand
are never lost or mangled as they pass through it.
"""

from __future__ import annotations

import math
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional

MAX_BUFFER_BYTES = 4 * 1024 * 1024  # guard against unbounded buffer growth on garbage data

_EVENT_OPEN_RE = re.compile(rb"<event\b")
_EVENT_CLOSE = b"</event>"
_OPENING_TAG_RE = re.compile(rb"^\s*(?:<\?xml[^>]*\?>\s*)?<event\b[^>]*>", re.DOTALL)
_UID_ATTR_RE = re.compile(rb'uid="[^"]*"')


@dataclass
class CotEvent:
    raw: bytes           # original <event ...>...</event> bytes, uid NOT yet renamed
    uid: str
    type: str
    time: str
    stale: str
    lat: float
    lon: float
    callsign: Optional[str]
    source: str           # name of the server connection this event came from
    chat_room: Optional[str] = None       # only set for type "b-t-f" (GeoChat)
    chat_sender: Optional[str] = None
    chat_message: Optional[str] = None


class CoTStreamParser:
    """
    Incremental parsing of a TCP byte stream into individual CoT events.

    A TAK server sends events back-to-back with no delimiters, so the
    buffer can't just be fed whole into ElementTree (it isn't one XML
    document, it's a sequence of documents). We split on <event ...>
    ... </event> boundaries by hand; CoT never nests <event> tags, so the
    first "</event>" found after a "<event" is a correct boundary.
    """

    def __init__(self) -> None:
        self._buffer = b""

    def feed(self, data: bytes) -> list[bytes]:
        self._buffer += data
        events: list[bytes] = []

        while True:
            start_match = _EVENT_OPEN_RE.search(self._buffer)
            if start_match is None:
                # no event start — if the buffer has accumulated garbage
                # with no sign of CoT in it, trim it so it doesn't grow forever
                if len(self._buffer) > MAX_BUFFER_BYTES:
                    self._buffer = b""
                break

            start = start_match.start()
            end = self._buffer.find(_EVENT_CLOSE, start)
            if end == -1:
                # event hasn't fully arrived yet — drop everything BEFORE
                # the event start (could have been garbage/an xml
                # declaration from the previous fragment) and wait for the rest
                self._buffer = self._buffer[start:]
                if len(self._buffer) > MAX_BUFFER_BYTES:
                    self._buffer = b""
                break

            end += len(_EVENT_CLOSE)
            events.append(self._buffer[start:end])
            self._buffer = self._buffer[end:]

        return events


def parse_cot_event(raw: bytes, source: str) -> Optional[CotEvent]:
    """Parses the raw bytes of a single CoT event into a CotEvent. None on parse error."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None

    uid = root.get("uid", "")
    if not uid:
        return None

    point = root.find("point")
    try:
        lat = float(point.get("lat", "0")) if point is not None else 0.0
        lon = float(point.get("lon", "0")) if point is not None else 0.0
    except (TypeError, ValueError):
        lat, lon = 0.0, 0.0

    callsign = None
    detail = root.find("detail")
    if detail is not None:
        contact = detail.find("contact")
        if contact is not None:
            callsign = contact.get("callsign")

    cot_type = root.get("type", "")
    chat_room = chat_sender = chat_message = None
    if cot_type == "b-t-f" and detail is not None:
        # exact match only: "b-t-f" is an actual chat message. "b-t-f-d"
        # (delivered) and "b-t-f-r" (read) are receipts on the same
        # family - they carry no message text and must NOT be parsed as
        # chat content, or shown in the chat log as empty messages.
        chat_el = detail.find("__chat")
        if chat_el is not None:
            chat_room = chat_el.get("chatroom")
            chat_sender = chat_el.get("senderCallsign")
        remarks = detail.find("remarks")
        if remarks is not None:
            chat_message = remarks.text
            if not chat_room:
                # group-chat room name is usually on __chat/@chatroom, but
                # fall back to remarks/@to (documented alternative location)
                chat_room = remarks.get("to")

    return CotEvent(
        raw=raw,
        uid=uid,
        type=cot_type,
        time=root.get("time", ""),
        stale=root.get("stale", ""),
        lat=lat,
        lon=lon,
        callsign=callsign,
        source=source,
        chat_room=chat_room,
        chat_sender=chat_sender,
        chat_message=chat_message,
    )


def namespace_uid(raw: bytes, new_uid: str) -> bytes:
    """
    Replaces uid ONLY in the opening <event ...> tag, leaving alone any
    uid that might appear inside detail (e.g. in <link uid="..."> pointing
    at another entity) — otherwise we could accidentally break the
    event's internal references to other objects.
    """
    match = _OPENING_TAG_RE.match(raw)
    if not match:
        return raw
    opening = match.group(0)
    new_opening = _UID_ATTR_RE.sub(f'uid="{new_uid}"'.encode("utf-8"), opening, count=1)
    return new_opening + raw[len(opening):]


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distance between two points in meters (for the significant-change threshold)."""
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def _cot_time(offset_seconds: int = 0) -> str:
    t = time.gmtime(time.time() + offset_seconds)
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", t)


def build_presence_xml(
    uid: str,
    callsign: str,
    lat: float = 0.0,
    lon: float = 0.0,
    stale_seconds: int = 90,
    group_name: str = "Cyan",
    group_role: str = "Team Member",
) -> bytes:
    """
    Self-presence marker: the relay periodically sends this event about
    itself so it's visible on the server as a live connection with a
    readable callsign, rather than a nameless TCP client. lat/lon default
    to 0,0 with a huge ce — this is the "position unknown/not applicable"
    convention, not a real point on the map (the relay isn't physically
    tied to one location). Set real lat/lon in the config to show the
    marker there instead.

    Besides contact/remarks, takv/__group/status/track are included — the
    set a real ATAK client always sends. The reason for adding them
    isn't confirmed against the server source (couldn't conclusively
    establish what GoATAK's Item classifier actually needs for an event
    to land in the Units/Dashboard list) — this is a careful approximation
    of a "real" client, not a guaranteed fix. If the marker still doesn't
    show up after this, the cause isn't the detail contents — see the
    README (scope, server-side CoT log).
    """
    root = ET.Element("event")
    root.set("version", "2.0")
    root.set("uid", uid)
    root.set("type", "a-f-G-U-C")
    root.set("how", "m-g")
    now = _cot_time()
    root.set("time", now)
    root.set("start", now)
    root.set("stale", _cot_time(stale_seconds))

    point = ET.SubElement(root, "point")
    point.set("lat", f"{lat:.7f}")
    point.set("lon", f"{lon:.7f}")
    point.set("hae", "0")
    point.set("ce", "9999999" if (lat == 0.0 and lon == 0.0) else "50")
    point.set("le", "9999999")

    detail = ET.SubElement(root, "detail")
    contact = ET.SubElement(detail, "contact")
    contact.set("callsign", callsign)
    remarks = ET.SubElement(detail, "remarks")
    remarks.text = "CoT Relay - service bridge connection, not a combat unit"

    takv = ET.SubElement(detail, "takv")
    takv.set("os", "linux")
    takv.set("version", "1.0")
    takv.set("device", "cot-relay")
    takv.set("platform", "CoT-Relay")

    group = ET.SubElement(detail, "__group")
    group.set("name", group_name)
    group.set("role", group_role)

    status = ET.SubElement(detail, "status")
    status.set("battery", "100")

    track = ET.SubElement(detail, "track")
    track.set("speed", "0.0")
    track.set("course", "0.0")

    return ET.tostring(root)
