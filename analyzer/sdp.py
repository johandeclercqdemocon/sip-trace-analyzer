"""SDP parsing, enough to reason about offer/answer (RFC 3264, RFC 8866)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

DIRECTIONS = ("sendrecv", "sendonly", "recvonly", "inactive")
STATIC_PAYLOADS = {
    0: ("PCMU", 8000), 3: ("GSM", 8000), 4: ("G723", 8000), 5: ("DVI4", 8000),
    8: ("PCMA", 8000), 9: ("G722", 8000), 10: ("L16", 44100), 11: ("L16", 44100),
    18: ("G729", 8000), 34: ("H263", 90000),
}


# Ranges that are unroutable across a NAT boundary. Deliberately narrower than
# ipaddress.is_private, which also covers the documentation ranges (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24) that appear as stand-ins for public addresses.
_UNROUTABLE = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",    # RFC 1918
    "100.64.0.0/10",                                     # RFC 6598 CGNAT
    "169.254.0.0/16",                                    # link-local
    "fc00::/7", "fe80::/10",                             # ULA and link-local v6
)]


def is_private(host: str) -> bool:
    """True for addresses that cannot be reached from the other side of a NAT."""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in _UNROUTABLE)


def is_unspecified(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_unspecified
    except ValueError:
        return False


@dataclass
class Media:
    kind: str = ""              # audio | video | application | image
    port: int = 0
    port_count: int = 1
    proto: str = ""             # RTP/AVP | RTP/SAVP | UDP/TLS/RTP/SAVP | udptl ...
    formats: list[str] = field(default_factory=list)
    connection: str | None = None       # media-level c=, overrides session level
    attributes: list[tuple[str, str]] = field(default_factory=list)
    rtpmap: dict[int, tuple[str, int]] = field(default_factory=dict)   # pt -> (name, rate)
    fmtp: dict[int, str] = field(default_factory=dict)

    def attr(self, name: str) -> str | None:
        for k, v in self.attributes:
            if k == name:
                return v
        return None

    def has_attr(self, name: str) -> bool:
        return any(k == name for k, _ in self.attributes)

    @property
    def direction(self) -> str | None:
        for k, _ in self.attributes:
            if k in DIRECTIONS:
                return k
        return None

    @property
    def payload_types(self) -> list[int]:
        return [int(f) for f in self.formats if f.isdigit()]

    @property
    def is_secure(self) -> bool:
        return "SAVP" in self.proto.upper()

    @property
    def crypto(self) -> list[str]:
        return [v for k, v in self.attributes if k == "crypto"]

    @property
    def is_disabled(self) -> bool:
        return self.port == 0

    def codec_name(self, pt: int) -> str:
        if pt in self.rtpmap:
            return self.rtpmap[pt][0].upper()
        return STATIC_PAYLOADS.get(pt, (f"pt{pt}", 0))[0].upper()

    def codec_set(self) -> set[str]:
        return {self.codec_name(pt) for pt in self.payload_types}

    @property
    def telephone_event_pts(self) -> set[int]:
        """Every RFC 4733 payload number offered, not just the first.

        An offer that carries several codec clock rates carries one telephone-event
        per rate — 110 at 48000 for Opus, 106 at 8000 for PCMA — and the answerer
        keeps the one matching the codec it chose. Reading only the first makes
        that ordinary negotiation look like the two ends disagreeing.
        """
        return {pt for pt, (name, _) in self.rtpmap.items()
                if name.lower() == "telephone-event"}

    @property
    def telephone_event_pt(self) -> int | None:
        return min(self.telephone_event_pts, default=None)


@dataclass
class Sdp:
    raw: str = ""
    version: str = ""
    origin: str = ""
    session_name: str = ""
    connection: str | None = None       # session-level c=
    attributes: list[tuple[str, str]] = field(default_factory=list)
    media: list[Media] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def origin_session_id(self) -> str:
        p = self.origin.split()
        return p[1] if len(p) > 1 else ""

    @property
    def origin_identity(self) -> tuple:
        """Every o= field except the version: two UAs may pick the same session id."""
        p = self.origin.split()
        return tuple(p[i] for i in (0, 1, 3, 4, 5) if i < len(p))

    @property
    def origin_version(self) -> str:
        p = self.origin.split()
        return p[2] if len(p) > 2 else ""

    @property
    def session_direction(self) -> str | None:
        for k, _ in self.attributes:
            if k in DIRECTIONS:
                return k
        return None

    def connection_for(self, m: Media) -> str | None:
        return m.connection or self.connection

    def address_for(self, m: Media) -> str:
        """The bare address from the applicable c= line."""
        c = self.connection_for(m)
        if not c:
            return ""
        parts = c.split()
        return parts[2].split("/")[0] if len(parts) >= 3 else ""

    def direction_for(self, m: Media) -> str:
        """Effective direction: media level wins, then session level, default sendrecv."""
        return m.direction or self.session_direction or "sendrecv"

    def audio(self) -> Media | None:
        return next((m for m in self.media if m.kind == "audio"), None)


def parse(body: str) -> Sdp | None:
    if not body or "=" not in body:
        return None
    sdp = Sdp(raw=body)
    current: Media | None = None
    for line in body.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        if len(line) < 2 or line[1] != "=":
            sdp.parse_errors.append(f"malformed SDP line: {line[:60]!r}")
            continue
        kind, value = line[0], line[2:].strip()
        if kind == "v":
            sdp.version = value
        elif kind == "o":
            sdp.origin = value
        elif kind == "s":
            sdp.session_name = value
        elif kind == "c":
            if current is None:
                sdp.connection = value
            else:
                current.connection = value
        elif kind == "m":
            current = _parse_media(value, sdp)
            sdp.media.append(current)
        elif kind == "a":
            name, _, val = value.partition(":")
            name = name.strip().lower()
            target = current.attributes if current is not None else sdp.attributes
            target.append((name, val.strip()))
            if current is not None:
                _apply_media_attr(current, name, val.strip(), sdp)
    return sdp


def _parse_media(value: str, sdp: Sdp) -> Media:
    parts = value.split()
    m = Media()
    if not parts:
        sdp.parse_errors.append("empty m= line")
        return m
    m.kind = parts[0]
    if len(parts) > 1:
        port, _, count = parts[1].partition("/")
        m.port = int(port) if port.isdigit() else 0
        m.port_count = int(count) if count.isdigit() else 1
    if len(parts) > 2:
        m.proto = parts[2]
    m.formats = parts[3:]
    return m


_RTPMAP = re.compile(r"^(\d+)\s+([^/]+)/(\d+)")


def _apply_media_attr(m: Media, name: str, val: str, sdp: Sdp) -> None:
    if name == "rtpmap":
        if rm := _RTPMAP.match(val):
            m.rtpmap[int(rm.group(1))] = (rm.group(2), int(rm.group(3)))
        else:
            sdp.parse_errors.append(f"malformed a=rtpmap:{val[:40]}")
    elif name == "fmtp":
        pt, _, rest = val.partition(" ")
        if pt.isdigit():
            m.fmtp[int(pt)] = rest.strip()
