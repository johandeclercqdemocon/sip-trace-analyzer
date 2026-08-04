"""SIP message parsing.

Deliberately tolerant: a trace is interesting precisely when it contains malformed
messages, so parsing records problems rather than raising.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

# RFC 3261 section 7.3.3 compact forms, plus the ones added by later RFCs.
COMPACT = {
    "a": "Accept-Contact", "b": "Referred-By", "c": "Content-Type", "d": "Request-Disposition",
    "e": "Content-Encoding", "f": "From", "i": "Call-ID", "j": "Reject-Contact",
    "k": "Supported", "l": "Content-Length", "m": "Contact", "n": "Identity-Info",
    "o": "Event", "r": "Refer-To", "s": "Subject", "t": "To", "u": "Allow-Events",
    "v": "Via", "x": "Session-Expires", "y": "Identity",
}

REQUEST_LINE = re.compile(r"^([A-Za-z]+)\s+(\S+)\s+SIP/(\d+\.\d+)\s*$")
STATUS_LINE = re.compile(r"^SIP/(\d+\.\d+)\s+(\d{3})\s*(.*)$")
# Headers that may legally be comma-separated into multiple values.
LIST_HEADERS = {
    "via", "route", "record-route", "contact", "path", "allow", "supported", "require",
    "proxy-require", "unsupported", "accept", "accept-encoding", "accept-language",
    "allow-events", "history-info", "diversion", "reason", "p-asserted-identity",
    "service-route", "call-info", "alert-info", "error-info", "warning",
}
# Contact may be a bare '*' in REGISTER; never split a URI on a comma inside <>.
_SPLIT_COMMA = re.compile(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)(?![^<]*>)")

TAG = re.compile(r";tag=([^;>\s]+)", re.I)
BRANCH = re.compile(r";branch=([^;>\s]+)", re.I)
URI_IN_ANGLES = re.compile(r"<([^>]+)>")
HOSTPORT = re.compile(r"^(?:[^@]*@)?(\[[0-9A-Fa-f:]+\]|[^:;?>]+)(?::(\d+))?")


def canonical(name: str) -> str:
    """Lower-cased canonical header name, expanding compact forms."""
    low = name.strip().lower()
    return COMPACT.get(low, name.strip()).lower() if len(low) == 1 else low


@dataclass
class Via:
    raw: str
    protocol: str = ""          # e.g. SIP/2.0/UDP
    host: str = ""
    port: int | None = None
    branch: str | None = None
    received: str | None = None
    rport: str | None = None    # '' when present but valueless
    params: dict[str, str] = field(default_factory=dict)

    @property
    def transport(self) -> str:
        return self.protocol.rsplit("/", 1)[-1].upper() if "/" in self.protocol else ""

    @property
    def is_rfc3261(self) -> bool:
        return bool(self.branch and self.branch.startswith("z9hG4bK"))


def parse_via(raw: str) -> Via:
    v = Via(raw=raw.strip())
    head, *rest = v.raw.split(";")
    parts = head.strip().split(None, 1)
    v.protocol = parts[0] if parts else ""
    if len(parts) > 1:
        m = HOSTPORT.match(parts[1].strip())
        if m:
            v.host = m.group(1)
            v.port = int(m.group(2)) if m.group(2) else None
    for p in rest:
        if "=" in p:
            k, _, val = p.partition("=")
            v.params[k.strip().lower()] = val.strip()
        elif p.strip():
            v.params[p.strip().lower()] = ""
    v.branch = v.params.get("branch")
    v.received = v.params.get("received")
    v.rport = v.params.get("rport")
    return v


@dataclass
class NameAddr:
    raw: str
    uri: str = ""
    tag: str | None = None
    params: dict[str, str] = field(default_factory=dict)

    @property
    def user(self) -> str:
        m = re.search(r"(?:sips?|tel):([^@;>\s]+)", self.uri)
        return m.group(1) if m else ""

    @property
    def host(self) -> str:
        m = re.search(r"(?:sips?):[^@>]*@?(\[[0-9A-Fa-f:]+\]|[^:;>\s]+)", self.uri)
        return m.group(1) if m else ""

    @property
    def port(self) -> int | None:
        m = re.search(r"(?:sips?):[^@>]*@?(?:\[[0-9A-Fa-f:]+\]|[^:;>\s]+):(\d+)", self.uri)
        return int(m.group(1)) if m else None


def parse_nameaddr(raw: str) -> NameAddr:
    na = NameAddr(raw=raw.strip())
    m = URI_IN_ANGLES.search(na.raw)
    if m:
        na.uri = m.group(1)
        params_part = na.raw[m.end():]
    else:
        # No angle brackets: parameters after the first ';' belong to the header.
        head, _, params_part = na.raw.partition(";")
        na.uri = head.strip()
        params_part = ";" + params_part if params_part else ""
    for p in params_part.split(";")[1:]:
        if not p.strip():
            continue
        k, _, val = p.partition("=")
        na.params[k.strip().lower()] = val.strip()
    na.tag = na.params.get("tag")
    return na


@dataclass
class Message:
    """One SIP message, with just enough structure for correlation and checks."""
    raw: str
    timestamp: float = 0.0
    time_known: bool = False    # False when the source gave us no timestamp
    src: str = ""               # 'ip:port'
    dst: str = ""
    transport: str = "UDP"
    frame: int = 0
    link_type: str = ""         # ethernet | vlan | cooked | raw-ip …

    # Layer 3, used to tell a capture artefact from a real retransmission.
    ip_id: int | None = None    # IPv4 identification (IPv6: flow label)
    ttl: int | None = None      # IPv4 TTL / IPv6 hop limit
    duplicate_of: int | None = None   # frame number this one duplicates
    duplicate_kind: str = ""          # 'frame' (byte-identical) | 'capture-point'

    is_request: bool = False
    method: str = ""            # request method, or the CSeq method for responses
    request_uri: str = ""
    status: int | None = None
    reason: str = ""
    version: str = "2.0"

    headers: dict[str, list[str]] = field(default_factory=dict)
    body: str = ""
    parse_errors: list[str] = field(default_factory=list)

    # ---- header access ----------------------------------------------------
    def get(self, name: str, default: str | None = None) -> str | None:
        vals = self.headers.get(canonical(name))
        return vals[0] if vals else default

    def all(self, name: str) -> list[str]:
        return self.headers.get(canonical(name), [])

    def has(self, name: str) -> bool:
        return canonical(name) in self.headers

    # ---- derived identity -------------------------------------------------
    @property
    def call_id(self) -> str:
        return (self.get("call-id") or "").strip()

    @property
    def cseq(self) -> tuple[int | None, str]:
        raw = (self.get("cseq") or "").split()
        num = int(raw[0]) if raw and raw[0].isdigit() else None
        return num, (raw[1].upper() if len(raw) > 1 else "")

    @property
    def cseq_number(self) -> int | None:
        return self.cseq[0]

    @property
    def from_(self) -> NameAddr:
        return parse_nameaddr(self.get("from") or "")

    @property
    def to(self) -> NameAddr:
        return parse_nameaddr(self.get("to") or "")

    @property
    def vias(self) -> list[Via]:
        return [parse_via(v) for v in self.all("via")]

    @property
    def top_via(self) -> Via | None:
        vias = self.all("via")
        return parse_via(vias[0]) if vias else None

    @property
    def branch(self) -> str | None:
        v = self.top_via
        return v.branch if v else None

    @property
    def contacts(self) -> list[NameAddr]:
        return [parse_nameaddr(c) for c in self.all("contact") if c.strip() != "*"]

    @property
    def content_type(self) -> str:
        return (self.get("content-type") or "").split(";")[0].strip().lower()

    @property
    def is_final(self) -> bool:
        return self.status is not None and self.status >= 200

    @property
    def is_provisional(self) -> bool:
        return self.status is not None and 100 <= self.status < 200

    @property
    def size(self) -> int:
        return len(self.raw.encode("utf-8", "replace"))

    @property
    def is_duplicate(self) -> bool:
        return self.duplicate_of is not None

    def header_lines(self) -> list[tuple[str, str]]:
        """Headers as they appear on the wire, in order, folding undone.

        Reads the raw text rather than the parsed dict so the ladder shows what
        was actually sent - original casing, compact forms, duplicate headers.
        """
        head, _, _ = self.raw.replace("\r\n", "\n").partition("\n\n")
        out: list[tuple[str, str]] = []
        for line in head.split("\n")[1:]:
            if not line.strip():
                continue
            if line[0] in " \t" and out:
                name, value = out[-1]
                out[-1] = (name, value + " " + line.strip())
                continue
            name, sep, value = line.partition(":")
            out.append((name.strip(), value.strip()) if sep else ("", line.strip()))
        return out

    @property
    def body_text(self) -> str:
        _, _, body = self.raw.replace("\r\n", "\n").partition("\n\n")
        return body

    def summary(self) -> str:
        if self.is_request:
            return f"{self.method} {self.request_uri}"
        return f"{self.status} {self.reason}"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Message {self.timestamp:.3f} {self.src}->{self.dst} {self.summary()}>"


def parse(raw: str, **meta) -> Message | None:
    """Parse one SIP message. Returns None if the first line is not SIP at all."""
    raw = raw.replace("\r\n", "\n").strip("\n")
    if not raw.strip():
        return None
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    msg = Message(raw=raw, body=body, **meta)

    first = lines[0].strip()
    if m := STATUS_LINE.match(first):
        msg.version, msg.status, msg.reason = m.group(1), int(m.group(2)), m.group(3).strip()
    elif m := REQUEST_LINE.match(first):
        msg.is_request = True
        msg.method, msg.request_uri, msg.version = m.group(1).upper(), m.group(2), m.group(3)
    else:
        return None

    # Unfold continuation lines (a leading space or tab continues the previous header).
    unfolded: list[str] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if line[0] in " \t" and unfolded:
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line)

    for line in unfolded:
        name, sep, value = line.partition(":")
        if not sep:
            msg.parse_errors.append(f"header line without colon: {line[:60]!r}")
            continue
        key = canonical(name)
        value = value.strip()
        values = ([v.strip() for v in _SPLIT_COMMA.split(value) if v.strip()]
                  if key in LIST_HEADERS else [value])
        msg.headers.setdefault(key, []).extend(values)

    if not msg.is_request:
        msg.method = msg.cseq[1]

    # Mandatory across every method and response (RFC 3261 Tables 2 and 3).
    for required in ("via", "from", "to", "call-id", "cseq"):
        if required not in msg.headers:
            msg.parse_errors.append(f"missing mandatory header: {required}")
    if msg.is_request and "max-forwards" not in msg.headers:
        msg.parse_errors.append("missing mandatory header: max-forwards")

    return msg


def split_stream(data: str) -> Iterator[str]:
    """Frame consecutive SIP messages out of a byte stream, using Content-Length.

    Used for TCP/TLS reassembly and for text logs that concatenate messages.
    """
    text = data.replace("\r\n", "\n")
    pos = 0
    while pos < len(text):
        start = _next_start(text, pos)
        if start is None:
            return
        sep = text.find("\n\n", start)
        if sep == -1:
            return
        head = text[start:sep]
        m = re.search(r"^(?:Content-Length|l)\s*:\s*(\d+)\s*$", head, re.I | re.M)
        body_len = int(m.group(1)) if m else 0
        end = sep + 2 + body_len
        if end > len(text):
            return  # incomplete tail: wait for more data
        yield text[start:end]
        pos = end


def _next_start(text: str, pos: int) -> int | None:
    for m in re.finditer(r"^(?:[A-Za-z]+ \S+ SIP/2\.0|SIP/2\.0 \d{3})", text[pos:], re.M):
        return pos + m.start()
    return None
