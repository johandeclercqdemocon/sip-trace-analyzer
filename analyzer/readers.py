"""Get SIP messages (and RTP packets) out of pcap/pcapng files and text logs."""
from __future__ import annotations

import pathlib
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime

from . import message as msgmod


@dataclass
class RtpPacket:
    timestamp: float
    src: str
    dst: str
    ssrc: int
    seq: int
    rtp_ts: int
    payload_type: int
    marker: bool
    payload_len: int
    is_rtcp: bool = False
    rtcp_type: int = 0


@dataclass
class Device:
    """A network element the trace source could name, with the addresses it owns.

    A capture cannot know that ten addresses are one SBC; a correlated export can,
    and says so. Everything that groups a ladder into columns needs this.
    """
    id: int
    name: str
    kind: str = ""              # SBC | TRUNK | GW … as the source labels it
    description: str = ""
    addresses: list[str] = field(default_factory=list)   # addresses and CIDRs


@dataclass
class MediaReport:
    """A media stream as an external probe measured it, rather than as packets.

    Kept apart from RtpStream on purpose. A summary can say a stream lost 3% of its
    packets, but it cannot answer 'which sequence numbers', 'did the SSRC change'
    or 'was the payload type negotiated' — so the per-packet checks must not see
    it and quietly conclude everything is fine.
    """
    frame: int
    at: float
    src: str                    # 'ip:port', IPv6 bracketed
    dst: str
    ends: bool = False          # an END row: the stream's closing summary
    label: str = ""             # 'START RTP', 'END RTP/RTCP' …
    reporter: str = ""          # which probe measured it
    media_type: str = ""        # audio | video
    codecs: list[str] = field(default_factory=list)
    packets: float | None = None
    lost: float | None = None
    discarded: float | None = None
    loss_ratio: float | None = None       # 0..1, as everywhere else here
    jitter_avg_ms: float | None = None
    jitter_max_ms: float | None = None
    mos: float | None = None
    leg: int | None = None
    src_device: str = ""
    dst_device: str = ""
    stats: dict[str, str] = field(default_factory=dict)   # the report verbatim

    @property
    def path(self) -> str:
        return f"{self.src} -> {self.dst}"


@dataclass
class Trace:
    source: str
    kind: str = "text"                  # pcap | text | ocom-html
    messages: list[msgmod.Message] = field(default_factory=list)
    rtp: list[RtpPacket] = field(default_factory=list)
    has_media_layer: bool = False       # False for text logs: RTP checks stay silent
    notes: list[str] = field(default_factory=list)
    nat_map: list = field(default_factory=list)   # (address, address) seen as one host
    # Set by sources that carry a device catalogue; empty for pcaps and text logs.
    devices: list[Device] = field(default_factory=list)
    device_order: list[str] = field(default_factory=list)   # ladder column order
    media_reports: list[MediaReport] = field(default_factory=list)
    display_offset: int = 0             # seconds the source rendered its clock at
    fragments_missing: int = 0          # datagrams whose reassembly failed

    @property
    def has_media_reports(self) -> bool:
        return bool(self.media_reports)

    def device_for(self, endpoint: str) -> str:
        """The device name owning an 'ip:port', or '' when nothing claims it."""
        host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
        for m in self.messages:
            if m.src == endpoint and m.src_device:
                return m.src_device
            if m.dst == endpoint and m.dst_device:
                return m.dst_device
        for d in self.devices:
            if host.strip("[]") in {a.strip("[]") for a in d.addresses}:
                return d.name
        return ""


# ---------------------------------------------------------------- pcap
def _parse_rtp(payload: bytes, ts: float, src: str, dst: str) -> RtpPacket | None:
    if len(payload) < 12 or (payload[0] >> 6) != 2:
        return None
    pt = payload[1] & 0x7F
    # RTCP shares the port range; packet types 200-207 identify it.
    if 200 <= pt + 128 <= 207 and (payload[1] & 0x80):
        return RtpPacket(ts, src, dst, 0, 0, 0, pt, False, len(payload) - 8,
                         is_rtcp=True, rtcp_type=payload[1])
    seq, rtp_ts, ssrc = struct.unpack("!HII", payload[2:12])
    csrc_count = payload[0] & 0x0F
    header_len = 12 + 4 * csrc_count
    if payload[0] & 0x10 and len(payload) >= header_len + 4:      # extension
        ext_words = struct.unpack("!H", payload[header_len + 2:header_len + 4])[0]
        header_len += 4 + 4 * ext_words
    return RtpPacket(ts, src, dst, ssrc, seq, rtp_ts, pt, bool(payload[1] & 0x80),
                     max(0, len(payload) - header_len))


def _is_rtcp(payload: bytes) -> bool:
    return len(payload) >= 8 and (payload[0] >> 6) == 2 and 200 <= payload[1] <= 207


# A real retransmission waits at least T1 (500 ms, RFC 3261 Table 4). Two identical
# datagrams closer together than this are a capture artefact, not the UA retrying.
DUPLICATE_WINDOW = 0.05


def mark_duplicates(trace: Trace) -> int:
    """Flag messages that are the same datagram captured twice.

    Ports mirrored on both sides of a device, a tap plus a host capture, or a
    bonded interface all produce doubled frames. Left unflagged they read as
    retransmissions and fire SIP-2XX-RETRANSMIT and friends on a healthy call.

    A duplicate is the same 5-tuple and identical bytes, plus either the same
    non-zero IPv4 identification field or an arrival within DUPLICATE_WINDOW
    of a message whose time is actually known: a placeholder timestamp says
    nothing about when a message arrived, so an untimed log's two transmissions
    of one request are retransmissions, not one datagram seen twice.
    """
    seen: dict[tuple, list[msgmod.Message]] = {}
    duplicates = 0
    for m in trace.messages:
        key = (m.src, m.dst, m.transport, m.raw)
        for earlier in seen.get(key, []):
            same_id = (m.ip_id is not None and m.ip_id == earlier.ip_id and m.ip_id != 0)
            close = (m.time_known and earlier.time_known
                     and abs(m.timestamp - earlier.timestamp) <= DUPLICATE_WINDOW)
            if same_id or close:
                m.duplicate_of = earlier.frame
                m.duplicate_kind = "frame"
                duplicates += 1
                break
        else:
            seen.setdefault(key, []).append(m)
    return duplicates


def mark_capture_points(trace: Trace) -> list[tuple[str, str]]:
    """Flag one datagram recorded at two points on its path.

    A capture taken either side of a NAT or SIP ALG contains every packet twice
    with *different* addresses, and often a rewritten body, so byte comparison
    misses it. The IPv4 identification field is set once by the sender and is not
    rewritten in transit, so the same id at the same instant carrying the same
    Call-ID and CSeq is one packet seen twice, not a retransmission.

    Returns the address pairs observed, which is the NAT's translation map.
    """
    groups: dict[tuple, list[msgmod.Message]] = {}
    for m in trace.messages:
        if m.duplicate_of is not None:
            continue
        # Branch plus CSeq identifies one transaction attempt; a forking proxy
        # allocates a fresh branch per fork, so this cannot merge real forks.
        groups.setdefault((m.call_id, m.cseq, m.status, m.method, m.branch), []).append(m)

    mapping: set[tuple[str, str]] = set()
    for members in groups.values():
        if len(members) < 2:
            continue
        members.sort(key=lambda m: (m.timestamp, m.frame))
        first = members[0]
        for other in members[1:]:
            translated = (first.src != other.src) or (first.dst != other.dst)
            same_datagram = (first.ip_id is not None and first.ip_id == other.ip_id
                             and first.ip_id != 0)
            # A retransmission keeps both addresses and gets a fresh IP id, so it
            # matches neither test. Unknown timestamps compare as simultaneous.
            simultaneous = (abs(other.timestamp - first.timestamp) <= DUPLICATE_WINDOW
                            or not (first.time_known or other.time_known))
            if not (translated or same_datagram) or not simultaneous:
                continue
            other.duplicate_of = first.frame
            other.duplicate_kind = "capture-point"
            for a, b in ((first.src, other.src), (first.dst, other.dst)):
                host_a, host_b = a.rsplit(":", 1)[0], b.rsplit(":", 1)[0]
                if host_a != host_b:
                    mapping.add(tuple(sorted((host_a, host_b))))
    return sorted(mapping)


def _link_type(pkt) -> str:
    """Name the link layer so a VLAN or 'tcpdump -i any' capture is visible.

    getlayer(IP) reaches the network layer through any encapsulation, but the
    encapsulation itself is worth reporting: the same call captured once on a
    tagged trunk and once cooked looks like two different traces otherwise.
    """
    from scapy.all import Dot1Q, Ether  # noqa: N811
    try:
        from scapy.layers.l2 import CookedLinux
    except ImportError:                                          # pragma: no cover
        CookedLinux = None
    if pkt.haslayer(Dot1Q):
        vlans = [str(v.vlan) for v in pkt.getlayer(Dot1Q).iterpayloads()
                 if isinstance(v, Dot1Q)]
        first = pkt.getlayer(Dot1Q).vlan
        return f"vlan {first}" + (f" (qinq {'/'.join(vlans)})" if len(vlans) > 1 else "")
    if CookedLinux is not None and pkt.haslayer(CookedLinux):
        return "cooked"
    if pkt.name in ("cooked linux v2", "CookedLinuxV2"):
        return "cooked"
    if pkt.haslayer(Ether):
        return "ethernet"
    return pkt.name.lower()


def _link_kind(link_type: str) -> str:
    """The kind of link layer, which is what tells two capture points apart.

    One trunk port carries many VLANs, so 'vlan 100' and 'vlan 200' (or any QinQ
    stack) are one kind: an SBC with its access leg on one VLAN and its core leg on
    another is still a single capture point.
    """
    return "vlan" if link_type.startswith("vlan ") else link_type


@dataclass
class _Segment:
    """One TCP segment's payload, kept until the whole capture has been read."""
    seq: int
    data: bytes
    frame: int
    ts: float
    l3: dict


# The SIP start line, in two strengths: the hint finds candidates anywhere, the
# full form must match a whole line, which is what a start line is.
_TCP_START_HINT = re.compile(rb"(?:[A-Za-z]+ \S+ SIP/2\.0|SIP/2\.0 \d{3})")
_TCP_START_LINE = re.compile(
    rb"(?:[A-Za-z]+ \S+ SIP/2\.0|SIP/2\.0 \d{3}(?:[ \t].*)?)\r?$")
_TCP_HEADER_END = re.compile(rb"\r\n\r\n|\n\r\n|\n\n")
_TCP_CONTENT_LENGTH = re.compile(
    rb"(?m)^(?:Content-Length|l)[ \t]*:[ \t]*(\d+)[ \t]*\r?$")


def _next_tcp_start(data: bytes, pos: int) -> int | None:
    """The next SIP start line at a line boundary at or after pos, or None."""
    for m in _TCP_START_HINT.finditer(data, pos):
        at = m.start()
        if at and data[at - 1] != 0x0A:
            continue                                # not where a line starts
        nl = data.find(b"\n", at)
        line = data[at:nl if nl != -1 else len(data)].rstrip(b"\r")
        if _TCP_START_LINE.fullmatch(line):
            return at
    return None


def _frame_tcp(data: bytes):
    """Complete SIP messages in a rebuilt TCP stream, as (start, end) offsets.

    Framing is octet-exact: Content-Length is the size of the message-body in
    decimal number of octets and MUST be used with stream oriented transports
    (RFC 3261 sections 20.14 and 18.3), so the line ends are not normalised
    before the body is measured. Bytes before the first start line are skipped:
    a capture often begins in the middle of a message on a long-lived
    connection. An incomplete tail is left unframed, as data that never came.
    """
    pos = 0
    while True:
        start = _next_tcp_start(data, pos)
        if start is None:
            return
        sep = _TCP_HEADER_END.search(data, start)
        if sep is None:
            return                                  # the headers never completed
        m = _TCP_CONTENT_LENGTH.search(data, start, sep.start())
        body_len = int(m.group(1)) if m else 0
        end = sep.end() + body_len
        if end > len(data):
            return                                  # the body never completed
        yield start, end
        pos = end


def _reassemble_tcp(segments: list[_Segment]) -> tuple[list[dict], list[tuple[int, int]]]:
    """Rebuild a direction's byte stream in sequence-number order.

    Segments captured out of order are put back in sequence order; a segment
    whose bytes were already captured is used once (overlaps are trimmed, so a
    re-segmented retransmission fills only what was missing); where sequence
    numbers show a gap the bytes either side are not joined. Returns the
    contiguous runs — each with its bytes and, per byte range, the segment that
    contributed it — and the missing ranges between them.
    """
    parts: list[list] = []       # [start, end, bytes, frame, ts, l3], disjoint
    for seg in sorted(segments, key=lambda s: (s.seq, s.ts)):
        lo, hi = seg.seq, seg.seq + len(seg.data)
        fresh: list[tuple[int, int]] = []
        pos, idx = lo, 0
        while pos < hi:
            while idx < len(parts) and parts[idx][1] <= pos:
                idx += 1
            if idx < len(parts) and parts[idx][0] <= pos:
                pos = parts[idx][1]                     # already captured
                idx += 1
                continue
            end = min(hi, parts[idx][0] if idx < len(parts) else hi)
            fresh.append((pos, end))
            pos = end
        for start, end in fresh:
            parts.append([start, end, seg.data[start - lo:end - lo],
                          seg.frame, seg.ts, seg.l3])
        parts.sort(key=lambda p: p[0])

    runs: list[dict] = []
    gaps: list[tuple[int, int]] = []
    cur: dict | None = None
    for start, end, data, frame, ts, l3 in parts:
        if cur is not None and start == cur["end"]:
            cur["data"] += data
            cur["contribs"].append((start - cur["start"], end - cur["start"],
                                    frame, ts, l3))
            cur["end"] = end
        else:
            if cur is not None:
                gaps.append((cur["end"], start))
            cur = {"start": start, "end": end, "data": bytearray(data),
                   "contribs": [(0, end - start, frame, ts, l3)]}
            runs.append(cur)
    return runs, gaps


def _completed_by(run: dict, start: int, end: int) -> tuple[float, int, dict]:
    """The segment that completed a message: the latest-captured one holding part of it."""
    best: tuple[int, float, dict] | None = None
    for s, e, frame, ts, l3 in run["contribs"]:
        if s < end and e > start and (best is None or (ts, frame) > (best[1], best[0])):
            best = (frame, ts, l3)
    return (best[1], best[0], best[2]) if best else (0.0, 0, {})


def _read_tcp_streams(trace: Trace,
                      directions: dict[tuple[str, str], list[_Segment]]) -> None:
    """Rebuild each TCP direction's stream and read the SIP messages out of it.

    A direction is SIP when its rebuilt stream holds a SIP start line anywhere;
    anything else on a TCP port (management traffic, a trunk's keepalive) is
    left alone. One note per SIP direction with a gap in its sequence numbers.
    """
    for (src, dst), segments in directions.items():
        runs, gaps = _reassemble_tcp(segments)
        if not any(_next_tcp_start(bytes(run["data"]), 0) is not None for run in runs):
            continue
        if gaps:
            missing = sum(hi - lo for lo, hi in gaps)
            trace.notes.append(
                f"TCP data missing from {src} to {dst}: {len(gaps)} gap(s) in the "
                f"sequence numbers, {missing} byte(s) never captured; messages after "
                f"the first gap cannot be reassembled")
        for run in runs:
            data = bytes(run["data"])
            for start, end in _frame_tcp(data):
                ts, frame, l3 = _completed_by(run, start, end)
                m = msgmod.parse(data[start:end].decode("utf-8", "replace"),
                                 timestamp=ts, src=src, dst=dst, transport="TCP",
                                 frame=frame, **l3)
                if m:
                    trace.messages.append(m)


def _fragment_parts(ip) -> dict | None:
    """Describe one IP fragment, or None when the frame carries a whole datagram.

    IPv4 shows its fragmentation in the header itself (RFC 791): the More
    Fragments flag, the fragment offset and the identification field. IPv6 puts
    the same three in the Fragment extension header (RFC 8200 section 4.5). Only
    the bytes past the (fragment) header are returned, taken from the wire bytes
    the packet was dissected from: a fragment on its own has no UDP header
    except the first one, and re-serializing a dissected packet would rewrite
    its checksums.

    Only UDP datagrams are reassembled here; fragments of other protocols keep
    the inline read they always had.
    """
    from scapy.all import IPv6ExtHdrFragment  # noqa: N811
    if ip.version == 4:
        more = "MF" in ip.flags
        offset = ip.frag * 8
        if offset == 0 and not more:
            return None
        if ip.proto != 17:
            return None
        return {"key": ("v4", ip.src, ip.dst, ip.id), "offset": offset, "mf": more,
                "payload": ip.original[ip.ihl * 4: ip.len]}
    frag = ip.getlayer(IPv6ExtHdrFragment)
    if frag is None or frag.nh != 17:
        return None
    cut = len(ip.original) - len(frag.original)     # where the fragment header sits
    return {"key": ("v6", ip.src, ip.dst, frag.id), "offset": frag.offset * 8,
            "mf": bool(frag.m), "payload": frag.original[8: 40 + ip.plen - cut]}


def _reassembled(parts: list[dict]) -> bytes | None:
    """The datagram's bytes when its fragments form it completely, else None.

    Complete means: the first fragment (offset 0) is there, the last one seen
    has More Fragments clear, and the offsets leave no hole. Fragments may have
    been captured in any order.
    """
    by_offset: dict[int, dict] = {}
    for p in parts:
        by_offset[p["offset"]] = p
    if 0 not in by_offset or by_offset[max(by_offset)]["mf"]:
        return None                        # the last fragment has not arrived yet
    data = bytearray()
    expect = 0
    for off in sorted(by_offset):
        if off != expect:                           # a hole: a fragment is missing
            return None
        data += by_offset[off]["payload"]
        expect = off + len(by_offset[off]["payload"])
    return bytes(data)


def read_pcap(path: pathlib.Path) -> Trace:
    from scapy.all import IP, TCP, UDP, IPv6, PcapReader  # noqa: N811

    trace = Trace(source=str(path), kind="pcap", has_media_layer=True)
    tcp_segments: dict[tuple[str, str], list[_Segment]] = {}
    frame = 0
    link_types: set[str] = set()
    # Fragments are kept per datagram until the last one completes it; a
    # fragment alone is not a packet either reader can use.
    datagrams: dict[tuple, list[dict]] = {}

    def read_udp(payload: bytes, ts: float, src: str, dst: str, f: int, l3: dict) -> None:
        """One whole UDP datagram's payload: SIP, or RTP/RTCP."""
        looks_sip = payload[:4] in (b"SIP/", b"INVI", b"ACK ", b"BYE ", b"CANC",
                                    b"REGI", b"OPTI", b"PRAC", b"UPDA", b"SUBS",
                                    b"NOTI", b"REFE", b"PUBL", b"MESS", b"INFO")
        if looks_sip:
            m = msgmod.parse(payload.decode("utf-8", "replace"), timestamp=ts,
                             src=src, dst=dst, transport="UDP", frame=f, **l3)
            if m:
                trace.messages.append(m)
        elif _is_rtcp(payload):
            trace.rtp.append(RtpPacket(ts, src, dst, 0, 0, 0, payload[1], False,
                                       len(payload), is_rtcp=True, rtcp_type=payload[1]))
        elif (rp := _parse_rtp(payload, ts, src, dst)) is not None:
            trace.rtp.append(rp)

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            frame += 1
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                continue
            ts = float(pkt.time)

            frag = _fragment_parts(ip)
            if frag is not None:
                link = _link_type(pkt)
                link_types.add(link)
                frag |= {"frame": frame, "ts": ts, "src": ip.src, "dst": ip.dst,
                         "link_type": link, "time_known": True,
                         "ip_id": ip.id if hasattr(ip, "id") else None,   # not the flow label (RFC 6437)
                         "ttl": getattr(ip, "ttl", None) if hasattr(ip, "ttl")
                         else getattr(ip, "hlim", None)}
                group = datagrams.setdefault(frag["key"], [])
                group.append(frag)
                data = _reassembled(group)
                if data is not None:
                    datagrams.pop(frag["key"])
                    sport, dport, ulen, _ = struct.unpack("!HHHH", data[:8])
                    if 8 <= ulen <= len(data):
                        data = data[:ulen]
                    read_udp(data[8:], ts, f"{ip.src}:{sport}", f"{ip.dst}:{dport}",
                             frame, {"ip_id": frag["ip_id"], "ttl": frag["ttl"],
                                     "link_type": link, "time_known": True})
                continue

            udp, tcp = pkt.getlayer(UDP), pkt.getlayer(TCP)
            layer = udp or tcp
            if layer is None or not bytes(layer.payload):
                continue
            payload = bytes(layer.payload)
            src = f"{ip.src}:{layer.sport}"
            dst = f"{ip.dst}:{layer.dport}"
            # IPv4 carries id/ttl. IPv6 has no identification field, and its flow label
            # names a whole flow (RFC 6437 section 2), so every retransmission carries
            # the same one: it is not a packet identity. IPv6 duplicates are found by
            # identical bytes within the window alone (RFC 6864 section 4.1).
            link = _link_type(pkt)
            link_types.add(link)
            l3 = {"ip_id": ip.id if hasattr(ip, "id") else None,
                  "ttl": getattr(ip, "ttl", None) if hasattr(ip, "ttl")
                  else getattr(ip, "hlim", None),
                  "link_type": link,
                  "time_known": True}

            if udp is not None:
                looks_sip = payload[:4] in (b"SIP/", b"INVI", b"ACK ", b"BYE ", b"CANC",
                                            b"REGI", b"OPTI", b"PRAC", b"UPDA", b"SUBS",
                                            b"NOTI", b"REFE", b"PUBL", b"MESS", b"INFO")
                if looks_sip:
                    m = msgmod.parse(payload.decode("utf-8", "replace"),
                                     timestamp=ts, src=src, dst=dst,
                                     transport="UDP", frame=frame, **l3)
                    if m:
                        trace.messages.append(m)
                elif _is_rtcp(payload):
                    trace.rtp.append(RtpPacket(ts, src, dst, 0, 0, 0, payload[1], False,
                                               len(payload), is_rtcp=True,
                                               rtcp_type=payload[1]))
                elif (rp := _parse_rtp(payload, ts, src, dst)) is not None:
                    trace.rtp.append(rp)
            elif tcp is not None:
                # A SIP message larger than one segment arrives in several; keep
                # every segment with its sequence number and rebuild the stream
                # once the whole capture has been read.
                tcp_segments.setdefault((src, dst), []).append(
                    _Segment(int(tcp.seq), payload, frame, ts, l3))

    # Whatever is left never completed: a fragment is missing from the capture.
    # That is packet loss, not a signalling fault, so say so per datagram and
    # keep what the first fragment did carry.
    for parts in datagrams.values():
        trace.fragments_missing += 1
        first = min(parts, key=lambda p: p["offset"])
        src, dst = first["src"], first["dst"]
        trace.notes.append(
            f"message incomplete: IP fragment missing: the datagram from {src} to {dst} "
            f"was captured as {len(parts)} fragment(s) that do not reassemble; the rest "
            f"was lost between the sender and this capture point")
        if first["offset"] == 0 and len(first["payload"]) >= 8:
            sport, dport = struct.unpack("!HH", first["payload"][:4])
            read_udp(first["payload"][8:], first["ts"], f"{src}:{sport}",
                     f"{dst}:{dport}", first["frame"],
                     {"ip_id": first["ip_id"], "ttl": first["ttl"],
                      "link_type": first["link_type"], "time_known": True})

    _read_tcp_streams(trace, tcp_segments)
    trace.messages.sort(key=lambda m: (m.timestamp, m.frame))
    dupes = mark_duplicates(trace)
    if dupes:
        trace.notes.append(
            f"{dupes} duplicated frame(s) detected at layer 3 and excluded from "
            f"transaction analysis")
    trace.nat_map = mark_capture_points(trace)
    if trace.nat_map:
        trace.notes.append(
            f"the same packets appear at {len(trace.nat_map) + 1} points on their path; "
            f"the second view is excluded from transaction analysis")
    if len({_link_kind(link) for link in link_types}) > 1:
        trace.notes.append(
            "mixed link layers in one capture (" + ", ".join(sorted(link_types)) +
            "): this usually means two capture points were merged")
    return trace


# ---------------------------------------------------------------- text logs
# sngrep / ngrep style:  U 2024/01/01 10:00:00.123456 1.2.3.4:5060 -> 5.6.7.8:5060
NGREP_HDR = re.compile(
    r"^([UT])\s+(?:(\d{4})/(\d{2})/(\d{2})\s+)?(\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(\S+?):(\d+)\s*(?:->|-)\s*(\S+?):(\d+)")
# Generic 'ip:port -> ip:port' anywhere on a line preceding a message
ENDPOINTS = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:]+\]):(\d+)\s*(?:->|=>|to)\s*"
                       r"(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:]+\]):(\d+)")
# tcpdump prints the port as a final dotted component:
#     10.1.0.150.5060 > 10.0.0.21.50210: [udp sum ok] SIP, length: 545
TCPDUMP_ENDPOINTS = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})\.(\d+):")
# tcpdump -v IP line:  IP (tos 0x10, ttl 63, id 885, offset 0, flags [DF], …)
TCPDUMP_IP = re.compile(r"\bttl (\d+), id (\d+)")
TCPDUMP_VLAN = re.compile(r"\bvlan (\d+)", re.I)
TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2}[T ])?(\d{2}:\d{2}:\d{2})[.,](\d{1,6})")
# The SIP start line, allowing the leading indentation that tcpdump -v adds.
START_LINE = re.compile(r"^(\s*)(?:[A-Za-z]+ \S+ SIP/2\.0|SIP/2\.0 \d{3}(?:\s.*)?)\s*$")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _clock(hms: str, frac: str, date: str | None = None) -> float:
    h, m, s = (int(x) for x in hms.split(":"))
    base = h * 3600 + m * 60 + s + int(frac.ljust(6, "0")[:6]) / 1e6
    if date:
        try:
            d = datetime.strptime(date.strip("T "), "%Y-%m-%d")
            return d.timestamp() + base
        except ValueError:
            pass
    return base


def read_text(path: pathlib.Path) -> Trace:
    """Read a text SIP log.

    Handles ngrep/sngrep dumps, Asterisk and Kamailio debug logs, and anything else
    that puts whole SIP messages in the file - the start line is the anchor, and
    timestamps and endpoints are taken from whatever preamble precedes it.
    """
    trace = Trace(source=str(path), kind="text")
    lines = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n")

    blocks: list[dict] = []
    i = 0
    # Preamble state, carried forward until the next SIP message consumes it.
    pending: dict = {"ts": None, "src": "", "dst": "", "ip_id": None, "ttl": None,
                     "link": "", "dated": False}
    any_ts = False

    while i < len(lines):
        line = lines[i]

        if m := NGREP_HDR.match(line):
            date = f"{m.group(2)}-{m.group(3)}-{m.group(4)}" if m.group(2) else None
            hms, frac = m.group(5).split(".")
            any_ts = True
            pending |= {"ts": _clock(hms, frac, date),
                        "dated": date is not None,
                        "src": f"{m.group(6)}:{m.group(7)}",
                        "dst": f"{m.group(8)}:{m.group(9)}"}
            i += 1
            continue

        start = START_LINE.match(line)
        if not start:
            # Preamble. Collect whatever this line tells us about the next message.
            if tm := TIMESTAMP.search(line):
                pending["ts"] = _clock(tm.group(2), tm.group(3), tm.group(1))
                pending["dated"] = bool(tm.group(1))
                any_ts = True
            if ipm := TCPDUMP_IP.search(line):
                pending |= {"ttl": int(ipm.group(1)), "ip_id": int(ipm.group(2))}
            if TCPDUMP_VLAN.search(line):
                pending["link"] = "vlan"
            if (em := TCPDUMP_ENDPOINTS.match(line)) or (em := ENDPOINTS.search(line)):
                pending |= {"src": f"{em.group(1)}:{em.group(2)}",
                            "dst": f"{em.group(3)}:{em.group(4)}"}
            i += 1
            continue

        # A SIP message starts here. tcpdump -v indents the whole block; strip
        # exactly that indentation so the parser sees a normal message.
        indent = len(start.group(1))
        block = [line[indent:]]
        i += 1
        while i < len(lines) and lines[i].strip() and _indent(lines[i]) >= indent:
            block.append(lines[i][indent:])
            i += 1

        head = "\n".join(block)
        cl = re.search(r"^(?:Content-Length|l)\s*:\s*(\d+)\s*$", head, re.I | re.M)
        body_len = int(cl.group(1)) if cl else 0
        if body_len and i < len(lines):
            i += 1                                  # the blank separator line
            body: list[str] = []
            while (i < len(lines) and sum(len(b) + 1 for b in body) < body_len
                   and _indent(lines[i]) >= indent):
                body.append(lines[i][indent:])
                i += 1
            block += [""] + body

        blocks.append({**pending, "lines": block})
        # Endpoints usually repeat per message; time, its date and L3 identity do not.
        pending = {**pending, "ts": None, "ip_id": None, "ttl": None, "dated": False}

    if not any_ts:
        trace.notes.append("no timestamps found in log: timing-based checks are disabled")

    # A log whose timestamps carry no date has only the file order as its clock, so
    # a step back of more than half a day is the log crossing midnight: everything
    # after it belongs to the next day. A small step back is a log written slightly
    # out of order; those messages keep their time of day, and the sort below
    # restores the true order. Dated timestamps carry their own day and stay put.
    day = 0
    prev_tod: float | None = None
    for b in blocks:
        if b["ts"] is None or b["dated"]:
            continue
        tod = b["ts"] % 86400.0
        if prev_tod is not None and prev_tod - tod > 43200.0:
            day += 1
        prev_tod = tod
        b["ts"] += day * 86400.0

    for n, b in enumerate(blocks, start=1):
        m = msgmod.parse("\n".join(b["lines"]), timestamp=b["ts"] or 0.0,
                         time_known=b["ts"] is not None, src=b["src"], dst=b["dst"],
                         frame=n, ip_id=b["ip_id"], ttl=b["ttl"], link_type=b["link"])
        if m:
            if not m.src and (v := m.top_via):
                # Fall back to the Via for direction when the log gave no endpoints.
                host = v.received or v.host
                port = v.params.get("rport") or v.port or 5060
                m.src = f"{host}:{port}"
            trace.messages.append(m)

    if any(m.time_known for m in trace.messages):
        trace.messages.sort(key=lambda m: (m.timestamp, m.frame))
    # Text logs have no layer 3, but a box that logs both the send and the receive
    # of the same message produces the same doubling, so the time rule still helps.
    dupes = mark_duplicates(trace)
    if dupes:
        trace.notes.append(f"{dupes} duplicated message(s) in the log, excluded from "
                           f"transaction analysis")
    trace.nat_map = mark_capture_points(trace)
    if trace.nat_map:
        trace.notes.append(
            "the log contains the same packets seen at two points on their path; "
            "the second view is excluded from transaction analysis")
    return trace


PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a",
              b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")


def read(path: str | pathlib.Path) -> Trace:
    p = pathlib.Path(path)
    if not p.exists():
        raise FileNotFoundError(p)
    with p.open("rb") as fh:
        head = fh.read(4096)
    if head[:4] in PCAP_MAGIC:
        return read_pcap(p)
    # An HTML export is one long line of jQuery with the trace buried near the end,
    # so the sniff can only say 'this is HTML'; the ocom reader decides whether it
    # is an export it understands, and says so plainly when it is not.
    if b"<html" in head[:1024].lower() or b"<!doctype html" in head[:1024].lower():
        from .ocom import read_ocom_html
        return read_ocom_html(p)
    return read_text(p)
