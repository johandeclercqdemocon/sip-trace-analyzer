"""Build synthetic traces with deliberately seeded faults.

Each scenario documents the faults it plants; the tests then assert the analyser
finds exactly those and nothing spurious. Most are pcaps; the OCOM helpers at the
bottom write the HTML export format instead.
"""
from __future__ import annotations

import json
import pathlib
import struct

from scapy.all import IP, UDP, Ether, Raw, wrpcap

CALLER = "203.0.113.10"
CALLEE = "198.51.100.20"
PROXY = "192.0.2.1"


def _ether():
    """Fixed MACs: letting scapy resolve them triggers a real ARP lookup."""
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


class Builder:
    def __init__(self) -> None:
        self.packets: list = []

    # ---- SIP ---------------------------------------------------------------
    def sip(self, t: float, src: str, dst: str, raw: str,
            sport: int = 5060, dport: int = 5060, *,
            ip_id: int | None = None, mirror: float | None = None) -> None:
        """Add one SIP datagram.

        mirror: also emit the identical frame this many seconds later with the same
        IP id, simulating a port mirrored on both sides of a device.
        """
        payload = raw.replace("\n", "\r\n").encode()
        self._ip_id = getattr(self, "_ip_id", 1000) + 1
        ident = ip_id if ip_id is not None else self._ip_id
        for offset in ([0.0] if mirror is None else [0.0, mirror]):
            pkt = (_ether() / IP(src=src, dst=dst, id=ident)
                   / UDP(sport=sport, dport=dport) / Raw(payload))
            pkt.time = t + offset
            self.packets.append(pkt)

    # ---- RTP ---------------------------------------------------------------
    def rtp(self, t0: float, src: str, dst: str, sport: int, dport: int, *,
            ssrc: int = 0x11223344, count: int = 100, pt: int = 0,
            ptime: float = 0.02, start_seq: int = 1000, drop: set[int] | None = None,
            payload_size: int = 160, pause: tuple[int, float] | None = None,
            mark_pause: bool = True) -> None:
        """Emit one RTP stream.

        pause: (index, seconds) — the sender goes quiet before that packet, so
        both the clock and the RTP timestamp skip ahead. mark_pause sets the
        marker bit on the packet that resumes, as a UA doing silence suppression
        does (RFC 3550 section 5.1); clearing it models a sender that does not.
        """
        drop = drop or set()
        ts = 0
        clock = t0
        for i in range(count):
            seq = start_seq + i
            ts += int(ptime * 8000)
            clock += ptime
            marker = False
            if pause and i == pause[0]:
                ts += int(pause[1] * 8000)
                clock += pause[1]
                marker = mark_pause
            if i in drop:
                continue
            header = struct.pack("!BBHII", 0x80, pt | (0x80 if marker else 0),
                                 seq & 0xFFFF, ts, ssrc)
            pkt = (_ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
                   / Raw(header + b"\xd5" * payload_size))
            pkt.time = clock - ptime
            self.packets.append(pkt)

    def write(self, path: pathlib.Path) -> pathlib.Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.packets.sort(key=lambda p: p.time)
        wrpcap(str(path), self.packets)
        return path


# ---------------------------------------------------------------- message templates
def sdp(addr: str, port: int, codecs: str = "0 8 101", direction: str = "sendrecv",
        version: int = 0, proto: str = "RTP/AVP", extra: str = "",
        session_id: int | None = None) -> str:
    rtpmaps = {"0": "PCMU/8000", "8": "PCMA/8000", "18": "G729/8000",
               "9": "G722/8000", "101": "telephone-event/8000", "100": "telephone-event/8000"}
    lines = [f"a=rtpmap:{c} {rtpmaps[c]}" for c in codecs.split() if c in rtpmaps]
    # A real UA picks its own session id; sharing one across both ends is not realistic.
    sid = session_id if session_id is not None else 1000 + (hash(addr) % 9000)
    body = (f"v=0\n"
            f"o=- {sid} {version} IN IP4 {addr}\n"
            f"s=-\n"
            f"c=IN IP4 {addr}\n"
            f"t=0 0\n"
            f"m=audio {port} {proto} {codecs}\n"
            + "\n".join(lines) + f"\na={direction}\n" + extra)
    return body


def invite(call_id: str, *, ftag: str = "aaa", cseq: int = 1, body: str = "",
           caller: str = CALLER, callee: str = CALLEE, contact: str | None = None,
           branch: str = "z9hG4bK-inv-1", extra: str = "", via_host: str | None = None,
           to_tag: str = "", max_forwards: int = 70, ruri: str | None = None) -> str:
    contact = contact or f"<sip:alice@{caller}>"
    head = (f"INVITE {ruri or f'sip:bob@{callee}'} SIP/2.0\n"
            f"Via: SIP/2.0/UDP {via_host or caller}:5060;branch={branch};rport\n"
            f"Max-Forwards: {max_forwards}\n"
            f"From: <sip:alice@{caller}>;tag={ftag}\n"
            f"To: <sip:bob@{callee}>{';tag=' + to_tag if to_tag else ''}\n"
            f"Call-ID: {call_id}\n"
            f"CSeq: {cseq} INVITE\n"
            f"Contact: {contact}\n"
            + extra
            + ("Content-Type: application/sdp\n" if body else ""))
    return head + f"Content-Length: {len(body)}\n\n{body}"


def response(status: int, reason: str, call_id: str, *, ftag: str = "aaa",
             ttag: str = "bbb", cseq: int = 1, method: str = "INVITE", body: str = "",
             caller: str = CALLER, callee: str = CALLEE, contact: str | None = None,
             branch: str = "z9hG4bK-inv-1", extra: str = "",
             record_route: str = "", via_host: str | None = None) -> str:
    # A response echoes the request's Via verbatim, so via_host must match the request.
    head = (f"SIP/2.0 {status} {reason}\n"
            f"Via: SIP/2.0/UDP {via_host or caller}:5060;branch={branch};rport\n"
            + (f"Record-Route: {record_route}\n" if record_route else "")
            + f"From: <sip:alice@{caller}>;tag={ftag}\n"
            f"To: <sip:bob@{callee}>{';tag=' + ttag if ttag else ''}\n"
            f"Call-ID: {call_id}\n"
            f"CSeq: {cseq} {method}\n"
            + (f"Contact: {contact}\n" if contact else "")
            + extra
            + ("Content-Type: application/sdp\n" if body else ""))
    return head + f"Content-Length: {len(body)}\n\n{body}"


def request(method: str, call_id: str, *, ftag: str = "aaa", ttag: str = "bbb",
            cseq: int = 2, caller: str = CALLER, callee: str = CALLEE,
            branch: str = "z9hG4bK-req-1", body: str = "", extra: str = "",
            target: str | None = None, contact: str | None = None,
            route: str = "", via_host: str | None = None,
            max_forwards: int | None = 70) -> str:
    """max_forwards=None omits the header, as the UAs RFC 3261 section 16.6 warns about do."""
    head = (f"{method} {target or f'sip:bob@{callee}'} SIP/2.0\n"
            f"Via: SIP/2.0/UDP {via_host or caller}:5060;branch={branch};rport\n"
            + (f"Route: {route}\n" if route else "")
            + (f"Max-Forwards: {max_forwards}\n" if max_forwards is not None else "")
            + f"From: <sip:alice@{caller}>;tag={ftag}\n"
            f"To: <sip:bob@{callee}>;tag={ttag}\n"
            f"Call-ID: {call_id}\n"
            f"CSeq: {cseq} {method}\n"
            + (f"Contact: {contact}\n" if contact else "")
            + extra
            + ("Content-Type: application/sdp\n" if body else ""))
    return head + f"Content-Length: {len(body)}\n\n{body}"


# ---------------------------------------------------------------- OCOM HTML export
# The shape analyzer/ocom.py reads: three JSON literals inside the page's last
# script block. Written out here rather than by trimming a real export, because a
# real one is a megabyte of jQuery and carries customer numbers.
OCOM_PAGE = """<!doctype html>
<html>
  <head><meta http-equiv="content-type" content="text/html;charset=utf-8" /><title></title>
  </head>
  <body>
    <div class="message-flow compact"><div class="entities"></div></div>
    <script type="text/javascript">
     $(window).on('load', function() {
        var data = (%(data)s);
        var offSet =%(offset)d;
        var config = _(data).defaults({
          devices: (%(devices)s),
          options: (%(options)s),
          offline: true,
          offset: offSet
        });
     });
    </script>
  </body>
</html>
"""

RESOLVED = ("<span style='color:#008000;font-weight:bold'><span style='font-weight:inherit;"
            "font-style:inherit;text-decoration:none;color:black'>%s</span> (%s)</span>")


def ocom_device(device_id: int, name: str, addresses: list[str], kind: str = "SBC") -> dict:
    return {"id": device_id, "name": name, "type": kind, "description": "",
            "ipranges": "\n".join(addresses), "match_type": "M_GENERIC",
            "realms": None, "hidden": None, "external": 0}


def ocom_sip(ts: str, src: str, dst: str, raw: str, *, leg: int, src_device: int,
             dst_device: int, realm: str = "", vlan: int = 100,
             src_port: int = 5060, dst_port: int = 5060) -> dict:
    """One SIP row. `realm` decorates src_ip the way 'Resolve IP addresses' does."""
    first = raw.split("\n", 1)[0]
    entry = {
        "type": "SIP", "proto": "UDP", "vlan": vlan,
        "src_ip": RESOLVED % (src, realm) if realm else src,
        "dst_ip": dst, "src_port": src_port, "dst_port": dst_port,
        "data": raw.replace("\n", "\r\n"), "ts": ts,
        "msgid": f"(b'\\x00', 0, {len(raw)})",
        "legid": leg, "src_device": src_device, "dst_device": dst_device,
        "src_mac": "00:00:00:00:00:00", "dst_mac": "00:00:00:00:00:00",
        "codecs": None, "html": "",
    }
    if first.startswith("SIP/2.0"):
        entry["code"], entry["reason"] = int(first.split()[1]), first.split(None, 2)[2]
    else:
        entry["method"], entry["ruri"] = first.split()[0], first.split()[1]
    return entry


def ocom_media(ts: str, src: str, src_port: int, dst: str, dst_port: int, *, leg: int,
               src_device: int, dst_device: int, label: str = "START RTP",
               packets: int = 250, lost: int = 0, discarded: int = 0,
               loss_pct: float = 0.0, jitter: float = 0.5, mos: float | None = None,
               codec: str = "PCMA (8)", reporter: str = "OCOM-RTP-PROBE") -> dict:
    """One START/END RTP row. The stats live in the tooltip text, as in a real export."""
    txt = (f"Reporter: {reporter}\n"
           f"Media type: audio\n"
           f"Codecs: {codec}\n"
           f"Packets received: {packets}\n"
           f"Packets lost: {lost}\n"
           f"Packets discarded: {discarded}\n"
           f"Packet loss rate: {loss_pct:.2f} %\n"
           f"Jitter average: {jitter:.2f} ms\n"
           f"Jitter maximum: {jitter:.2f} ms\n")
    entry = {"type": "RTP", "text": label, "txt": txt, "ts": ts, "vlan": 100,
             "src_ip": src, "dst_ip": dst, "src_port": src_port, "dst_port": dst_port,
             "direction": "src2dst", "msgid": f"rtp_{leg}", "legid": leg,
             "src_device": src_device, "dst_device": dst_device, "html": ""}
    if mos is not None:
        entry["MOS"] = mos
    return entry


def write_ocom(path: pathlib.Path, entries: list[dict], devices: list[dict],
               options: dict | None = None, offset: int = -7200) -> pathlib.Path:
    defaults = {"resolve_ips": True, "media": True, "duplicates": True, "ips": True,
                "codecs": True, "absolute_time": True}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(OCOM_PAGE % {
        "data": json.dumps({"messages": entries}),
        "devices": json.dumps(devices),
        "options": json.dumps({**defaults, **(options or {})}),
        "offset": offset,
    })
    return path
