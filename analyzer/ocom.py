"""Read an OCOM 'message flow' HTML export.

OCOM (Oracle Communications Operations Monitor, formerly Palladion) shows a call as
a ladder and exports that page as a single self-contained HTML file. The page is
mostly jQuery and pre-rendered markup, but everything the ladder draws comes from
three JSON literals embedded in the last script block:

    var data = ({"messages": [...]})          every arrow on the ladder
    ...  devices:  ([...])                    the device catalogue, ip ranges included
    ...  options:  ({...})                    which columns the exporter had switched on

That JSON is the trace. Each SIP entry carries the whole message verbatim, so the
normal parser does the work; this module's job is the envelope - time, addresses,
transport, and the two things a pcap cannot tell us:

* **Which device an address belongs to.** One SBC answers on a dozen addresses, so
  'the same box' is a fact about the network, not something inferable from a
  capture. The export states it, which is what makes a device-column ladder
  possible and what stops two legs of one B2BUA reading as two unrelated hosts.
* **Media the capture never contained.** OCOM's probes report a stream as a summary
  - packets, loss, jitter, MOS - not as packets. Those become MediaReports rather
  than RtpPackets: nothing downstream may treat them as a packet-level capture,
  because the per-packet checks (sequence gaps, SSRC changes, timestamp jumps)
  have nothing to run on.

An export is a *correlated* trace: the same call appears once per hop, with the
Call-ID preserved and a fresh Via branch each time. Every entry carries its leg
number, which is what keeps four views of one INVITE from reading as four offers.
"""
from __future__ import annotations

import html
import ipaddress
import json
import pathlib
import re
from datetime import datetime

from . import message as msgmod
from .readers import Device, MediaReport, Trace, mark_capture_points, mark_duplicates

# The three literals, each introduced by 'name = (' or 'name: (' and closed by the
# matching bracket. Only the opening is matched here: raw_decode finds the end,
# which is the one way to do it that survives braces inside the SIP bodies.
DATA = re.compile(r"\bvar\s+data\s*=\s*\(")
DEVICES = re.compile(r"\bdevices\s*:\s*\(")
OPTIONS = re.compile(r"\boptions\s*:\s*\(")
OFFSET = re.compile(r"\bvar\s+offSet\s*=\s*(-?\d+)")

TAGS = re.compile(r"<[^>]+>")
REALM = re.compile(r"\(([^)]*)\)")


def looks_like_ocom(head: str) -> bool:
    """True for the HTML export, false for any other HTML file.

    Deliberately checks for the payload rather than for OCOM branding: the export
    carries no product name anywhere in the markup, and the anchor is the thing we
    actually need to be present.
    """
    return "var data = (" in head and '"messages"' in head


def _literal(text: str, anchor: re.Pattern, what: str):
    m = anchor.search(text)
    if m is None:
        raise ValueError(f"this HTML has no OCOM {what} block")
    try:
        value, _ = json.JSONDecoder().raw_decode(text, m.end())
    except json.JSONDecodeError as exc:                             # pragma: no cover
        raise ValueError(f"the OCOM {what} block is not valid JSON: {exc}") from exc
    return value


def _plain(cell) -> tuple[str, list[str]]:
    """('address', [realm, …]) from an export cell.

    With 'Resolve IP addresses' switched on the exporter writes the cell as markup -
    the address in one span, then a parenthesised realm per span it belongs to:

        <span …>192.0.2.10</span> (Core)</span>, <span …>(Core-MG )</span>

    With it off the cell is the bare address. Stripping the tags gives one form that
    covers both.
    """
    text = html.unescape(TAGS.sub("", str(cell or ""))).strip()
    if not text:
        return "", []
    address, _, rest = text.partition(" ")
    return address, [r.strip() for r in REALM.findall(rest) if r.strip()]


def _endpoint(address: str, port) -> str:
    """'ip:port', bracketing IPv6 so the ':' that separates the port stays unique.

    Everything downstream splits an endpoint with rsplit(':', 1); a bare IPv6
    address turns that into nonsense, and this format is full of them.
    """
    if not address:
        return ""
    try:
        if isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address):
            address = f"[{address}]"
    except ValueError:
        pass                                    # a hostname, or already bracketed
    return f"{address}:{port}" if port not in (None, "") else address


def _epoch(ts: str) -> tuple[float, bool]:
    """The export writes RFC 3339 with an explicit offset, so this is unambiguous."""
    try:
        return datetime.fromisoformat(ts).timestamp(), True
    except (TypeError, ValueError):
        return 0.0, False


def _devices(raw: list) -> dict[int, Device]:
    out: dict[int, Device] = {}
    for d in raw or []:
        if d.get("id") is None:
            continue
        # ipranges is a newline-separated mix of addresses and CIDRs, and is the
        # authoritative answer to 'is this the same box'.
        ranges = [r.strip() for r in str(d.get("ipranges") or "").split("\n") if r.strip()]
        out[d["id"]] = Device(id=d["id"], name=(d.get("name") or f"device {d['id']}").strip(),
                              kind=(d.get("type") or "").strip(),
                              description=(d.get("description") or "").strip(),
                              addresses=ranges)
    return out


# Probe summaries are 'Label: value' lines. The labels are the probe's, not ours,
# so they are matched loosely and anything unrecognised is kept verbatim.
STAT = re.compile(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", re.M)
NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


def _number(value: str) -> float | None:
    m = NUMBER.search(value or "")
    return float(m.group()) if m else None


def _media_report(entry: dict, frame: int, devices: dict[int, Device]) -> MediaReport:
    """Turn one START/END RTP row into the stream summary behind it.

    The row's tooltip is the report: reporter, codec, packet counts, loss, jitter
    and - when the probe computed one - a MOS. What is *not* there is any packet,
    which is why this is not an RtpStream.
    """
    stats = {k.strip().lower(): v for k, v in STAT.findall(entry.get("txt") or "")}
    src, _ = _plain(entry.get("src_ip"))
    dst, _ = _plain(entry.get("dst_ip"))
    at, _ = _epoch(entry.get("ts", ""))
    label = (entry.get("text") or "").strip()

    loss_rate = _number(stats.get("packet loss rate", ""))
    return MediaReport(
        frame=frame,
        at=at,
        ends=label.upper().startswith("END"),
        src=_endpoint(src, entry.get("src_port")),
        dst=_endpoint(dst, entry.get("dst_port")),
        label=label,
        reporter=stats.get("reporter", ""),
        media_type=stats.get("media type", ""),
        codecs=[c.strip() for c in (stats.get("codecs") or "").split(",") if c.strip()],
        packets=_number(stats.get("packets received", "")),
        lost=_number(stats.get("packets lost", "")),
        discarded=_number(stats.get("packets discarded", "")),
        # The probe prints a percentage; every other ratio in this codebase is 0..1.
        loss_ratio=loss_rate / 100.0 if loss_rate is not None else None,
        jitter_avg_ms=_number(stats.get("jitter average", "")),
        jitter_max_ms=_number(stats.get("jitter maximum", "")),
        mos=entry.get("MOS") if isinstance(entry.get("MOS"), (int, float))
        else _number(stats.get("mos", "")),
        leg=_leg(entry.get("legid")),
        src_device=_name_of(devices, entry.get("src_device")),
        dst_device=_name_of(devices, entry.get("dst_device")),
        stats=stats,
    )


def _name_of(devices: dict[int, Device], device_id) -> str:
    d = devices.get(device_id)
    return d.name if d else ""


def _leg(value) -> int | None:
    """The hop number, or None when the source did not say.

    Leg numbering is the export's, not ours: how many a call has depends on how
    many elements it crossed, the numbers need not start at zero or be contiguous,
    and two calls in one export need not agree on either. Nothing here counts
    them or assumes a range - a leg is only ever compared for equality. Older
    exports omit the field entirely, which reads as 'one undivided view'.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def read_ocom_html(path: pathlib.Path) -> Trace:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not looks_like_ocom(text):
        raise ValueError("this HTML is not an OCOM message-flow export "
                         "(no 'var data' block with messages in it)")

    payload = _literal(text, DATA, "message")
    entries = payload.get("messages") or []
    devices = _devices(_literal(text, DEVICES, "device") if DEVICES.search(text) else [])
    options = _literal(text, OPTIONS, "option") if OPTIONS.search(text) else {}

    trace = Trace(source=str(path), kind="ocom-html")
    trace.display_offset = int(m.group(1)) if (m := OFFSET.search(text)) else 0

    order: list[str] = []             # device columns, in first-appearance order
    unhandled: dict[str, int] = {}

    # The export numbers the ladder over every row, SIP and media alike, and those
    # numbers are what the operator reads off the screen. Keeping frame == that
    # number is what lets a finding be looked up in the original export.
    for frame, entry in enumerate(entries, start=1):
        for device_id in (entry.get("src_device"), entry.get("dst_device")):
            name = _name_of(devices, device_id)
            if name and name not in order:
                order.append(name)

        kind = (entry.get("type") or "").upper()
        if kind == "RTP":
            trace.media_reports.append(_media_report(entry, frame, devices))
            continue
        if kind != "SIP" or not entry.get("data"):
            # H.248/MEGACO and ISUP rows appear in the same export. They are not
            # dropped silently: a trace half of whose rows were ignored is a
            # different trace, and the note says so.
            unhandled[kind or "unknown"] = unhandled.get(kind or "unknown", 0) + 1
            continue

        src, src_realms = _plain(entry.get("src_ip"))
        dst, dst_realms = _plain(entry.get("dst_ip"))
        at, known = _epoch(entry.get("ts", ""))
        vlan = entry.get("vlan")
        m = msgmod.parse(
            entry["data"], timestamp=at, time_known=known,
            src=_endpoint(src, entry.get("src_port")),
            dst=_endpoint(dst, entry.get("dst_port")),
            transport=(entry.get("proto") or "UDP").upper(),
            frame=frame,
            link_type=f"vlan {vlan}" if vlan else "",
            src_device=_name_of(devices, entry.get("src_device")),
            dst_device=_name_of(devices, entry.get("dst_device")),
            src_realms=src_realms, dst_realms=dst_realms,
            leg=_leg(entry.get("legid")),
        )
        if m is None:
            trace.notes.append(f"row {frame} is marked SIP but does not parse as a "
                               f"SIP message")
            continue
        trace.messages.append(m)

    # The catalogue is the whole OCOM inventory - hundreds of elements, of which a
    # handful are on this flow. Only those are the trace's.
    trace.device_order = order
    trace.devices = [d for d in devices.values() if d.name in order]
    trace.media_reports.sort(key=lambda r: (r.at, r.frame))
    trace.messages.sort(key=lambda m: (m.timestamp, m.frame))

    _note(trace, options, unhandled)
    # An export is already correlated, so byte-identical rows are rare - but a
    # probe that sees a packet on two segments still produces them, and the same
    # rules apply as to any other trace.
    dupes = mark_duplicates(trace)
    if dupes:
        trace.notes.append(f"{dupes} duplicated row(s) in the export, excluded from "
                           f"transaction analysis")
    trace.nat_map = mark_capture_points(trace)
    return trace


def _note(trace: Trace, options: dict, unhandled: dict[str, int]) -> None:
    for kind, n in sorted(unhandled.items()):
        trace.notes.append(f"{n} {kind} row(s) in the export are not SIP or RTP and "
                           f"were not analysed")
    if trace.media_reports:
        reporters = sorted({r.reporter for r in trace.media_reports if r.reporter})
        trace.notes.append(
            f"media is present as {len(trace.media_reports)} probe report(s)"
            + (f" from {', '.join(reporters)}" if reporters else "") +
            ", not as packets: the per-packet RTP checks cannot run, and the "
            "reported loss, jitter and MOS are used instead")
    if trace.devices:
        trace.notes.append(
            f"the export names {len(trace.device_order)} device(s) on this flow; "
            f"addresses are grouped by device rather than treated as separate hosts")
    # An export made with a column switched off is missing that data entirely, and
    # the checks that need it would otherwise look like they found nothing.
    if options.get("resolve_ips") is False:
        trace.notes.append("the export was made with 'Resolve IP addresses' off")
    if options.get("media") is False:
        trace.notes.append("the export was made with 'Media' off: it contains no RTP "
                           "rows even if the call had media")
    if options.get("duplicates") is False:
        trace.notes.append("the export was made with 'Duplicates' off, so rows OCOM "
                           "considered duplicates are in the file but were hidden on "
                           "the page it was taken from")
