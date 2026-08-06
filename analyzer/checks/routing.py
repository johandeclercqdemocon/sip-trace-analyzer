"""Routing, NAT and transport checks."""
from __future__ import annotations

from collections.abc import Iterable

from ..message import parse_nameaddr
from ..sdp import is_private
from .base import MTU_THRESHOLD, Context, Finding, check, finding


def _host_of(endpoint: str) -> str:
    """The bare host from any of the forms this codebase carries one in.

    '1.2.3.4:5060' -> '1.2.3.4', '[::1]:5060' -> '::1', '[::1]' -> '::1'.

    Via sent-by and URI hosts keep the wire form, so an IPv6 host arrives here in
    brackets while the same address taken from an endpoint does not. Comparing the
    two forms directly reports every IPv6 hop as a mismatch with itself, so every
    host entering a comparison goes through this first.
    """
    if not endpoint:
        return ""
    if endpoint.startswith("["):
        return endpoint[1:endpoint.find("]")] if "]" in endpoint else endpoint
    return endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint


@check("SIP-RECORD-ROUTE-ASYMMETRY")
def record_route_asymmetry(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for d in call.dialogs:
            if not (d.record_route_early and d.record_route_final):
                continue
            if d.record_route_early == d.record_route_final:
                continue
            yield finding(
                "SIP-RECORD-ROUTE-ASYMMETRY", call,
                f"the Record-Route set changed between the provisional and the 2xx: "
                f"{d.record_route_early} then {d.record_route_final}; the Route set built from "
                f"the 2xx will not match the path the early dialog used",
                d.establishing)


@check("SIP-NO-ROUTE-IN-DIALOG")
def no_route_in_dialog(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for d in call.dialogs:
            rr = d.record_route_final or d.record_route_early
            if not rr:
                continue
            # A proxy in the Route set pops its own entry before forwarding
            # (RFC 3261 section 16.12), so the copy it sends on legitimately has
            # no Route. On a capture taken either side of that proxy, both copies
            # are present and only the one it sent would be reported.
            rr_hosts = {_host_of(parse_nameaddr(h).host) for h in rr}
            for m in d.messages:
                if not m.is_request or m.method in ("ACK", "CANCEL", "INVITE"):
                    continue
                if _host_of(m.src) in rr_hosts:
                    continue
                if m.to.tag and m.from_.tag and not m.all("route"):
                    yield finding(
                        "SIP-NO-ROUTE-IN-DIALOG", call,
                        f"in-dialog {m.method} carries no Route header although the dialog was "
                        f"established with Record-Route ({len(rr)} hop(s)); it will not follow "
                        f"the signalling path", m)
                    break


@check("SIP-CONTACT-PRIVATE-ADDRESS")
def contact_private(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        reported: set[str] = set()
        for m in call.messages:
            src_host = _host_of(m.src)
            if src_host and is_private(src_host):
                continue        # both ends private: an internal capture, not a NAT problem
            for c in m.contacts:
                host = _host_of(c.host)
                if not host or not is_private(host) or host in reported:
                    continue
                reported.add(host)
                yield finding(
                    "SIP-CONTACT-PRIVATE-ADDRESS", call,
                    f"{m.summary()} advertises Contact <{c.uri}> with private address {host} "
                    f"while the packet arrived from public {src_host}; in-dialog requests sent "
                    f"to that Contact will be black-holed", m)


@check("SIP-VIA-RECEIVED-MISMATCH")
def via_received_mismatch(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        reported: set[str] = set()
        # RFC 3261 section 18.2.1 puts the duty on the *receiver*, so a request
        # captured on the wire has legitimately not been given a received yet. The
        # response is where the receiver's answer shows up: if it came back with
        # one, the rule was honoured and there is nothing to report. Only a trace
        # that never shows the parameter is evidence of the fault.
        answered = {v.branch for m in call.messages if not m.is_request
                    for v in m.vias if v.received and v.branch}
        for m in call.messages:
            # An ACK is answered by nothing, so no received parameter can ever
            # appear for it and its absence is not evidence of anything.
            if not m.is_request or not m.src or m.method == "ACK":
                continue
            v = m.top_via
            if v is None or not v.host:
                continue
            src_host = _host_of(m.src)
            via_host = _host_of(v.host)
            if via_host == src_host or v.received or v.branch in answered:
                continue
            if via_host in reported:
                continue
            reported.add(via_host)
            yield finding(
                "SIP-VIA-RECEIVED-MISMATCH", call,
                f"{m.method} has Via sent-by {via_host} but arrived from {src_host}, and no "
                f"received= parameter was added; responses will go to an address that cannot "
                f"be reached", m)


@check("SIP-NO-RPORT")
def no_rport(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        reported: set[str] = set()
        for m in call.messages:
            if not m.is_request or not m.src:
                continue
            v = m.top_via
            if v is None or v.rport is not None:
                continue
            src_host = _host_of(m.src)
            src_port = m.src.rsplit(":", 1)[-1] if ":" in m.src else ""
            # Only interesting when the source really is behind a NAT.
            via_host = _host_of(v.host)
            if not (is_private(via_host) and not is_private(src_host)):
                continue
            if via_host in reported:
                continue
            reported.add(via_host)
            detail = (f"{m.method} from a NATed source ({via_host} seen as {src_host}:{src_port}) "
                      f"has no rport parameter; responses go to the Via port, not the mapped one")
            yield finding("SIP-NO-RPORT", call, detail, m)


@check("SIP-REGISTER-EXPIRY-EXCEEDS-NAT")
def register_expiry_exceeds_nat(ctx: Context) -> Iterable[Finding]:
    """A long binding from behind NAT dies with the NAT mapping unless kept alive."""
    NAT_BINDING = 120           # a common UDP mapping lifetime
    for call in ctx.calls:
        for txn in call.transactions_of("REGISTER"):
            req, ok = txn.request, None
            for r in txn.finals:
                if 200 <= (r.status or 0) < 300:
                    ok = r
                    break
            if req is None or ok is None or req.transport != "UDP":
                continue
            v = req.top_via
            src_host = _host_of(req.src)
            behind_nat = bool(v and ((is_private(_host_of(v.host)) and not is_private(src_host))
                                     or v.received))
            if not behind_nat:
                continue
            granted = None
            for c in ok.contacts:
                e = c.params.get("expires")
                if e and e.isdigit():
                    granted = max(granted or 0, int(e))
            hdr = ok.get("expires")
            if hdr and hdr.strip().isdigit():
                granted = max(granted or 0, int(hdr.strip()))
            if not granted or granted <= NAT_BINDING:
                continue
            # Any traffic from that client inside the window holds the mapping open.
            later = [m for m in ctx.trace.messages
                     if m.src == req.src and m.timestamp > ok.timestamp]
            gaps = [b.timestamp - a.timestamp
                    for a, b in zip([ok] + later, later, strict=False)] if later else []
            if gaps and max(gaps) <= NAT_BINDING:
                continue
            yield finding(
                "SIP-REGISTER-EXPIRY-EXCEEDS-NAT", call,
                f"the registrar granted {granted}s to a client behind NAT "
                f"({_host_of(v.host) if v else '?'} seen as {src_host}) with no traffic from it inside "
                f"the usual {NAT_BINDING}s binding lifetime; inbound calls will fail once the "
                f"mapping expires", req, ok)


@check("SIP-UDP-OVERSIZE")
def udp_oversize(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        worst = None
        for m in call.messages:
            if m.transport != "UDP":
                continue
            if m.size >= MTU_THRESHOLD and (worst is None or m.size > worst.size):
                worst = m
        if worst is not None:
            yield finding(
                "SIP-UDP-OVERSIZE", call,
                f"{worst.summary()} is {worst.size} bytes over UDP, at or above the "
                f"{MTU_THRESHOLD}-byte threshold at which RFC 3261 requires TCP; it will be "
                f"fragmented and is likely to be dropped", worst)


@check("SIP-MAX-FORWARDS-LOW")
def max_forwards_low(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for m in call.messages:
            if not m.is_request or m.to.tag:
                continue
            mf = m.get("max-forwards")
            if mf and mf.strip().isdigit() and int(mf) < 20:
                yield finding("SIP-MAX-FORWARDS-LOW", call,
                              f"initial {m.method} starts with Max-Forwards {mf.strip()}; the "
                              f"recommended starting value is 70", m)
                break


@check("SIP-VIA-LOOP")
def via_loop(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for m in call.messages:
            if not m.is_request:
                continue
            # A Via identifies an element by sent-by, which is host AND port
            # (RFC 3261 section 20.42). Matching on the host alone calls it a loop
            # whenever a UA and its proxy, or two ports of one B2BUA, share an
            # address — common enough that it made this critical check unusable.
            sent_by = [f"{v.host}:{v.port or 5060}" for v in m.vias if v.host]
            dupes = {h for h in sent_by if sent_by.count(h) > 1}
            if dupes:
                yield finding(
                    "SIP-VIA-LOOP", call,
                    f"{m.method} carries {len(sent_by)} Via headers with "
                    f"{', '.join(sorted(dupes))} appearing more than once - the request has "
                    f"looped through the same element", m)
                break
