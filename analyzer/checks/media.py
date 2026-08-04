"""SDP offer/answer and RTP media-plane checks."""
from __future__ import annotations

from collections.abc import Iterable

from ..model import Call, Dialog, RtpStream
from ..sdp import Sdp, is_private, is_unspecified
from .base import Context, Finding, check, finding


def _endpoints(d: Dialog) -> list[tuple[str, int, Sdp, str]]:
    """(address, port, sdp, who) for every audio stream the dialog negotiated."""
    out = []
    ex = d.negotiated
    if ex is None:
        return out
    for sdp, who in ((ex.offer_sdp, "offerer"), (ex.answer_sdp, "answerer")):
        if sdp is None:
            continue
        m = sdp.audio()
        if m is None or m.is_disabled:
            continue
        addr = sdp.address_for(m)
        if addr and not is_unspecified(addr):
            out.append((addr, m.port, sdp, who))
    return out


# ---------------------------------------------------------------- offer/answer
@check("SDP-ANSWER-MISSING")
def answer_missing(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for d in call.dialogs:
            if d.establishing is None:
                continue
            for ex in d.exchanges:
                if ex.complete or ex.offer is not d.invite:
                    continue
                yield finding(
                    "SDP-ANSWER-MISSING", call,
                    "the INVITE carried an offer but no SDP answer appears anywhere in the "
                    "dialog, including the 2xx", d.invite, d.establishing)


@check("SDP-OFFERLESS-INVITE-NO-ACK-ANSWER")
def offerless_no_ack_answer(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for d in call.dialogs:
            inv, ok = d.invite, d.establishing
            if inv is None or ok is None:
                continue
            if inv.body.strip() or not ok.body.strip():
                continue
            # Offer is in the 2xx, so the answer must be in the ACK.
            acks = [a for t in call.transactions_of("INVITE") for a in t.acks]
            acks += [m for m in call.messages if m.is_request and m.method == "ACK"]
            if any(a.body.strip() for a in acks):
                continue
            yield finding(
                "SDP-OFFERLESS-INVITE-NO-ACK-ANSWER", call,
                "the INVITE had no offer, so the 2xx carried it - but the ACK contains no SDP "
                "answer, leaving the negotiation incomplete", inv, ok)


@check("SDP-CODEC-MISMATCH")
def codec_mismatch(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for txn in call.invite_transactions:
            rej = next((r for r in txn.finals if r.status in (488, 606)), None)
            req = txn.request
            if rej is None or req is None:
                continue
            offered = ""
            if (s := _sdp(req)) and (m := s.audio()):
                offered = ", ".join(sorted(m.codec_set()))
            yield finding(
                "SDP-CODEC-MISMATCH", call,
                f"{rej.status} {rej.reason} rejecting the offer"
                + (f" (offered {offered})" if offered else ""), req, rej)

        for d in call.dialogs:
            ex = d.negotiated
            if ex is None or ex.answer_sdp is None:
                continue
            om, am = ex.offer_sdp.audio(), ex.answer_sdp.audio()
            if om is None or am is None or am.is_disabled:
                continue
            common = om.codec_set() & am.codec_set() - {"TELEPHONE-EVENT", "CN"}
            if not common:
                yield finding(
                    "SDP-CODEC-MISMATCH", call,
                    f"the answer shares no audio codec with the offer: offered "
                    f"{sorted(om.codec_set())}, answered {sorted(am.codec_set())}",
                    ex.offer, ex.answer)


def _sdp(m) -> Sdp | None:
    from ..model import _sdp_of
    return _sdp_of(m)


@check("SDP-TRANSPORT-PROFILE-MISMATCH")
def transport_profile_mismatch(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for d in call.dialogs:
            ex = d.negotiated
            if ex is None or ex.answer_sdp is None:
                continue
            om, am = ex.offer_sdp.audio(), ex.answer_sdp.audio()
            if om is None or am is None or am.is_disabled:
                continue
            if om.proto != am.proto:
                yield finding(
                    "SDP-TRANSPORT-PROFILE-MISMATCH", call,
                    f"media transport profile differs: offer m= uses {om.proto}, answer uses "
                    f"{am.proto}", ex.offer, ex.answer)
            elif om.is_secure and bool(om.crypto) != bool(am.crypto):
                side = "answer" if om.crypto else "offer"
                yield finding(
                    "SDP-TRANSPORT-PROFILE-MISMATCH", call,
                    f"both sides negotiated {om.proto} but the {side} carries no a=crypto line, "
                    f"so no SRTP key was exchanged", ex.offer, ex.answer)


@check("SDP-DIRECTION-MISMATCH")
def direction_mismatch(ctx: Context) -> Iterable[Finding]:
    complement = {"sendonly": "recvonly", "recvonly": "sendonly",
                  "sendrecv": "sendrecv", "inactive": "inactive"}
    for call in ctx.calls:
        for d in call.dialogs:
            for ex in d.exchanges:
                if not ex.complete or ex.answer_sdp is None:
                    continue
                om, am = ex.offer_sdp.audio(), ex.answer_sdp.audio()
                if om is None or am is None or am.is_disabled:
                    continue
                od = ex.offer_sdp.direction_for(om)
                ad = ex.answer_sdp.direction_for(am)
                # sendrecv may legitimately be answered with a narrower direction.
                if od == "sendrecv" and ad in ("sendonly", "recvonly", "inactive", "sendrecv"):
                    continue
                if ad == complement[od]:
                    continue
                if od == "inactive" and ad == "inactive":
                    continue
                yield finding(
                    "SDP-DIRECTION-MISMATCH", call,
                    f"offer is a={od} but the answer is a={ad}; the complement of {od} is "
                    f"{complement[od]}, so the two ends disagree about who may send",
                    ex.offer, ex.answer)


@check("SDP-PRIVATE-MEDIA-ADDRESS")
def private_media_address(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        reported: set[str] = set()
        for d in call.dialogs:
            for ex in d.exchanges:
                for sdp, msg in ((ex.offer_sdp, ex.offer), (ex.answer_sdp, ex.answer)):
                    if sdp is None or msg is None:
                        continue
                    peer = (msg.dst or "").rsplit(":", 1)[0]
                    if peer and is_private(peer):
                        continue
                    for m in sdp.media:
                        addr = sdp.address_for(m)
                        if not addr or not is_private(addr) or addr in reported:
                            continue
                        reported.add(addr)
                        yield finding(
                            "SDP-PRIVATE-MEDIA-ADDRESS", call,
                            f"{msg.summary()} offers {m.kind} media at private address "
                            f"{addr}:{m.port} to a public peer ({peer or 'unknown'}); "
                            f"media sent there will not arrive", msg)


@check("SDP-PORT-ZERO")
def port_zero(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for d in call.dialogs:
            ex = d.negotiated
            if ex is None or ex.answer_sdp is None:
                continue
            for om, am in zip(ex.offer_sdp.media, ex.answer_sdp.media, strict=False):
                if am.is_disabled and not om.is_disabled:
                    yield finding(
                        "SDP-PORT-ZERO", call,
                        f"the {am.kind} stream offered on port {om.port} was declined with "
                        f"port 0 in the answer", ex.answer)


@check("SDP-VERSION-NOT-INCREMENTED")
def version_not_incremented(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for d in call.dialogs:
            by_origin: dict[str, list] = {}
            for ex in d.exchanges:
                for sdp, msg in ((ex.offer_sdp, ex.offer), (ex.answer_sdp, ex.answer)):
                    if sdp is None or msg is None or not sdp.origin:
                        continue
                    by_origin.setdefault(sdp.origin_identity, []).append((sdp, msg))
            for ident, items in by_origin.items():
                sid = ident[1] if len(ident) > 1 else "?"
                for (a, ma), (b, mb) in zip(items, items[1:], strict=False):
                    if a.origin_version == b.origin_version and a.raw.strip() != b.raw.strip():
                        yield finding(
                            "SDP-VERSION-NOT-INCREMENTED", call,
                            f"session {sid} kept o= version {a.origin_version} while the body "
                            f"changed; the peer is entitled to ignore the change", ma, mb)


@check("SDP-HOLD-INCONSISTENT")
def hold_inconsistent(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for d in call.dialogs:
            legacy, modern = [], []
            for ex in d.exchanges:
                for sdp, msg in ((ex.offer_sdp, ex.offer), (ex.answer_sdp, ex.answer)):
                    if sdp is None or msg is None:
                        continue
                    m = sdp.audio()
                    if m is None:
                        continue
                    addr = sdp.address_for(m)
                    if addr and is_unspecified(addr):
                        legacy.append(msg)
                    elif sdp.direction_for(m) in ("sendonly", "inactive"):
                        modern.append(msg)
            if legacy and modern:
                yield finding(
                    "SDP-HOLD-INCONSISTENT", call,
                    "hold is signalled two different ways in one dialog: c=0.0.0.0 in "
                    f"{len(legacy)} message(s) and a=sendonly/inactive in {len(modern)}",
                    *(legacy[:1] + modern[:1]))


@check("SDP-DTMF-MISMATCH")
def dtmf_mismatch(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for d in call.dialogs:
            ex = d.negotiated
            if ex is None or ex.answer_sdp is None:
                continue
            om, am = ex.offer_sdp.audio(), ex.answer_sdp.audio()
            if om is None or am is None or am.is_disabled:
                continue
            op, ap = om.telephone_event_pt, am.telephone_event_pt
            if op is not None and ap is None:
                yield finding(
                    "SDP-DTMF-MISMATCH", call,
                    f"the offer negotiates RFC 4733 DTMF (telephone-event payload {op}) but the "
                    f"answer does not; DTMF will have to go inband or via INFO",
                    ex.offer, ex.answer)
            elif op is not None and ap is not None and op != ap:
                yield finding(
                    "SDP-DTMF-MISMATCH", call,
                    f"telephone-event payload number differs between offer ({op}) and answer "
                    f"({ap}); anything not rewriting the RTP will send unrecognised digits",
                    ex.offer, ex.answer)


@check("SDP-MULTIPLE-STREAMS-REORDERED")
def streams_reordered(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for d in call.dialogs:
            ex = d.negotiated
            if ex is None or ex.answer_sdp is None:
                continue
            okinds = [m.kind for m in ex.offer_sdp.media]
            akinds = [m.kind for m in ex.answer_sdp.media]
            if okinds != akinds:
                yield finding(
                    "SDP-MULTIPLE-STREAMS-REORDERED", call,
                    f"the answer's m= lines ({', '.join(akinds) or 'none'}) do not match the "
                    f"offer's ({', '.join(okinds) or 'none'}) in count or order",
                    ex.offer, ex.answer)


# ---------------------------------------------------------------- RTP
def _call_for(ctx: Context, *endpoints: str) -> Call | None:
    """Find the call whose negotiated media addresses include any of these endpoints."""
    wanted = set(endpoints)
    for call in ctx.calls:
        for d in call.dialogs:
            if any(f"{a}:{p}" in wanted for a, p, _, _ in _endpoints(d)):
                return call
    return None


def _stream_finding(ctx: Context, check_id: str, stream: RtpStream, detail: str,
                    evidence: list[str] | None = None) -> Finding:
    call = _call_for(ctx, stream.src, stream.dst)
    return Finding(check_id=check_id, detail=detail, at=stream.start,
                   call_id=call.call_id if call else "",
                   call_label=call.label() if call else "",
                   evidence=evidence or [])


def _streams_to(streams: list[RtpStream], addr: str, port: int) -> list[RtpStream]:
    want = f"{addr}:{port}"
    return [s for s in streams if s.dst == want]


def _streams_from(streams: list[RtpStream], addr: str, port: int) -> list[RtpStream]:
    want = f"{addr}:{port}"
    return [s for s in streams if s.src == want]


@check("RTP-NO-STREAM")
def rtp_no_stream(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_media:
        return
    for call in ctx.calls:
        for d in call.dialogs:
            if d.establishing is None:
                continue
            eps = _endpoints(d)
            if not eps:
                continue
            if any(_streams_to(ctx.streams, a, p) or _streams_from(ctx.streams, a, p)
                   for a, p, _, _ in eps):
                continue
            where = ", ".join(f"{a}:{p} ({who})" for a, p, _, who in eps)
            yield finding(
                "RTP-NO-STREAM", call,
                f"the dialog was answered and media negotiated at {where}, but the capture "
                f"contains no RTP to or from those addresses", d.establishing)


@check("RTP-ONE-WAY")
def rtp_one_way(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_media:
        return
    for call in ctx.calls:
        for d in call.dialogs:
            eps = _endpoints(d)
            if len(eps) < 2:
                continue
            silent = [(a, p, who) for a, p, _, who in eps
                      if not _streams_from(ctx.streams, a, p)]
            speaking = [(a, p, who) for a, p, _, who in eps
                        if _streams_from(ctx.streams, a, p)]
            if silent and speaking:
                sa, sp, swho = silent[0]
                ta, tp, twho = speaking[0]
                yield finding(
                    "RTP-ONE-WAY", call,
                    f"RTP flows from {ta}:{tp} ({twho}) but nothing is sent from {sa}:{sp} "
                    f"({swho}); audio will be one-way", d.establishing or d.invite)


@check("RTP-PAYLOAD-NOT-NEGOTIATED")
def rtp_payload_not_negotiated(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_media:
        return
    for call in ctx.calls:
        for d in call.dialogs:
            ex = d.negotiated
            if ex is None or ex.answer_sdp is None:
                continue
            am = ex.answer_sdp.audio()
            if am is None or am.is_disabled:
                continue
            allowed = set(am.payload_types)
            if not allowed:
                continue
            for a, p, _, who in _endpoints(d):
                for s in _streams_from(ctx.streams, a, p):
                    extra = s.payload_types - allowed - {13}     # 13 is comfort noise
                    if extra:
                        yield finding(
                            "RTP-PAYLOAD-NOT-NEGOTIATED", call,
                            f"the stream from {a}:{p} ({who}) carries payload type(s) "
                            f"{sorted(extra)} that the answer did not accept "
                            f"(negotiated {sorted(allowed)})", d.establishing or d.invite)


@check("RTP-SSRC-CHANGE")
def rtp_ssrc_change(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_media:
        return
    by_path: dict[tuple, list[RtpStream]] = {}
    for s in ctx.streams:
        by_path.setdefault((s.src, s.dst), []).append(s)
    for (src, dst), streams in by_path.items():
        if len(streams) < 2:
            continue
        streams.sort(key=lambda s: s.start)
        ssrcs = ", ".join(f"0x{s.ssrc:08x}" for s in streams)
        f = _stream_finding(
            ctx, "RTP-SSRC-CHANGE", streams[0],
            f"the media path {src} -> {dst} carries {len(streams)} SSRCs ({ssrcs}); the "
            f"source changed mid-stream",
            [f"{s.src} -> {s.dst} ssrc 0x{s.ssrc:08x} {len(s.packets)} packets over "
             f"{s.duration:.1f}s" for s in streams])
        f.at = streams[1].start
        yield f


@check("RTP-SEQUENCE-GAP")
def rtp_sequence_gap(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_media:
        return
    for s in ctx.streams:
        if len(s.packets) < 20 or s.lost == 0:
            continue
        ratio = s.loss_ratio
        if ratio < 0.005:
            continue
        gaps = s.sequence_gaps()
        biggest = max(n for _, n in gaps)
        yield _stream_finding(
            ctx, "RTP-SEQUENCE-GAP", s,
            f"{s.src} -> {s.dst} (ssrc 0x{s.ssrc:08x}) lost {s.lost} of {s.expected} "
            f"packets ({ratio * 100:.1f}%) in {len(gaps)} gap(s), largest {biggest}",
            [f"{len(s.packets)} packets received over {s.duration:.1f}s"])


@check("RTP-TIMESTAMP-JUMP")
def rtp_timestamp_jump(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_media:
        return
    for s in ctx.streams:
        if len(s.packets) < 20:
            continue
        pkts = sorted(s.packets, key=lambda p: p.seq)
        deltas = [(b.rtp_ts - a.rtp_ts) for a, b in zip(pkts, pkts[1:], strict=False) if b.seq == a.seq + 1]
        if len(deltas) < 10:
            continue
        typical = sorted(deltas)[len(deltas) // 2]
        if typical <= 0:
            continue
        jumps = [d for d in deltas if d > typical * 5 or d < 0]
        if jumps:
            yield _stream_finding(
                ctx, "RTP-TIMESTAMP-JUMP", s,
                f"{s.src} -> {s.dst} (ssrc 0x{s.ssrc:08x}) has {len(jumps)} timestamp "
                f"step(s) inconsistent with the {typical}-unit packet interval "
                f"(largest {max(jumps)})")


@check("RTCP-ABSENT")
def rtcp_absent(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_media:
        return
    rtcp_ports = {p.src for p in ctx.trace.rtp if p.is_rtcp} | \
                 {p.dst for p in ctx.trace.rtp if p.is_rtcp}
    for s in ctx.streams:
        if s.duration < 30:
            continue
        host, _, port = s.src.rpartition(":")
        if not port.isdigit():
            continue
        paired = f"{host}:{int(port) + 1}"
        if paired in rtcp_ports or s.src in rtcp_ports:
            continue
        yield _stream_finding(
            ctx, "RTCP-ABSENT", s,
            f"{s.src} -> {s.dst} ran for {s.duration:.0f}s with no RTCP on {paired} "
            f"and no rtcp-mux traffic on the RTP port")


@check("RTP-JITTER-HIGH")
def rtp_jitter_high(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_media:
        return
    for s in ctx.streams:
        if len(s.packets) < 50:
            continue
        j = s.jitter()
        if j > 30.0:
            yield _stream_finding(
                ctx, "RTP-JITTER-HIGH", s,
                f"{s.src} -> {s.dst} (ssrc 0x{s.ssrc:08x}) shows {j:.1f} ms interarrival "
                f"jitter over {len(s.packets)} packets")
