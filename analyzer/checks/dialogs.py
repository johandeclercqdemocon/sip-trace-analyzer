"""Dialog lifecycle checks: target refresh, mid-dialog modification, redirection.

These cover the part of RFC 3261 that governs what a dialog is allowed to do
after it exists — where the remote target comes from, which method may modify a
session and when, and what a UAC owes a 3xx or a 420. RFC 3311 is the other half
of that story: UPDATE exists precisely because a re-INVITE cannot be used before
the initial INVITE has been answered.
"""
from __future__ import annotations

from collections.abc import Iterable

from .. import sdp as sdpmod
from ..message import Message
from .base import Context, Finding, check, finding

# A capture that stops seconds after the event under test proves nothing: the
# request that would have satisfied the check may simply be past the last frame.
TRUNCATION_GUARD = 2.0


def _capture_end(ctx: Context) -> float:
    return max((m.timestamp for m in ctx.trace.messages if m.time_known), default=0.0)


def _truncated_after(ctx: Context, m: Message) -> bool:
    """True when too little of the capture follows m to conclude anything."""
    if not ctx.has_timing or not m.time_known:
        return False
    return _capture_end(ctx) - m.timestamp < TRUNCATION_GUARD


@check("SIP-2XX-NO-CONTACT")
def two_xx_without_contact(ctx: Context) -> Iterable[Finding]:
    """RFC 3261 section 12.1.1: the UAS MUST put a Contact in a dialog-establishing 2xx.

    Without it the UAC has no remote target, so the ACK and every later BYE or
    re-INVITE can only be guessed at — usually by falling back to the Request-URI
    of the INVITE, which is the proxy, not the answering UAS.
    """
    for call in ctx.calls:
        for txn in call.invite_transactions:
            reported = False
            for r in txn.finals:
                if not (r.status and 200 <= r.status < 300) or reported:
                    continue
                if r.contacts:
                    continue
                reported = True
                yield finding(
                    "SIP-2XX-NO-CONTACT", call,
                    f"the {r.status} answering {txn.method} carries no Contact header, so the "
                    f"dialog has no remote target; the ACK and any later in-dialog request "
                    f"have nowhere to go but the original Request-URI", r)


@check("SIP-REINVITE-IN-EARLY-DIALOG")
def reinvite_in_early_dialog(ctx: Context) -> Iterable[Finding]:
    """A second INVITE inside a dialog whose first INVITE is still unanswered.

    RFC 3261 section 14.1 forbids it, and RFC 3311 section 1 explains why UPDATE
    exists: a re-INVITE changes dialog state as well as session state, so it
    cannot be used to modify a session before the call has been answered. UPDATE
    is the method for an early dialog; a re-INVITE is for a confirmed one.
    """
    for call in ctx.calls:
        invites = sorted((t for t in call.invite_transactions if t.request),
                         key=lambda t: t.start)
        for i, later in enumerate(invites):
            req = later.request
            if req is None or not req.to.tag:
                continue                        # the dialog-forming INVITE itself
            for earlier in invites[:i]:
                first = earlier.request
                if first is None or earlier is later:
                    continue
                final = earlier.final
                if final is not None and final.timestamp <= req.timestamp:
                    continue                    # that transaction had finished
                if final is None and earlier.responses and not ctx.has_timing:
                    continue
                yield finding(
                    "SIP-REINVITE-IN-EARLY-DIALOG", call,
                    f"a re-INVITE was sent while the {earlier.method} on branch "
                    f"{earlier.branch or '?'} was still awaiting a final response; the dialog "
                    f"is early, so UPDATE is the method that modifies the session here",
                    first, req)
                break


def _rack_key(m: Message) -> tuple | None:
    """(RSeq, CSeq number, method) as a PRACK's RAck header names it."""
    parts = (m.get("rack") or "").split()
    if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    return (int(parts[0]), int(parts[1]), parts[2])


def _reliable_key(r: Message) -> tuple | None:
    """The same triple as seen from the reliable provisional itself."""
    rseq, (num, meth) = (r.get("rseq") or "").strip(), r.cseq
    if not rseq.isdigit() or num is None:
        return None
    return (int(rseq), num, meth)


def _is_reliable(r: Message) -> bool:
    return (r.is_provisional and r.status != 100
            and "100rel" in (r.get("require") or "").lower())


@check("SIP-RSEQ-MISSING")
def rseq_missing(ctx: Context) -> Iterable[Finding]:
    """A reliable provisional with no RSeq cannot be acknowledged at all.

    RFC 3262 section 3 requires both Require: 100rel and RSeq on the response;
    section 7.2 builds RAck from that RSeq plus the CSeq. With no RSeq the UAC
    has nothing to put in RAck, so it cannot PRACK, and the UAS keeps
    retransmitting the response until the INVITE transaction gives up.
    """
    for call in ctx.calls:
        for r in call.messages:
            if not _is_reliable(r) or (r.get("rseq") or "").strip().isdigit():
                continue
            yield finding(
                "SIP-RSEQ-MISSING", call,
                f"{r.status} demands 100rel but carries no RSeq header, so no PRACK can be "
                f"built for it; the response will be retransmitted until the transaction "
                f"times out", r)


@check("SIP-RACK-MISMATCH")
def rack_mismatch(ctx: Context) -> Iterable[Finding]:
    """A PRACK whose RAck matches no reliable provisional in the dialog.

    RAck carries the RSeq of the response being acknowledged plus the CSeq
    number and method copied from it, and the method is case sensitive
    (RFC 3262 section 7.2). Get any of the three wrong and the UAS cannot match
    the PRACK: it answers 481 and goes on retransmitting.
    """
    for call in ctx.calls:
        offered = {k for k in (_reliable_key(r) for r in call.messages
                               if _is_reliable(r)) if k}
        if not offered:
            continue
        for p in call.messages:
            if not (p.is_request and p.method == "PRACK"):
                continue
            key = _rack_key(p)
            if key in offered:
                continue
            seen = ", ".join(f"{a} {b} {c}" for a, b, c in sorted(offered))
            got = p.get("rack") or "(absent)"
            yield finding(
                "SIP-RACK-MISMATCH", call,
                f"PRACK carries RAck: {got.strip()}, which matches no reliable provisional "
                f"in this dialog (offered: {seen}); the UAS cannot match it and will keep "
                f"retransmitting", p)


@check("SIP-RSEQ-NOT-SEQUENTIAL")
def rseq_not_sequential(ctx: Context) -> Iterable[Finding]:
    """RFC 3262 section 3: each further reliable provisional adds exactly one."""
    for call in ctx.calls:
        for txn in call.invite_transactions:
            seq = [(r, int((r.get("rseq") or "0").strip()))
                   for r in txn.responses
                   if _is_reliable(r) and (r.get("rseq") or "").strip().isdigit()]
            # Retransmissions repeat an RSeq legitimately; only the steps matter.
            uniq = sorted({n for _, n in seq})
            for a, b in zip(uniq, uniq[1:], strict=False):
                if b - a == 1:
                    continue
                yield finding(
                    "SIP-RSEQ-NOT-SEQUENTIAL", call,
                    f"RSeq went from {a} to {b} on the same INVITE, a step of {b - a}; the UAC "
                    f"will not acknowledge a response it believes it has not seen the "
                    f"predecessor of", *[r for r, n in seq if n in (a, b)][:2])
                break


@check("SIP-UPDATE-NOT-SUPPORTED")
def update_not_supported(ctx: Context) -> Iterable[Finding]:
    """UPDATE sent to a peer that never advertised it (RFC 3311 section 4).

    Support is advertised in Allow. Only reported on evidence: either the peer
    published an Allow without UPDATE, or it rejected the UPDATE outright.
    """
    for call in ctx.calls:
        for txn in call.transactions_of("UPDATE"):
            req = txn.request
            if req is None:
                continue
            refusal = next((r for r in txn.finals
                            if r.status in (405, 420, 501)), None)
            allows = [m for m in call.messages
                      if m.src == req.dst and m.all("allow")]
            advertised = any("UPDATE" in a.upper() for m in allows for a in m.all("allow"))
            if advertised or (not allows and refusal is None):
                continue
            if refusal is not None:
                detail = (f"UPDATE was refused with {refusal.status} "
                          f"{refusal.reason or ''}".rstrip() +
                          "; the peer does not implement RFC 3311, so an early-dialog "
                          "session change has no mechanism on this leg")
                yield finding("SIP-UPDATE-NOT-SUPPORTED", call, detail, req, refusal)
            else:
                published = ", ".join(sorted({a.strip() for m in allows
                                              for a in m.all("allow")}))[:120]
                yield finding(
                    "SIP-UPDATE-NOT-SUPPORTED", call,
                    f"UPDATE was sent to {req.dst}, which advertised Allow: {published} "
                    f"without UPDATE; RFC 3311 section 4 makes that header the way support "
                    f"is determined", req, *allows[:1])


@check("SIP-REQUIRE-UNSUPPORTED")
def require_unsupported(ctx: Context) -> Iterable[Finding]:
    """420 Bad Extension: the request demanded an option tag the peer lacks.

    RFC 3261 section 8.2.2.3 has the UAS answer 420 and list the tags it does not
    support in Unsupported. The call fails outright unless the UAC retries
    without them, so the tag itself is the diagnosis.
    """
    for call in ctx.calls:
        for txn in call.transactions:
            bad = next((r for r in txn.finals if r.status == 420), None)
            if bad is None:
                continue
            req = txn.request
            required = sorted({t.strip() for h in (req.all("require") if req else [])
                               for t in h.split(",") if t.strip()})
            unsupported = sorted({t.strip() for h in bad.all("unsupported")
                                  for t in h.split(",") if t.strip()})
            names = ", ".join(unsupported or required) or "an unnamed extension"
            yield finding(
                "SIP-REQUIRE-UNSUPPORTED", call,
                f"{txn.method} required {names}, which the peer does not support (420 Bad "
                f"Extension); the request fails unless it is retried without the tag",
                *( [req] if req else [] ), bad)


@check("SIP-REDIRECT-NOT-FOLLOWED")
def redirect_not_followed(ctx: Context) -> Iterable[Finding]:
    """A 3xx nobody acted on (RFC 3261 section 8.1.3.4).

    The redirect carries the targets to try next. If no later request in the
    capture goes to any of them, either the UAC ignored the redirection or the
    retry left by a path the capture does not cover.
    """
    end = _capture_end(ctx)
    for call in ctx.calls:
        for txn in call.transactions:
            red = next((r for r in txn.finals
                        if r.status and 300 <= r.status < 400 and r.status != 305), None)
            if red is None or not red.contacts:
                continue
            if _truncated_after(ctx, red):
                continue
            targets = {c.host for c in red.contacts if c.host}
            if not targets:
                continue
            followed = any(
                m.is_request and m.timestamp >= red.timestamp
                and (any(t in m.request_uri for t in targets)
                     or m.dst.rsplit(":", 1)[0] in targets)
                for m in ctx.trace.messages)
            if followed:
                continue
            yield finding(
                "SIP-REDIRECT-NOT-FOLLOWED", call,
                f"{red.status} {red.reason or 'redirect'} offered "
                f"{', '.join(sorted(targets))} but nothing in the next "
                f"{end - red.timestamp:.1f}s was sent there; the redirection was dropped",
                red)


@check("SIP-EARLY-MEDIA-UNNEGOTIATED")
def early_media_unnegotiated(ctx: Context) -> Iterable[Finding]:
    """Media arriving before the answer, with no SDP in any provisional.

    The classic no-ringback fault: a gateway that sends 180 Ringing instead of
    183 Session Progress with SDP has no negotiated session to carry the tone or
    announcement, so the caller hears silence — or the UAC, having no early
    media indicator, plays local ringback over it (RFC 3960 sections 3.2, 3.3).
    """
    if not ctx.has_media:
        return
    for call in ctx.calls:
        txn = call.initial_invite
        if txn is None or txn.request is None:
            continue
        offer = sdpmod.parse(txn.request.body) if txn.request.body.strip() else None
        answered = next((r.timestamp for r in txn.finals
                         if r.status and 200 <= r.status < 300), None)
        if offer is None or answered is None:
            continue
        media = offer.audio() or (offer.media[0] if offer.media else None)
        if media is None or not media.port:
            continue
        target = f"{offer.address_for(media)}:{media.port}"
        if target.startswith(":"):
            continue
        if any(sdpmod.parse(r.body) is not None
               for r in txn.responses if r.is_provisional and r.body.strip()):
            continue                      # 183 with SDP: the session was negotiated
        early = [p for p in ctx.trace.rtp
                 if not p.is_rtcp and p.dst == target
                 and txn.start <= p.timestamp < answered]
        if len(early) < 10:
            continue
        provisionals = ", ".join(sorted({f"{r.status}" for r in txn.provisionals})) or "none"
        yield finding(
            "SIP-EARLY-MEDIA-UNNEGOTIATED", call,
            f"{len(early)} RTP packets reached the caller's offered address {target} "
            f"{answered - early[0].timestamp:.1f}s before the call was answered, but no "
            f"provisional response carried SDP (saw {provisionals}); the early media was "
            f"never negotiated and the caller may hear nothing",
            txn.request)
