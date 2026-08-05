"""Transaction-level, authentication, registration and timer checks."""
from __future__ import annotations

import re
from collections.abc import Iterable

from ..message import Message
from ..model import Call
from .base import TIMER_B, TIMER_C, Context, Finding, check, dialog_of, finding


def _fmt(t: float) -> str:
    return f"{t:.3f}s"


def _gap(a: Message, b: Message) -> float:
    return b.timestamp - a.timestamp


def _proxy_hop(a: Message, b: Message) -> bool:
    """True when one message is the other after a proxy forwarded it.

    A proxy pushes its own Via on top of the stack and leaves the rest intact
    (RFC 3261 section 16.6 step 8), so the upstream copy's Via list is a suffix
    of the downstream copy's. Same Call-ID, same From tag, same CSeq, different
    branch: without this test every proxied request in a capture that sees both
    sides of the proxy reads as a merged fork and a CSeq reuse.
    """
    older, newer = (a, b) if len(a.vias) < len(b.vias) else (b, a)
    depth = len(older.vias)
    if depth == 0 or len(newer.vias) <= depth:
        return False
    tail = [v.branch for v in newer.vias[-depth:]]
    return all(tail) and tail == [v.branch for v in older.vias]


# ---------------------------------------------------------------- capture quality
@check("CAP-DUPLICATE-FRAMES")
def duplicate_frames(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        mine = [m for m in call.duplicates if m.duplicate_kind == "frame"]
        if not mine:
            continue
        total = len(call.messages) + len(call.duplicates)
        gaps = [abs(m.timestamp - _frame_time(ctx, m.duplicate_of)) for m in mine
                if _frame_time(ctx, m.duplicate_of) is not None]
        spread = f", {min(gaps) * 1000:.1f}-{max(gaps) * 1000:.1f} ms apart" if gaps else ""
        same_id = sum(1 for m in mine
                      if m.ip_id is not None and m.ip_id == _frame_ip_id(ctx, m.duplicate_of))
        detail = (f"{len(mine)} of {total} frames in this call are byte-identical "
                  f"repeats of an earlier frame{spread}")
        if same_id:
            detail += f"; {same_id} share the same IPv4 identification field"
        detail += ". They were excluded from transaction analysis."
        yield finding("CAP-DUPLICATE-FRAMES", call, detail, *mine[:3],
                      evidence=[f"frame {m.frame} duplicates frame {m.duplicate_of}: "
                                f"{m.summary()}" for m in mine[:4]])


@check("CAP-MULTIPLE-CAPTURE-POINTS")
def multiple_capture_points(ctx: Context) -> Iterable[Finding]:
    """The same packet recorded on both sides of a NAT, ALG or proxy."""
    for call in ctx.calls:
        mine = [m for m in call.duplicates if m.duplicate_kind == "capture-point"]
        if not mine:
            continue
        total = len(call.messages) + len(call.duplicates)
        pairs = " and ".join(f"{a} ↔ {b}" for a, b in ctx.trace.nat_map[:3]) or "—"
        rewritten = sum(1 for m in mine
                        if _frame_raw(ctx, m.duplicate_of) not in (None, m.raw))
        detail = (f"{len(mine)} of {total} messages in this call are the same packet "
                  f"seen a second time at another point on its path, not a "
                  f"retransmission. Addresses that are the same host either side of "
                  f"the translation: {pairs}")
        if rewritten:
            detail += (f". {rewritten} of them were rewritten in transit, so an ALG "
                       f"is modifying SIP, not just the IP header")
        detail += ". The second view was excluded from transaction analysis."
        yield finding("CAP-MULTIPLE-CAPTURE-POINTS", call, detail, *mine[:3],
                      evidence=[f"frame {m.frame} is frame {m.duplicate_of} seen again: "
                                f"{m.summary()} ({m.src} -> {m.dst})" for m in mine[:4]])


def _frame_raw(ctx: Context, frame: int | None) -> str | None:
    return next((m.raw for m in ctx.trace.messages if m.frame == frame), None)


def _frame_time(ctx: Context, frame: int | None) -> float | None:
    return next((m.timestamp for m in ctx.trace.messages if m.frame == frame), None)


def _frame_ip_id(ctx: Context, frame: int | None) -> int | None:
    return next((m.ip_id for m in ctx.trace.messages if m.frame == frame), None)


# ---------------------------------------------------------------- ACK handling
@check("SIP-ACK-MISSING")
def ack_missing(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for txn in call.invite_transactions:
            reported: set[tuple] = set()
            for ok in txn.finals:
                if ok.status is None or not 200 <= ok.status < 300:
                    continue
                # Retransmissions of the same 2xx are one problem, not several.
                ident = (ok.cseq_number, ok.to.tag)
                if ident in reported:
                    continue
                reported.add(ident)
                # The 2xx ACK is a separate transaction: match on Call-ID and CSeq number.
                num = ok.cseq_number
                acked = any(
                    m.is_request and m.method == "ACK" and m.cseq_number == num
                    and (not ok.to.tag or m.to.tag == ok.to.tag)
                    for m in call.messages
                )
                if acked:
                    continue
                d = dialog_of(call, ok)
                detail = (f"200 OK for INVITE (CSeq {num}) was never acknowledged"
                          f"{f' in dialog {d.label()}' if d else ''}")
                if ctx.has_timing:
                    tail = call.end - ok.timestamp
                    detail += (f"; the trace continues {_fmt(tail)} after it, so the ACK is "
                               f"absent rather than merely outside the capture"
                               if tail > 1.0 else
                               "; the capture ends less than a second later, so the ACK may "
                               "simply be beyond it")
                contact = ok.contacts[0].uri if ok.contacts else "(none)"
                yield finding("SIP-ACK-MISSING", call, detail, ok,
                              evidence=[f"200 OK from {ok.src} to {ok.dst}",
                                        f"Contact in the 200 OK: {contact}"])


@check("SIP-2XX-RETRANSMIT")
def two_xx_retransmit(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for txn in call.invite_transactions:
            for group in txn.response_retransmissions():
                if not (200 <= (group[0].status or 0) < 300):
                    continue
                gaps = [_fmt(_gap(a, b)) for a, b in zip(group, group[1:], strict=False)]
                yield finding(
                    "SIP-2XX-RETRANSMIT", call,
                    f"{group[0].status} retransmitted {len(group) - 1} time(s) "
                    f"(intervals {', '.join(gaps)}) - Timer G backoff, meaning no ACK arrived",
                    *group)


@check("SIP-NON-2XX-NOT-ACKED")
def non_2xx_not_acked(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for txn in call.invite_transactions:
            finals = [f for f in txn.finals if (f.status or 0) >= 300]
            if not finals or txn.acks:
                continue
            f0 = finals[0]
            detail = (f"{f0.status} {f0.reason} was not acknowledged; a non-2xx final must be "
                      f"ACKed hop-by-hop on the INVITE's own branch ({txn.branch or 'n/a'})")
            yield finding("SIP-NON-2XX-NOT-ACKED", call, detail, f0)


# ---------------------------------------------------------------- retransmission
@check("SIP-INVITE-RETRANSMIT-NO-RESPONSE")
def invite_retransmit_no_response(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for txn in call.invite_transactions:
            if len(txn.requests) < 2 or txn.responses:
                continue
            gaps = [_fmt(_gap(a, b)) for a, b in zip(txn.requests, txn.requests[1:], strict=False)]
            first = txn.requests[0]
            yield finding(
                "SIP-INVITE-RETRANSMIT-NO-RESPONSE", call,
                f"INVITE to {first.dst} sent {len(txn.requests)} times with no response of any "
                f"class (intervals {', '.join(gaps)})",
                *txn.requests[:4])


@check("SIP-NO-100-TRYING")
def no_100_trying(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_timing:
        return
    for call in ctx.calls:
        for txn in call.invite_transactions:
            req = txn.request
            if req is None or req.transport != "UDP" or len(txn.requests) < 2:
                continue
            first_1xx = next((r for r in txn.provisionals), None)
            if first_1xx is not None and _gap(req, first_1xx) <= 0.5:
                continue
            delay = _gap(req, first_1xx) if first_1xx else None
            detail = (f"no provisional response within 500 ms of the INVITE to {req.dst}"
                      + (f" (first 1xx after {_fmt(delay)})" if delay else " (none at all)")
                      + f"; the UAC retransmitted {len(txn.requests) - 1} time(s)")
            yield finding("SIP-NO-100-TRYING", call, detail, req)


@check("SIP-TIMER-B-TIMEOUT")
def timer_b_timeout(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_timing:
        return
    for call in ctx.calls:
        for txn in call.invite_transactions:
            if len(txn.requests) < 2 or txn.finals:
                continue
            span = txn.requests[-1].timestamp - txn.requests[0].timestamp
            if span < TIMER_B * 0.6:
                continue
            yield finding(
                "SIP-TIMER-B-TIMEOUT", call,
                f"INVITE transaction retransmitted for {_fmt(span)} with no final response; "
                f"Timer B fires at {TIMER_B:g}s and the UAC then reports 408 locally",
                txn.requests[0], txn.requests[-1])


@check("SIP-TIMER-C-CANCEL")
def timer_c_cancel(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_timing:
        return
    for call in ctx.calls:
        for txn in call.invite_transactions:
            if not txn.provisionals:
                continue
            last_prov = txn.provisionals[-1]
            c487 = next((r for r in txn.finals if r.status == 487), None)
            if c487 is None:
                continue
            stalled = _gap(last_prov, c487)
            if stalled < TIMER_C:
                continue
            cancels = [m for m in call.messages if m.is_request and m.method == "CANCEL"]
            origin = cancels[0].src if cancels else "an upstream element"
            yield finding(
                "SIP-TIMER-C-CANCEL", call,
                f"the call sat in {last_prov.status} for {_fmt(stalled)} before being "
                f"terminated by {origin}; proxy Timer C expires after {TIMER_C:g}s",
                last_prov, c487)


# ---------------------------------------------------------------- CANCEL
@check("SIP-487-WITHOUT-CANCEL")
def rt_487_without_cancel(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for txn in call.invite_transactions:
            r487 = next((r for r in txn.finals if r.status == 487), None)
            if r487 is None:
                continue
            if any(m.is_request and m.method == "CANCEL" and m.branch == txn.branch
                   for m in call.messages):
                continue
            yield finding(
                "SIP-487-WITHOUT-CANCEL", call,
                f"487 on branch {txn.branch or 'n/a'} with no CANCEL for that branch in the "
                f"capture; it was generated upstream (forking, or proxy Timer C)",
                r487)


@check("SIP-CANCEL-RACE")
def cancel_race(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        cancels = [m for m in call.messages if m.is_request and m.method == "CANCEL"]
        for c in cancels:
            txn = next((t for t in call.invite_transactions if t.branch == c.branch), None)
            if txn is None:
                continue
            ok = next((r for r in txn.finals if 200 <= (r.status or 0) < 300), None)
            if ok is not None and (not ctx.has_timing or c.timestamp >= ok.timestamp):
                yield finding(
                    "SIP-CANCEL-RACE", call,
                    "CANCEL was sent after the INVITE had already been answered 2xx; it has no "
                    "effect and the caller must ACK and then send BYE",
                    ok, c)
                continue
            # A 481 to the CANCEL says the same thing from the other direction.
            for txn2 in call.transactions_of("CANCEL"):
                if txn2.branch == c.branch and any(r.status == 481 for r in txn2.finals):
                    yield finding("SIP-CANCEL-RACE", call,
                                  "CANCEL was rejected 481: the INVITE transaction had already "
                                  "completed", c)


# ---------------------------------------------------------------- dialog integrity
@check("SIP-491-GLARE")
def glare(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        r491 = [m for m in call.messages if m.status == 491]
        for r in r491:
            yield finding("SIP-491-GLARE", call,
                          f"491 Request Pending to an in-dialog INVITE (CSeq {r.cseq_number}): "
                          f"both ends modified the session at once", r)
        if len(r491) > 1:
            yield finding("SIP-491-GLARE", call,
                          f"{len(r491)} separate 491s in this dialog - one side is not applying "
                          f"the randomised backoff", *r491)


@check("SIP-CSEQ-NOT-INCREMENTED")
def cseq_not_incremented(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        seen: dict[tuple, Message] = {}
        for m in call.messages:
            if not m.is_request or m.method in ("ACK", "CANCEL"):
                continue
            num, meth = m.cseq
            if num is None:
                continue
            key = (m.from_.tag, m.to.tag, num, meth)
            prev = seen.get(key)
            if prev is None:
                seen[key] = m
                continue
            if (prev.branch and m.branch and prev.branch != m.branch
                    and not _proxy_hop(prev, m)):
                yield finding(
                    "SIP-CSEQ-NOT-INCREMENTED", call,
                    f"two different {meth} transactions reuse CSeq {num} in the same dialog "
                    f"(branches {prev.branch} and {m.branch})", prev, m)


@check("SIP-MERGED-REQUEST")
def merged_request(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        seen: dict[tuple, Message] = {}
        for m in call.messages:
            if not m.is_request or m.to.tag:
                continue
            num, meth = m.cseq
            key = (m.from_.tag, num, meth)
            prev = seen.get(key)
            if prev is None:
                seen[key] = m
                continue
            # RFC 3261 section 8.2.2.2 is about two copies reaching the same UAS.
            # Different destinations mean the capture simply saw both sides of a
            # proxy forwarding the request onward, which is not a merge.
            if prev.branch != m.branch and prev.dst == m.dst and not _proxy_hop(prev, m):
                yield finding(
                    "SIP-MERGED-REQUEST", call,
                    f"the same {meth} (From tag {m.from_.tag}, CSeq {num}) arrived on two "
                    f"different branches - a forked request merging at the UAS", prev, m)


@check("SIP-BRANCH-NOT-RFC3261")
def branch_not_rfc3261(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        reported: set[str] = set()
        for m in call.messages:
            if not m.is_request:
                continue
            v = m.top_via
            if v is None or v.is_rfc3261:
                continue
            if v.host in reported:
                continue
            reported.add(v.host)
            yield finding(
                "SIP-BRANCH-NOT-RFC3261", call,
                f"{m.method} from {v.host} has branch={v.branch or '(absent)'}, which lacks the "
                f"z9hG4bK magic cookie; transaction matching falls back to RFC 2543 rules", m)


@check("SIP-BRANCH-REUSED")
def branch_reused(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        by_branch: dict[str, list[Message]] = {}
        for m in call.messages:
            if m.is_request and m.branch:
                by_branch.setdefault(m.branch, []).append(m)
        for branch, msgs in by_branch.items():
            # ACK and CANCEL legitimately share the INVITE's branch.
            distinct = {(m.method, m.request_uri) for m in msgs
                        if m.method not in ("ACK", "CANCEL")}
            if len(distinct) > 1:
                yield finding(
                    "SIP-BRANCH-REUSED", call,
                    f"branch {branch} is used by {len(distinct)} distinct transactions: "
                    + ", ".join(f"{meth} {uri}" for meth, uri in sorted(distinct)),
                    *msgs[:4])


# ---------------------------------------------------------------- authentication
_AUTH_PARAM = re.compile(r'(\w+)\s*=\s*"?([^",]+)"?')


def _auth_params(value: str) -> dict[str, str]:
    return {k.lower(): v for k, v in _AUTH_PARAM.findall(value or "")}


@check("SIP-AUTH-LOOP")
def auth_loop(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        by_method: dict[str, list[Message]] = {}
        for m in call.messages:
            if m.status in (401, 407):
                by_method.setdefault(m.method, []).append(m)
        for meth, challenges in by_method.items():
            fresh = [c for c in challenges
                     if not _auth_params(c.get("www-authenticate") or
                                         c.get("proxy-authenticate") or "").get("stale",
                                                                                "").lower()
                     .startswith("true")]
            if len(fresh) < 2:
                continue
            succeeded = any(200 <= (m.status or 0) < 300 and m.method == meth
                            for m in call.messages)
            realms = {_auth_params(c.get("www-authenticate") or
                                   c.get("proxy-authenticate") or "").get("realm", "?")
                      for c in fresh}
            detail = (f"{meth} was challenged {len(fresh)} times "
                      f"(realm{'s' if len(realms) > 1 else ''} {', '.join(sorted(realms))})"
                      f"{' and never succeeded' if not succeeded else ''}")
            yield finding("SIP-AUTH-LOOP", call, detail, *fresh[:4])


@check("SIP-AUTH-STALE-NONCE")
def auth_stale(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for m in call.messages:
            if m.status not in (401, 407):
                continue
            hdr = m.get("www-authenticate") or m.get("proxy-authenticate") or ""
            if _auth_params(hdr).get("stale", "").lower().startswith("true"):
                yield finding("SIP-AUTH-STALE-NONCE", call,
                              f"{m.status} to {m.method} carries stale=true: the nonce aged out, "
                              f"this is not a credential failure", m)


@check("SIP-AUTH-WRONG-HEADER")
def auth_wrong_header(ctx: Context) -> Iterable[Finding]:
    """A 407 answered with Authorization (or a 401 with Proxy-Authorization) never succeeds."""
    for call in ctx.calls:
        for m in call.messages:
            if m.status not in (401, 407):
                continue
            retry = next((r for r in call.messages
                          if r.is_request and r.method == m.method
                          and (r.cseq_number or 0) > (m.cseq_number or 0)), None)
            if retry is None:
                continue
            if m.status == 407 and retry.has("authorization") and not retry.has(
                    "proxy-authorization"):
                yield finding("SIP-AUTH-WRONG-HEADER", call,
                              "the proxy challenged with 407 but the retry carried credentials "
                              "in Authorization instead of Proxy-Authorization", m, retry)
            elif m.status == 401 and retry.has("proxy-authorization") and not retry.has(
                    "authorization"):
                yield finding("SIP-AUTH-WRONG-HEADER", call,
                              "the UAS challenged with 401 but the retry carried credentials in "
                              "Proxy-Authorization instead of Authorization", m, retry)


# ---------------------------------------------------------------- registration
@check("SIP-REGISTER-423-LOOP")
def register_423(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        r423 = [m for m in call.messages if m.status == 423]
        if not r423:
            continue
        min_exp = r423[0].get("min-expires")
        if len(r423) > 1:
            yield finding("SIP-REGISTER-423-LOOP", call,
                          f"REGISTER rejected 423 {len(r423)} times; the client is not honouring "
                          f"Min-Expires ({min_exp})", *r423[:3])
            continue
        later = [m for m in call.messages
                 if m.is_request and m.method == "REGISTER"
                 and m.timestamp >= r423[0].timestamp]
        for reg in later:
            exp = reg.get("expires")
            if exp and min_exp and exp.isdigit() and min_exp.isdigit() and \
                    int(exp) < int(min_exp):
                yield finding("SIP-REGISTER-423-LOOP", call,
                              f"the retry after 423 still asks for Expires {exp}, below the "
                              f"registrar's Min-Expires {min_exp}", r423[0], reg)


@check("SIP-REGISTER-FLAPPING")
def register_flapping(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_timing:
        return
    by_aor: dict[str, list[Message]] = {}
    for call in ctx.calls:
        for m in call.messages:
            if m.is_request and m.method == "REGISTER":
                by_aor.setdefault(m.to.uri or m.to.raw, []).append(m)
    for aor, regs in by_aor.items():
        if len(regs) < 3:
            continue
        regs.sort(key=lambda m: m.timestamp)
        granted = None
        for m in regs:
            e = m.get("expires")
            if e and e.isdigit():
                granted = int(e)
        intervals = [b.timestamp - a.timestamp for a, b in zip(regs, regs[1:], strict=False)]
        typical = sorted(intervals)[len(intervals) // 2]
        call_ids = {m.call_id for m in regs}
        if granted and typical < granted / 3 and len(call_ids) > 1:
            yield finding(
                "SIP-REGISTER-FLAPPING", None,
                f"{aor} re-registered every ~{typical:.0f}s against a granted expiry of "
                f"{granted}s, using {len(call_ids)} different Call-IDs",
                *regs[:3])


# ---------------------------------------------------------------- session timers
@check("SIP-SESSION-TIMER-422-LOOP")
def session_timer_422(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        r422 = [m for m in call.messages if m.status == 422]
        if not r422:
            continue
        min_se = r422[0].get("min-se")
        if len(r422) > 1:
            yield finding("SIP-SESSION-TIMER-422-LOOP", call,
                          f"{len(r422)} x 422 in one Call-ID; the UAC is not adopting Min-SE "
                          f"({min_se})", *r422[:3])
            continue
        for inv in call.messages:
            if not (inv.is_request and inv.method == "INVITE"
                    and inv.timestamp >= r422[0].timestamp):
                continue
            se = (inv.get("session-expires") or "").split(";")[0].strip()
            if se.isdigit() and min_se and min_se.isdigit() and int(se) < int(min_se):
                yield finding("SIP-SESSION-TIMER-422-LOOP", call,
                              f"the retry after 422 still offers Session-Expires {se}, below the "
                              f"peer's Min-SE {min_se}", r422[0], inv)


@check("SIP-SESSION-TIMER-NO-REFRESH")
def session_timer_no_refresh(ctx: Context) -> Iterable[Finding]:
    if not ctx.has_timing:
        return
    for call in ctx.calls:
        for d in call.dialogs:
            if d.establishing is None:
                continue
            se_raw = d.establishing.get("session-expires")
            if not se_raw:
                continue
            head = se_raw.split(";")[0].strip()
            if not head.isdigit():
                continue
            interval = int(head)
            refresher = next((p.split("=")[1] for p in se_raw.split(";")[1:]
                              if p.strip().lower().startswith("refresher=")), "?")
            answered = d.establishing.timestamp
            refreshes = [m for m in d.messages
                         if m.is_request and m.method in ("INVITE", "UPDATE")
                         and m.timestamp > answered]
            observed = d.end - answered
            if refreshes or observed < interval * 0.75:
                continue
            ended_by = d.terminator
            detail = (f"Session-Expires {interval}s (refresher={refresher}) was negotiated but no "
                      f"re-INVITE or UPDATE followed in {observed:.0f}s of dialog")
            if ended_by is not None:
                detail += f"; the dialog was torn down by a BYE from {ended_by.src}"
            yield finding("SIP-SESSION-TIMER-NO-REFRESH", call, detail,
                          d.establishing, *( [ended_by] if ended_by else [] ))


# ---------------------------------------------------------------- 100rel / PRACK
@check("SIP-PRACK-MISSING")
def prack_missing(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for m in call.messages:
            if not m.is_provisional or "100rel" not in (m.get("require") or "").lower():
                continue
            rseq = m.get("rseq")
            if not rseq:
                continue
            pracked = any(
                p.is_request and p.method == "PRACK"
                and (p.get("rack") or "").split()[:1] == [rseq.strip()]
                for p in call.messages)
            if not pracked:
                yield finding("SIP-PRACK-MISSING", call,
                              f"{m.status} sent reliably (RSeq {rseq.strip()}) was never PRACKed; "
                              f"the UAS will retransmit it with exponential backoff", m)


@check("SIP-100REL-UNSUPPORTED")
def rel100_unsupported(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for m in call.messages:
            if m.status != 420:
                continue
            unsup = ", ".join(m.all("unsupported")) or "(not named)"
            yield finding("SIP-100REL-UNSUPPORTED", call,
                          f"420 Bad Extension rejecting Require: {unsup}", m)


# ---------------------------------------------------------------- transfer
@check("SIP-REFER-NO-NOTIFY")
def refer_no_notify(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for txn in call.transactions_of("REFER"):
            if not any(200 <= (r.status or 0) < 300 for r in txn.finals):
                continue
            req = txn.request
            notifies = [m for m in call.messages
                        if m.is_request and m.method == "NOTIFY"
                        and "refer" in (m.get("event") or "").lower()]
            if not notifies:
                yield finding("SIP-REFER-NO-NOTIFY", call,
                              f"REFER to {req.get('refer-to') if req else '?'} was accepted but "
                              f"no NOTIFY reported the outcome", req or txn.finals[0])


@check("SIP-REPLACES-NO-DIALOG")
def replaces_no_dialog(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for txn in call.invite_transactions:
            req = txn.request
            if req is None or not req.has("replaces"):
                continue
            bad = next((r for r in txn.finals if r.status in (481, 603)), None)
            if bad is not None:
                yield finding("SIP-REPLACES-NO-DIALOG", call,
                              f"INVITE with Replaces: {req.get('replaces')} was rejected "
                              f"{bad.status}; the target dialog was not found", req, bad)


# ---------------------------------------------------------------- non-INVITE failures
# ACK carries no response of its own and CANCEL's outcome is the INVITE's, so
# neither can fail as a transaction; INVITE has the whole catalog above.
_NON_INVITE_EXEMPT = frozenset({"INVITE", "ACK", "CANCEL"})

# Codes a dedicated check already reports. Repeating them here would say the same
# thing twice with less detail.
_COVERED_ELSEWHERE = {420: "SIP-100REL-UNSUPPORTED", 422: "SIP-SESSION-TIMER-422-LOOP",
                      423: "SIP-REGISTER-423-LOOP", 481: "SIP-IN-DIALOG-481",
                      488: "SDP-CODEC-MISMATCH", 491: "SIP-491-GLARE"}

# The RFC that defines the method, cited alongside RFC 3261 section 21 on the
# finding itself. Everything absent here is defined by RFC 3261.
_METHOD_RFC = {"SUBSCRIBE": "RFC 3265", "NOTIFY": "RFC 3265", "PUBLISH": "RFC 3903",
               "REFER": "RFC 3515", "UPDATE": "RFC 3311", "PRACK": "RFC 3262"}


def _credentialed_retry(call: Call, method: str, challenge: Message) -> Message | None:
    """The request that answers a challenge: same method, later, carrying credentials.

    Matched on frame order rather than on time, because a text log may carry no
    usable timestamps at all, and on CSeq the retry is only required to be higher
    (RFC 3261 section 22.2), not adjacent.
    """
    return next((m for m in call.messages
                 if m.is_request and m.method == method and m.frame > challenge.frame
                 and (m.has("authorization") or m.has("proxy-authorization"))), None)


@check("SIP-NON-INVITE-FAILED")
def non_invite_failed(ctx: Context) -> Iterable[Finding]:
    """A REGISTER, SUBSCRIBE, PUBLISH or other non-INVITE that ended 4xx/5xx.

    Everything above this is INVITE- and media-centric, so an ordinary
    wrong-password registration - challenged once, refused once, and then given up
    on - passed the entire catalog silently. SIP-AUTH-LOOP needs the challenge to
    repeat, and it does not repeat when the client stops trying.

    A client that keeps retrying a request its peer will never accept opens a new
    Call-ID each time, so the same refusal is grouped across the whole trace rather
    than reported once per attempt: what matters is that this AoR and this event
    package are refused, not that the phone asked nine times.
    """
    groups: dict[tuple, list[tuple[Call, Message | None, Message]]] = {}
    for call in ctx.calls:
        for txn in call.transactions:
            if txn.method in _NON_INVITE_EXEMPT or not txn.finals:
                continue
            final = txn.finals[0]
            code = final.status or 0
            if not 400 <= code < 600 or code in _COVERED_ELSEWHERE:
                continue

            if code in (401, 407):
                # One challenge answered with credentials is digest auth working as
                # designed; a challenge that keeps coming back is SIP-AUTH-LOOP's
                # finding. Only a challenge nobody ever answered belongs here.
                if _credentialed_retry(call, txn.method, final) is not None:
                    continue
                if sum(1 for m in call.messages
                       if m.status in (401, 407) and m.method == txn.method) > 1:
                    continue
                # A capture that stops on the challenge simply ended too early.
                if ctx.has_timing and call.end - final.timestamp <= 1.0:
                    continue

            req = txn.request
            target = (req.to.uri if req else "") or final.to.uri or final.to.raw
            event = ((req.get("event") if req else None) or "").split(";")[0].strip()
            groups.setdefault((txn.method, code, target, event), []).append((call, req, final))

    for (method, code, target, event), members in groups.items():
        calls = {c.call_id for c, _, _ in members}
        first_call, _, first_final = members[0]
        reason = first_final.reason
        subject = f"{method} to {target}" + (f" for event '{event}'" if event else "")

        if len(members) == 1:
            detail = f"{subject} ended in {code} {reason}".rstrip()
        else:
            span = ""
            if ctx.has_timing:
                stamps = [fin.timestamp for _, _, fin in members]
                span = f" over {_fmt(max(stamps) - min(stamps))}"
            spread = f", across {len(calls)} Call-IDs" if len(calls) > 1 else ""
            detail = (f"{subject} was refused {code} {reason} "
                      f"{len(members)} times{span}{spread}").rstrip()
        if code in (401, 407):
            detail += ("; no retry carrying credentials followed, so the transaction was "
                       "abandoned at the challenge")
        else:
            detail += ", a final refusal the transaction never recovered from"
        # The same Call-ID succeeding on the same method later means the refusal was a
        # step on the way rather than the end of it - worth saying, not worth hiding.
        recovered = {c.call_id for c, _, _ in members
                     if any(200 <= (r.status or 0) < 300
                            for t in c.transactions_of(method) for r in t.finals)}
        if recovered:
            detail += (f". A {method} in the same Call-ID did succeed, so the refusal was "
                       f"not the end of the story" if len(calls) == 1 else
                       f". {len(recovered)} of the {len(calls)} Call-IDs did see a "
                       f"{method} succeed")
        cite = _METHOD_RFC.get(method)
        detail += (f" ({method} is defined by {cite}; RFC 3261 section 21 gives the "
                   f"response code)" if cite else
                   " (RFC 3261 section 21 gives the response code)")

        evidence = [f"{m.summary()}  ({m.src} -> {m.dst})"
                    for _, req, fin in members[:2] for m in (req, fin) if m]
        for hdr in ("warning", "reason"):
            if first_final.get(hdr):
                evidence.append(f"{hdr.title()}: {first_final.get(hdr)}")
        msgs = [m for _, req, fin in members for m in (req, fin) if m]
        yield finding("SIP-NON-INVITE-FAILED",
                      first_call if len(calls) == 1 else None,
                      detail, *msgs, evidence=evidence, response_code=code)


# ---------------------------------------------------------------- generic 481
@check("SIP-IN-DIALOG-481")
def in_dialog_481(ctx: Context) -> Iterable[Finding]:
    for call in ctx.calls:
        for m in call.messages:
            if m.status != 481 or m.method in ("CANCEL",):
                continue
            d = dialog_of(call, m)
            known = " (the dialog is present in this capture)" if d and d.confirmed else \
                    " (no confirmed dialog for these tags in this capture)"
            yield finding("SIP-IN-DIALOG-481", call,
                          f"{m.method} was answered 481: the peer has no such dialog{known}", m)
