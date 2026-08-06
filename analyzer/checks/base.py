"""Check framework: context, findings, and the registry."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ..message import Message
from ..model import Call, Dialog, RtpStream  # noqa: F401  (Dialog re-exported for checks)
from ..readers import Trace

T1 = 0.5                    # RFC 3261 Table 4
T2 = 4.0
T4 = 5.0
TIMER_B = TIMER_F = TIMER_H = 64 * T1
TIMER_C = 180.0
MTU_THRESHOLD = 1300        # RFC 3261 section 18.1.1


@dataclass
class Finding:
    check_id: str
    detail: str                              # what is wrong in *this* trace
    call_id: str = ""
    call_label: str = ""
    at: float = 0.0                          # timestamp of the evidence
    frames: list[int] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)   # quoted lines from the trace
    response_code: int | None = None         # the status this finding turns on, if any

    def sort_key(self) -> tuple:
        return (self.at, self.check_id)


@dataclass
class Context:
    trace: Trace
    calls: list[Call]
    streams: list[RtpStream]

    @property
    def has_timing(self) -> bool:
        return any(m.time_known for m in self.trace.messages)

    @property
    def has_media(self) -> bool:
        """Media is present as packets, so the per-packet checks can run."""
        return self.trace.has_media_layer

    @property
    def media_reports(self) -> list:
        """Media the source measured for us instead of capturing (see readers.py)."""
        return self.trace.media_reports


CheckFn = Callable[[Context], Iterable[Finding]]
REGISTRY: dict[str, CheckFn] = {}


def check(check_id: str) -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        REGISTRY[check_id] = fn
        fn.check_id = check_id                                   # type: ignore[attr-defined]
        return fn
    return deco


def finding(check_id: str, call: Call | None, detail: str, *msgs: Message,
            evidence: Iterable[str] = (), response_code: int | None = None) -> Finding:
    stamps = [m.timestamp for m in msgs if m is not None]
    return Finding(
        check_id=check_id,
        detail=detail,
        call_id=call.call_id if call else "",
        call_label=call.label() if call else "",
        at=min(stamps) if stamps else 0.0,
        frames=[m.frame for m in msgs if m is not None],
        evidence=list(evidence) or [f"{m.summary()}  ({m.src} -> {m.dst})"
                                    for m in msgs if m is not None],
        response_code=response_code,
    )


def dialog_of(call: Call, m: Message) -> Dialog | None:
    ft, tt = m.from_.tag, m.to.tag
    if not (ft and tt):
        return None
    key = frozenset({ft, tt})
    return next((d for d in call.dialogs if d.tags == key and d.leg == m.leg), None)


def same_message_forwarded(a: Message, b: Message) -> bool:
    """True when two messages are one request seen on two hops of its path.

    A correlated trace states the hop outright, which is the only reliable answer
    when the forwarder is a B2BUA: an SBC replaces the whole Via stack, so
    comparing Via depth (the test that works for a plain proxy) says these are
    unrelated requests that happen to share a Call-ID, a From tag and a CSeq —
    which is precisely the shape of the faults the pairwise checks look for.
    """
    return a.leg is not None and b.leg is not None and a.leg != b.leg


def run_all(ctx: Context, only: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for cid, fn in REGISTRY.items():
        if only and cid not in only:
            continue
        out.extend(fn(ctx))
    out.sort(key=Finding.sort_key)
    return out
