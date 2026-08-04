"""Reconstruct transactions, dialogs and calls from a flat list of messages."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import sdp as sdpmod
from .message import Message, NameAddr
from .readers import RtpPacket, Trace


@dataclass
class Transaction:
    branch: str
    method: str
    key: tuple
    requests: list[Message] = field(default_factory=list)     # [0] is the original
    responses: list[Message] = field(default_factory=list)
    acks: list[Message] = field(default_factory=list)         # non-2xx ACK only

    @property
    def request(self) -> Message | None:
        return self.requests[0] if self.requests else None

    @property
    def retransmissions(self) -> list[Message]:
        return self.requests[1:]

    @property
    def final(self) -> Message | None:
        return next((r for r in self.responses if r.is_final), None)

    @property
    def finals(self) -> list[Message]:
        return [r for r in self.responses if r.is_final]

    @property
    def provisionals(self) -> list[Message]:
        return [r for r in self.responses if r.is_provisional]

    @property
    def start(self) -> float:
        return self.requests[0].timestamp if self.requests else 0.0

    @property
    def end(self) -> float:
        stamps = [m.timestamp for m in self.requests + self.responses + self.acks]
        return max(stamps) if stamps else 0.0

    def response_retransmissions(self) -> list[list[Message]]:
        """Groups of identical final responses (same status and to-tag), size > 1."""
        groups: dict[tuple, list[Message]] = {}
        for r in self.finals:
            groups.setdefault((r.status, r.to.tag), []).append(r)
        return [g for g in groups.values() if len(g) > 1]


@dataclass
class SdpExchange:
    """One offer/answer pair, with where each half was carried."""
    offer: Message
    offer_sdp: sdpmod.Sdp
    answer: Message | None = None
    answer_sdp: sdpmod.Sdp | None = None

    @property
    def complete(self) -> bool:
        return self.answer_sdp is not None


@dataclass
class Dialog:
    call_id: str
    tags: frozenset
    caller: str = ""            # 'ip:port' that sent the dialog-forming request
    callee: str = ""
    messages: list[Message] = field(default_factory=list)
    early_responses: list[Message] = field(default_factory=list)
    establishing: Message | None = None      # the 2xx that confirmed it
    invite: Message | None = None
    terminator: Message | None = None        # BYE, or the final that killed it
    record_route_early: list[str] = field(default_factory=list)
    record_route_final: list[str] = field(default_factory=list)
    remote_contacts: dict[str, NameAddr] = field(default_factory=dict)  # tag -> Contact
    exchanges: list[SdpExchange] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        return self.establishing is not None

    @property
    def start(self) -> float:
        return self.messages[0].timestamp if self.messages else 0.0

    @property
    def answered_at(self) -> float | None:
        return self.establishing.timestamp if self.establishing else None

    @property
    def end(self) -> float:
        return self.messages[-1].timestamp if self.messages else 0.0

    @property
    def negotiated(self) -> SdpExchange | None:
        """The most recent completed offer/answer."""
        return next((e for e in reversed(self.exchanges) if e.complete), None)

    def label(self) -> str:
        if self.invite:
            return f"{self.invite.from_.user or '?'} -> {self.invite.to.user or '?'}"
        return self.call_id[:24]


@dataclass
class Call:
    call_id: str
    messages: list[Message] = field(default_factory=list)      # duplicates excluded
    duplicates: list[Message] = field(default_factory=list)    # kept for reporting
    transactions: list[Transaction] = field(default_factory=list)
    dialogs: list[Dialog] = field(default_factory=list)

    @property
    def start(self) -> float:
        return self.messages[0].timestamp if self.messages else 0.0

    @property
    def end(self) -> float:
        return self.messages[-1].timestamp if self.messages else 0.0

    @property
    def invite_transactions(self) -> list[Transaction]:
        return [t for t in self.transactions if t.method == "INVITE"]

    @property
    def initial_invite(self) -> Transaction | None:
        inv = [t for t in self.invite_transactions if t.request and not t.request.to.tag]
        return inv[0] if inv else (self.invite_transactions[0]
                                   if self.invite_transactions else None)

    def transactions_of(self, method: str) -> list[Transaction]:
        return [t for t in self.transactions if t.method == method]

    def label(self) -> str:
        for d in self.dialogs:
            if d.invite:
                return d.label()
        first = self.messages[0] if self.messages else None
        return f"{first.method} {first.from_.user}" if first else self.call_id[:24]

    @property
    def outcome(self) -> str:
        inv = self.initial_invite
        if inv is None:
            return "no INVITE"
        finals = inv.finals
        if not finals:
            return "no final response"
        best = min(f.status for f in finals)
        if best < 300:
            return "answered"
        return f"failed {best}"


@dataclass
class RtpStream:
    src: str
    dst: str
    ssrc: int
    packets: list[RtpPacket] = field(default_factory=list)

    @property
    def payload_types(self) -> set[int]:
        return {p.payload_type for p in self.packets}

    @property
    def start(self) -> float:
        return self.packets[0].timestamp if self.packets else 0.0

    @property
    def end(self) -> float:
        return self.packets[-1].timestamp if self.packets else 0.0

    @property
    def duration(self) -> float:
        return self.end - self.start

    def sequence_gaps(self) -> list[tuple[int, int]]:
        """(after_seq, missing_count) for each gap, tolerating reordering."""
        seqs = sorted({p.seq for p in self.packets})
        gaps = []
        for a, b in zip(seqs, seqs[1:], strict=False):
            if b - a > 1:
                gaps.append((a, b - a - 1))
        return gaps

    @property
    def lost(self) -> int:
        return sum(n for _, n in self.sequence_gaps())

    @property
    def expected(self) -> int:
        seqs = [p.seq for p in self.packets]
        return (max(seqs) - min(seqs) + 1) if seqs else 0

    @property
    def loss_ratio(self) -> float:
        return self.lost / self.expected if self.expected else 0.0

    def jitter(self) -> float:
        """Interarrival jitter in milliseconds, as defined in RFC 3550 section 6.4.1."""
        clock = 8000.0
        j = 0.0
        prev = None
        for p in sorted(self.packets, key=lambda x: x.seq):
            if prev is not None:
                d = ((p.timestamp - prev.timestamp) -
                     (p.rtp_ts - prev.rtp_ts) / clock)
                j += (abs(d) - j) / 16.0
            prev = p
        return j * 1000.0


def _transaction_key(m: Message) -> tuple:
    """Match by Via branch where possible; fall back for RFC 2543 style traces."""
    branch = m.branch
    method = m.method
    # A 2xx ACK is its own transaction; a non-2xx ACK belongs to the INVITE's.
    if m.is_request and method == "ACK":
        method = "INVITE"
    if branch and branch.startswith("z9hG4bK"):
        # Branch plus CSeq method, per RFC 3261 section 17.1.3. The Via sent-by is
        # deliberately excluded: a NATed UA's response carries a rewritten sent-by.
        return ("b", branch, method)
    num, _ = m.cseq
    return ("l", m.call_id, num, method, m.from_.tag)


def build(trace: Trace) -> tuple[list[Call], list[RtpStream]]:
    calls: dict[str, Call] = {}
    txns: dict[tuple, Transaction] = {}

    for m in trace.messages:
        call = calls.setdefault(m.call_id, Call(call_id=m.call_id))

        # A frame the capture recorded twice is not a second message. Keeping it
        # out of the call entirely is what makes every check correct by default:
        # otherwise anything counting messages (auth challenges, 491s, CSeq reuse)
        # sees each one twice. The ladder reads trace.messages, so it still shows
        # them, and the duplicate checks read trace.messages too.
        if m.is_duplicate:
            call.duplicates.append(m)
            continue
        call.messages.append(m)

        key = _transaction_key(m)
        txn = txns.get(key)
        if txn is None:
            txn = Transaction(branch=m.branch or "", method=key[-2] if key[0] == "l" else key[2],
                              key=key)
            txns[key] = txn
            call.transactions.append(txn)
        if m.is_request:
            if m.method == "ACK" and txn.method == "INVITE":
                txn.acks.append(m)
            else:
                txn.requests.append(m)
        else:
            txn.responses.append(m)

    for call in calls.values():
        _build_dialogs(call)

    return list(calls.values()), _build_streams(trace.rtp)


def _dialog_key(m: Message) -> frozenset | None:
    ft, tt = m.from_.tag, m.to.tag
    return frozenset({ft, tt}) if ft and tt else None


def _build_dialogs(call: Call) -> None:
    dialogs: dict[frozenset, Dialog] = {}
    for m in call.messages:
        if m.is_duplicate:
            continue
        key = _dialog_key(m)
        if key is None:
            continue
        d = dialogs.get(key)
        if d is None:
            d = Dialog(call_id=call.call_id, tags=key)
            dialogs[key] = d
            call.dialogs.append(d)
        d.messages.append(m)

        if m.is_request and m.method == "INVITE" and d.invite is None:
            d.invite = m
            d.caller, d.callee = m.src, m.dst
        if m.is_provisional and m.method == "INVITE":
            d.early_responses.append(m)
            if not d.record_route_early:
                d.record_route_early = m.all("record-route")
            if not d.caller:
                d.caller, d.callee = m.dst, m.src
        if m.status is not None and 200 <= m.status < 300 and m.method == "INVITE":
            if d.establishing is None:
                d.establishing = m
                d.record_route_final = m.all("record-route")
            if not d.caller:
                d.caller, d.callee = m.dst, m.src
        if m.is_request and m.method == "BYE":
            d.terminator = m
        for c in m.contacts:
            tag = m.from_.tag
            if tag:
                d.remote_contacts.setdefault(tag, c)

    # The initial INVITE carries no to-tag, so attach it to every dialog it forked into.
    inv = call.initial_invite
    if inv and inv.request:
        for d in call.dialogs:
            if d.invite is None and inv.request.from_.tag in d.tags:
                d.invite = inv.request
                d.caller, d.callee = inv.request.src, inv.request.dst

    for d in call.dialogs:
        _track_offer_answer(d, call)


def _sdp_of(m: Message) -> sdpmod.Sdp | None:
    if m.content_type == "application/sdp" and m.body.strip():
        return sdpmod.parse(m.body)
    if m.content_type.startswith("multipart/") and "v=0" in m.body:
        # Pull the SDP part out of a multipart body (SIP-I and friends).
        for part in m.body.split("--"):
            if "application/sdp" in part.lower() and "v=0" in part:
                _, _, chunk = part.partition("\n\n")
                return sdpmod.parse(chunk or part)
    return None


def _track_offer_answer(d: Dialog, call: Call) -> None:
    """Walk the dialog in time order pairing offers with answers (RFC 3264)."""
    seen = [m for m in d.messages if _sdp_of(m) is not None]
    # The dialog-forming INVITE predates the to-tag, so include it explicitly.
    if d.invite is not None and d.invite not in seen and _sdp_of(d.invite) is not None:
        seen.insert(0, d.invite)
    # A 2xx ACK is a separate transaction and may not carry both tags in older stacks.
    for t in call.transactions_of("INVITE"):
        for a in t.acks:
            if _dialog_key(a) == d.tags and a not in seen:
                seen.append(a)
    seen.sort(key=lambda m: (m.timestamp, m.frame))

    # Drop retransmissions: a repeated 200 OK is not a fresh offer.
    unique: list[Message] = []
    seen_ids: set[tuple] = set()
    for m in seen:
        ident = ((m.status, m.cseq_number, m.to.tag) if not m.is_request
                 else (m.method, m.branch, m.cseq_number))
        if ident in seen_ids:
            continue
        seen_ids.add(ident)
        unique.append(m)

    pending: SdpExchange | None = None
    for m in unique:
        body = _sdp_of(m)
        if body is None:
            continue
        if pending is None:
            pending = SdpExchange(offer=m, offer_sdp=body)
            d.exchanges.append(pending)
        else:
            # An identical retransmitted offer is not an answer.
            if m.is_request and pending.offer.is_request and body.raw == pending.offer_sdp.raw:
                continue
            pending.answer, pending.answer_sdp = m, body
            pending = None


def _build_streams(packets: list[RtpPacket]) -> list[RtpStream]:
    streams: dict[tuple, RtpStream] = {}
    for p in packets:
        if p.is_rtcp:
            continue
        key = (p.src, p.dst, p.ssrc)
        s = streams.get(key)
        if s is None:
            s = RtpStream(src=p.src, dst=p.dst, ssrc=p.ssrc)
            streams[key] = s
        s.packets.append(p)
    return list(streams.values())
