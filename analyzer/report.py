"""Turn findings into a report, enriched from the knowledge base."""
from __future__ import annotations

import json
import os
import textwrap
from dataclasses import dataclass, field

import psycopg

from .checks.base import Finding
from .model import Call, RtpStream

DSN = os.environ.get("SIPTRACE_DSN", "postgresql://siptrace:siptrace@localhost:55432/siptrace")

SEVERITY_ORDER = {"critical": 0, "major": 1, "minor": 2, "info": 3}

# Reported in this order: what a VoIP analyser would call a call first, then the
# groups that inflate a naive Call-ID count.
KIND_ORDER = ("call", "orphan", "registration", "subscription", "keepalive", "other")
KIND_HELP = {
    "call": "a dialog-forming INVITE was captured",
    "orphan": "in-dialog request only (BYE, re-INVITE, UPDATE) — the call began "
              "before the capture did",
    "registration": "REGISTER transactions",
    "subscription": "SUBSCRIBE, NOTIFY, PUBLISH or REFER",
    "keepalive": "OPTIONS ping only",
    "other": "no INVITE and no recognised non-call transaction",
}
COLOUR = {"critical": "\033[31m", "major": "\033[33m", "minor": "\033[36m", "info": "\033[32m"}
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


@dataclass
class Knowledge:
    """The catalog entry behind a check, plus response-code meanings."""
    checks: dict[str, dict] = field(default_factory=dict)
    codes: dict[int, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, dsn: str = DSN) -> Knowledge:
        k = cls()
        with psycopg.connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute("SELECT id, category, severity, title, symptom, root_causes,"
                        " remediation, rfc_refs, confidence FROM diagnostic_check")
            for row in cur.fetchall():
                k.checks[row[0]] = dict(zip(
                    ("id", "category", "severity", "title", "symptom", "root_causes",
                     "remediation", "rfc_refs", "confidence"), row, strict=False))
            cur.execute("SELECT code, name, meaning, likely_causes, next_checks, severity"
                        " FROM response_code")
            for row in cur.fetchall():
                k.codes[row[0]] = dict(zip(
                    ("code", "name", "meaning", "likely_causes", "next_checks", "severity"), row, strict=False))
        return k

    def severity(self, check_id: str) -> str:
        return self.checks.get(check_id, {}).get("severity", "info")


@dataclass
class Report:
    source: str
    calls: list[Call]
    streams: list[RtpStream]
    findings: list[Finding]
    knowledge: Knowledge
    notes: list[str] = field(default_factory=list)

    @property
    def t0(self) -> float:
        """Trace start, so findings are timed relative to it rather than to the epoch.

        Keyed on time_known rather than on a non-zero value: a capture may legitimately
        start at epoch 0, and a log may carry messages whose time was never recorded.
        """
        stamps = [m.timestamp for c in self.calls for m in c.messages if m.time_known]
        return min(stamps, default=0.0)

    def census(self) -> dict:
        """Reconcile the Call-ID count with the call count.

        Every tool that groups by Call-ID reports a bigger number than a VoIP
        analyser does, because keepalives and registrations are Call-IDs too.
        Publishing both numbers with the breakdown between them is the whole
        point: an unexplained '19 calls' next to Wireshark's '2' reads as a bug.
        """
        by_kind: dict[str, int] = dict.fromkeys(KIND_ORDER, 0)
        for c in self.calls:
            by_kind[c.kind] = by_kind.get(c.kind, 0) + 1
        return {
            "call_ids": len(self.calls),
            "calls": by_kind["call"],
            "by_kind": {k: n for k, n in by_kind.items() if n},
        }

    def ranked(self) -> list[Finding]:
        return sorted(self.findings,
                      key=lambda f: (SEVERITY_ORDER.get(self.knowledge.severity(f.check_id), 9),
                                     f.at, f.check_id))

    # ---------------------------------------------------------------- text
    def render(self, verbose: bool = False, colour: bool = True) -> str:
        def c(code: str) -> str:
            return code if colour else ""

        out: list[str] = []
        out.append(f"\n{c(BOLD)}SIP trace analysis{c(RESET)}  {c(DIM)}{self.source}{c(RESET)}")
        span = max((cl.end for cl in self.calls), default=0) - \
            min((cl.start for cl in self.calls), default=0)
        msgs = sum(len(cl.messages) for cl in self.calls)
        cen = self.census()
        out.append(f"{msgs} SIP messages, {cen['calls']} call(s) "
                   f"across {cen['call_ids']} Call-ID(s), "
                   f"{len(self.streams)} RTP stream(s)"
                   + (f", {span:.1f}s span" if span > 0 else ""))
        if cen["call_ids"] != cen["calls"]:
            breakdown = ", ".join(f"{n} {k}" for k, n in cen["by_kind"].items())
            out.append(f"{c(DIM)}Call-IDs by kind: {breakdown}. A VoIP analyser "
                       f"(Wireshark's VoIP Calls) counts the {cen['calls']} "
                       f"INVITE dialog(s) only.{c(RESET)}")
        for n in self.notes:
            out.append(f"{c(DIM)}note: {n}{c(RESET)}")

        out.append(f"\n{c(BOLD)}Call-IDs{c(RESET)}")
        for cl in self.calls:
            n = sum(1 for f in self.findings if f.call_id == cl.call_id)
            out.append(f"  {cl.kind:<13} {cl.label():<40} {cl.outcome:<22} "
                       f"{len(cl.messages):>3} msgs  {n} finding(s)")
            if verbose:
                out.append(f"    {c(DIM)}Call-ID {cl.call_id}{c(RESET)}")

        if not self.findings:
            out.append(f"\n{c(BOLD)}No problems found.{c(RESET)}\n")
            return "\n".join(out)

        counts: dict[str, int] = {}
        for f in self.findings:
            counts[self.knowledge.severity(f.check_id)] = \
                counts.get(self.knowledge.severity(f.check_id), 0) + 1
        summary = "  ".join(f"{c(COLOUR.get(s, ''))}{n} {s}{c(RESET)}"
                            for s, n in sorted(counts.items(),
                                               key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))
        out.append(f"\n{c(BOLD)}Findings{c(RESET)}   {summary}")

        for f in self.ranked():
            meta = self.knowledge.checks.get(f.check_id, {})
            sev = meta.get("severity", "info")
            out.append(f"\n{c(COLOUR.get(sev, ''))}{c(BOLD)}[{sev.upper()}]{c(RESET)} "
                       f"{c(BOLD)}{meta.get('title', f.check_id)}{c(RESET)}  "
                       f"{c(DIM)}{f.check_id}{c(RESET)}")
            if f.call_label:
                out.append(f"  {c(DIM)}call: {f.call_label}"
                           + (f"  at {f.at - self.t0:+.3f}s" if f.at else "") + c(RESET))
            out.append(textwrap.fill(f.detail, 96, initial_indent="  ",
                                     subsequent_indent="  "))
            for e in f.evidence[:4]:
                out.append(f"    {c(DIM)}| {e}{c(RESET)}")
            if f.frames:
                out.append(f"    {c(DIM)}frames: "
                           f"{', '.join(str(x) for x in f.frames[:8])}{c(RESET)}")
            if verbose:
                for cause in meta.get("root_causes") or []:
                    out.append(f"      - {cause}")
                if meta.get("remediation"):
                    out.append(textwrap.fill(meta["remediation"], 92,
                                             initial_indent="    fix: ",
                                             subsequent_indent="         "))
            refs = ", ".join(meta.get("rfc_refs") or [])
            if refs:
                out.append(f"    {c(DIM)}{refs}{c(RESET)}")
        out.append("")
        return "\n".join(out)

    # ---------------------------------------------------------------- json
    def to_json(self) -> str:
        return json.dumps({
            "source": self.source,
            "counts": {**self.census(), "kind_help": KIND_HELP},
            "calls": [{"call_id": c.call_id, "label": c.label(), "outcome": c.outcome,
                       "kind": c.kind, "methods": sorted({t.method for t in c.transactions}),
                       "messages": len(c.messages), "start": c.start, "end": c.end,
                       "dialogs": len(c.dialogs)} for c in self.calls],
            "streams": [{"src": s.src, "dst": s.dst, "ssrc": s.ssrc,
                         "packets": len(s.packets), "duration": round(s.duration, 3),
                         "loss_ratio": round(s.loss_ratio, 5),
                         "jitter_ms": round(s.jitter(), 2)} for s in self.streams],
            "findings": [{
                "check_id": f.check_id,
                "severity": self.knowledge.severity(f.check_id),
                "title": self.knowledge.checks.get(f.check_id, {}).get("title"),
                "detail": f.detail,
                "call_id": f.call_id,
                "call": f.call_label,
                "at": round(f.at, 6),
                "at_relative": round(f.at - self.t0, 6) if f.at else 0.0,
                "frames": f.frames,
                "evidence": f.evidence,
                "rfc_refs": self.knowledge.checks.get(f.check_id, {}).get("rfc_refs", []),
                "remediation": self.knowledge.checks.get(f.check_id, {}).get("remediation"),
            } for f in self.ranked()],
            "notes": self.notes,
        }, indent=2)
