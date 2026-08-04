"""Render an analysis report as JSON, Markdown or CSV."""
from __future__ import annotations

import csv
import io
import json


def as_json(report: dict, consultations: list[dict]) -> str:
    return json.dumps({**report, "consultations": consultations}, indent=2, default=str)


def as_markdown(report: dict, consultations: list[dict]) -> str:
    out: list[str] = [f"# SIP trace analysis — {report.get('source', '')}\n"]

    calls = report.get("calls", [])
    streams = report.get("streams", [])
    findings = report.get("findings", [])
    out.append(f"{len(calls)} call(s), {len(streams)} RTP stream(s), "
               f"{len(findings)} finding(s).\n")
    for note in report.get("notes", []):
        out.append(f"> {note}\n")

    if calls:
        out.append("\n## Calls\n")
        out.append("| Call | Outcome | Messages | Dialogs |")
        out.append("|---|---|---:|---:|")
        for c in calls:
            out.append(f"| {c.get('label')} | {c.get('outcome')} | "
                       f"{c.get('messages')} | {c.get('dialogs')} |")

    if streams:
        out.append("\n## RTP streams\n")
        out.append("| From | To | SSRC | Packets | Duration | Loss | Jitter |")
        out.append("|---|---|---|---:|---:|---:|---:|")
        for s in streams:
            out.append(f"| {s['src']} | {s['dst']} | 0x{s['ssrc']:08x} | {s['packets']} | "
                       f"{s['duration']}s | {s['loss_ratio'] * 100:.2f}% | {s['jitter_ms']} ms |")

    out.append("\n## Findings\n")
    if not findings:
        out.append("No problems found.\n")
    for f in findings:
        out.append(f"\n### [{f['severity'].upper()}] {f.get('title')}\n")
        out.append(f"`{f['check_id']}`"
                   + (f" — call *{f['call']}*" if f.get("call") else "")
                   + (f" at +{f.get('at_relative', 0):.3f}s" if f.get("at_relative") else "")
                   + "\n")
        out.append(f["detail"] + "\n")
        for e in f.get("evidence", []):
            out.append(f"    {e}")
        if f.get("frames"):
            out.append(f"\nFrames: {', '.join(str(x) for x in f['frames'])}")
        if f.get("remediation"):
            out.append(f"\n**Fix:** {f['remediation']}")
        if f.get("rfc_refs"):
            out.append(f"\n*{', '.join(f['rfc_refs'])}*")

    for c in consultations:
        if not c.get("interpretation"):
            continue
        out.append(f"\n## Anthropic consult — {c['model']} "
                   f"({c['created_at']})\n")
        out.append(c["interpretation"])
        if c.get("facts"):
            out.append("\n**Candidate facts**\n")
            for fact in c["facts"]:
                mark = {"approved": "accepted", "rejected": "rejected"}.get(
                    fact["status"], "pending review")
                out.append(f"- [{fact['topic']}] {fact['fact']} "
                           f"({', '.join(fact['rfc_refs'] or []) or 'no citation'}) — {mark}")
    return "\n".join(out) + "\n"


def ladder_as_text(rows: list[dict], source: str) -> str:
    """The ladder as a plain-text flow, each message followed by its headers."""
    out = [f"SIP message ladder — {source}", "=" * 78, ""]
    for r in rows:
        arrow = "->" if r["request"] else "<-"
        dup = f"   [DUPLICATE of frame {r['duplicate_of']}]" if r["duplicate_of"] else ""
        out.append(f"#{r['frame']:<5} {r['at']:9.3f}s  {r['src']:>22} {arrow} "
                   f"{r['dst']:<22}  {r['summary']}{dup}")
        l3 = []
        if r.get("ip_id") is not None:
            l3.append(f"ip-id={r['ip_id']}")
        if r.get("ttl") is not None:
            l3.append(f"ttl={r['ttl']}")
        l3.append(r.get("transport", "UDP"))
        out.append(f"        ({', '.join(l3)})")
        out.append(f"        {r['start_line']}")
        for name, value in r["headers"]:
            out.append(f"        {name}: {value}" if name else f"        {value}")
        if r.get("body"):
            out.append("")
            for line in r["body"].rstrip().split("\n"):
                out.append(f"        | {line}")
        out.append("")
    return "\n".join(out) + "\n"


def ladder_as_markdown(rows: list[dict], source: str) -> str:
    out = [f"# SIP message ladder — {source}\n",
           "| # | Time | From | | To | Message |", "|---:|---:|---|:-:|---|---|"]
    for r in rows:
        arrow = "→" if r["request"] else "←"
        dup = " ⧉" if r["duplicate_of"] else ""
        out.append(f"| {r['frame']} | {r['at']:.3f}s | `{r['src']}` | {arrow} | "
                   f"`{r['dst']}` | {r['summary']}{dup} |")
    out.append("\n⧉ marks a frame the capture recorded more than once.\n")

    out.append("\n## Messages\n")
    for r in rows:
        out.append(f"\n### #{r['frame']} — {r['summary']}"
                   + (f" (duplicate of #{r['duplicate_of']})" if r["duplicate_of"] else ""))
        out.append(f"\n`{r['src']} {'→' if r['request'] else '←'} {r['dst']}` "
                   f"at +{r['at']:.3f}s\n")
        out.append("```")
        out.append(r["start_line"])
        for name, value in r["headers"]:
            out.append(f"{name}: {value}" if name else value)
        if r.get("body"):
            out.append("")
            out.append(r["body"].rstrip())
        out.append("```")
    return "\n".join(out) + "\n"


def ladder_as_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["frame", "time_s", "src", "dst", "direction", "summary", "call_id",
                "transport", "ip_id", "ttl", "duplicate_of", "headers"])
    for r in rows:
        w.writerow([
            r["frame"], r["at"], r["src"], r["dst"],
            "request" if r["request"] else "response", r["summary"], r["call_id"],
            r.get("transport"), r.get("ip_id"), r.get("ttl"), r["duplicate_of"],
            " | ".join(f"{n}: {v}" for n, v in r["headers"]),
        ])
    return buf.getvalue()


def as_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "check_id", "title", "call", "at_seconds", "detail",
                "frames", "rfc_refs"])
    for f in report.get("findings", []):
        w.writerow([
            f.get("severity"), f.get("check_id"), f.get("title"), f.get("call"),
            f.get("at_relative"), f.get("detail"),
            " ".join(str(x) for x in f.get("frames", [])),
            " ".join(f.get("rfc_refs", [])),
        ])
    return buf.getvalue()
