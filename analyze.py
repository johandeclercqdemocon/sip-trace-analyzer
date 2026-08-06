#!/usr/bin/env python3
"""Analyse a SIP trace and report what is wrong with it.

  ./analyze.py capture.pcap
  ./analyze.py sip.log --verbose
  ./analyze.py capture.pcapng --json > findings.json
  ./analyze.py capture.pcap --only SIP-ACK-MISSING,RTP-ONE-WAY
  ./analyze.py capture.pcap --ladder          # message ladder per call

Purely deterministic: it reconstructs transactions and dialogs, runs the checks, and
cites the RFC sections behind each finding. No model inference anywhere in the path.
"""
from __future__ import annotations

import argparse
import sys

from analyzer import model, readers
from analyzer.checks import Context, run_all
from analyzer.report import Knowledge, Report


def ladder(report: Report) -> str:
    out = []
    for call in report.calls:
        out.append(f"\n\033[1m{call.label()}\033[0m  \033[2m{call.call_id}\033[0m")
        t0 = call.start
        for m in call.messages:
            rel = f"{m.timestamp - t0:8.3f}" if m.timestamp else "        "
            arrow = "->" if m.is_request else "<-"
            # Where the source named the devices, they are the useful column:
            # 'sbc02 -> sre-uat' reads as a path in a way two addresses do not.
            hop = (f"  \033[2m{m.src_device} -> {m.dst_device}\033[0m"
                   if m.src_device or m.dst_device else "")
            out.append(f"  {rel}  {m.src:>21} {arrow} {m.dst:<21} {m.summary()}{hop}")
    return "\n".join(out) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("trace", help="pcap, pcapng, or a text SIP log")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="include root causes and remediation")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--ladder", action="store_true", help="print the message ladder")
    p.add_argument("--only", help="comma-separated check ids to run")
    p.add_argument("--no-colour", action="store_true")
    args = p.parse_args()

    trace = readers.read(args.trace)
    if not trace.messages:
        print(f"no SIP messages found in {args.trace}", file=sys.stderr)
        return 2

    calls, streams = model.build(trace)
    ctx = Context(trace=trace, calls=calls, streams=streams)
    only = {s.strip() for s in args.only.split(",")} if args.only else None
    findings = run_all(ctx, only)

    try:
        knowledge = Knowledge.load()
    except Exception as exc:                                  # noqa: BLE001
        print(f"knowledge base unavailable ({exc}); run ./rebuild.sh", file=sys.stderr)
        return 3

    notes = list(trace.notes)
    if not trace.has_media_layer and not trace.media_reports:
        notes.append(f"{trace.kind}: no media layer, so the RTP checks were not run")
    parse_problems = sum(len(m.parse_errors) for m in trace.messages)
    if parse_problems:
        notes.append(f"{parse_problems} message parse problem(s); see --verbose")

    report = Report(source=trace.source, calls=calls, streams=streams,
                    findings=findings, knowledge=knowledge, notes=notes, trace=trace)

    if args.ladder:
        print(ladder(report))
    print(report.to_json() if args.json
          else report.render(verbose=args.verbose, colour=not args.no_colour))

    worst = min((report.knowledge.severity(f.check_id) for f in findings),
                key=lambda s: {"critical": 0, "major": 1, "minor": 2, "info": 3}.get(s, 9),
                default=None)
    return 1 if worst in ("critical", "major") else 0


if __name__ == "__main__":
    sys.exit(main())
