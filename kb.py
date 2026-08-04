#!/usr/bin/env python3
"""Query the SIP knowledge base.

  ./kb.py code 488                 what a response code means, and what to check next
  ./kb.py check --category media   failure-mode catalog
  ./kb.py check SDP-ANSWER-MISSING
  ./kb.py rule "ACK for 2xx"       full-text search over RFC 2119 normative statements
  ./kb.py rule --topic ack --kw MUST
  ./kb.py section 3261 17.1.1.3    read an RFC section verbatim
  ./kb.py headers INVITE           mandatory/optional headers for a method
  ./kb.py timers                   RFC 3261 timer table with what each one causes
  ./kb.py methods
  ./kb.py notes nat
"""
from __future__ import annotations

import argparse
import os
import sys
import textwrap

import psycopg

DSN = os.environ.get("SIPTRACE_DSN", "postgresql://siptrace:siptrace@localhost:55432/siptrace")

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
SEV = {"critical": "\033[31m", "major": "\033[33m", "minor": "\033[36m", "info": "\033[32m",
       "error": "\033[31m", "warning": "\033[33m"}


def wrap(text: str, indent: str = "  ") -> str:
    return "\n".join(textwrap.fill(p, 96, initial_indent=indent, subsequent_indent=indent)
                     for p in (text or "").split("\n"))


def bullets(items, indent: str = "    ") -> str:
    return "\n".join(textwrap.fill(f"- {i}", 96, initial_indent=indent,
                                   subsequent_indent=indent + "  ") for i in (items or []))


def cmd_code(cur, args) -> None:
    cur.execute(
        "SELECT code, name, defining_rfc, section, meaning, likely_causes, next_checks,"
        " who_emits, severity, rfc_text FROM response_code WHERE code = %s", (args.code,))
    row = cur.fetchone()
    if not row:
        sys.exit(f"no such response code: {args.code}")
    code, name, ref, section, meaning, causes, checks, emits, sev, rfc_text = row
    colour = SEV.get(sev or "", "")
    print(f"\n{BOLD}{colour}{code} {name}{RESET}  {DIM}{ref}"
          f"{' §' + section if section else ''} | emitted by {emits or '?'}{RESET}\n")
    if meaning:
        print(wrap(meaning))
    if causes:
        print(f"\n  {BOLD}Likely causes{RESET}")
        print(bullets(causes))
    if checks:
        print(f"\n  {BOLD}Check next{RESET}")
        print(bullets(checks))
    if args.verbatim and rfc_text:
        print(f"\n  {BOLD}RFC text{RESET}\n{DIM}{rfc_text}{RESET}")
    print()


def cmd_check(cur, args) -> None:
    if args.id:
        cur.execute(
            "SELECT id, category, severity, title, symptom, detection, root_causes,"
            " remediation, rfc_refs, confidence FROM diagnostic_check WHERE id ILIKE %s"
            " ORDER BY id", (args.id,))
    else:
        sql = ("SELECT id, category, severity, title, symptom, detection, root_causes,"
               " remediation, rfc_refs, confidence FROM diagnostic_check")
        params: list = []
        if args.category:
            sql += " WHERE category = %s"
            params.append(args.category)
        sql += (" ORDER BY array_position(ARRAY['critical','major','minor','info'], severity), id")
        cur.execute(sql, params)
    rows = cur.fetchall()
    if not rows:
        sys.exit("no matching checks")
    for (cid, cat, sev, title, symptom, detection, causes, remedy, refs, conf) in rows:
        colour = SEV.get(sev, "")
        print(f"\n{BOLD}{colour}[{sev.upper()}]{RESET} {BOLD}{cid}{RESET}  {DIM}{cat} | "
              f"confidence {conf}{RESET}")
        print(wrap(title))
        if args.id or len(rows) == 1:
            print(f"\n  {BOLD}Symptom{RESET}\n{wrap(symptom, '    ')}")
            print(f"\n  {BOLD}Detection{RESET}\n{wrap(detection, '    ')}")
            print(f"\n  {BOLD}Root causes{RESET}\n{bullets(causes)}")
            print(f"\n  {BOLD}Remediation{RESET}\n{wrap(remedy or '-', '    ')}")
            print(f"\n  {DIM}{', '.join(refs)}{RESET}")
    print(f"\n{len(rows)} check(s)\n")


def cmd_rule(cur, args) -> None:
    sql = ("SELECT citation, keyword, section_title, text FROM v_rule_search WHERE TRUE")
    params: list = []
    if args.query:
        sql += " AND to_tsvector('english', text) @@ plainto_tsquery('english', %s)"
        params.append(args.query)
    if args.topic:
        sql += " AND %s = ANY(topics)"
        params.append(args.topic)
    if args.kw:
        sql += " AND keyword = %s"
        params.append(args.kw.upper())
    if args.rfc:
        sql += " AND rfc_number = %s"
        params.append(args.rfc)
    sql += " ORDER BY rfc_number, section LIMIT %s"
    params.append(args.limit)
    cur.execute(sql, params)
    rows = cur.fetchall()
    for citation, kw, stitle, text in rows:
        print(f"\n{BOLD}{citation}{RESET} {DIM}{stitle}{RESET}  [{kw}]")
        print(wrap(text))
    print(f"\n{len(rows)} rule(s)\n")


def cmd_section(cur, args) -> None:
    cur.execute("SELECT title, body FROM rfc_section WHERE rfc_number=%s AND section=%s",
                (args.rfc, args.section))
    row = cur.fetchone()
    if not row:
        cur.execute("SELECT section, title FROM rfc_section WHERE rfc_number=%s"
                    " AND section LIKE %s ORDER BY section", (args.rfc, args.section + "%"))
        near = cur.fetchall()
        sys.exit("not found. nearby:\n" + "\n".join(f"  {s}  {t}" for s, t in near[:20]))
    print(f"\n{BOLD}RFC{args.rfc} §{args.section}  {row[0]}{RESET}\n")
    print(row[1])
    print()


def cmd_headers(cur, args) -> None:
    cur.execute(
        "SELECT u.applies_to, u.header, u.requirement, h.compact, u.proxy_flags"
        " FROM header_usage u JOIN header_field h ON h.name = u.header"
        " WHERE u.method = %s AND u.requirement <> '-'"
        " ORDER BY array_position(ARRAY['m','m*','c','t','*','o'], u.requirement),"
        " u.applies_to, u.header", (args.method.upper(),))
    rows = cur.fetchall()
    legend = {"m": "mandatory", "m*": "mandatory unless body absent/other cond.",
              "c": "conditional", "t": "required if body may be non-zero",
              "*": "required if body non-empty", "o": "optional"}
    cur_req = None
    for applies, header, req, compact, proxy in rows:
        if req != cur_req:
            cur_req = req
            print(f"\n{BOLD}{req}{RESET}  {DIM}{legend.get(req,'')}{RESET}")
        c = f" ({compact})" if compact else ""
        p = f" {DIM}proxy:{proxy}{RESET}" if proxy else ""
        print(f"    {applies:<18} {header}{c}{p}")
    print(f"\n{len(rows)} entries for {args.method.upper()}\n")


def cmd_timers(cur, _args) -> None:
    cur.execute("SELECT name, default_value, seconds, section, applies_to, transport, meaning"
                " FROM timer ORDER BY name")
    for name, default, secs, section, applies, transport, meaning in cur.fetchall():
        print(f"\n{BOLD}{name}{RESET}  {default}"
              f"{f' = {secs:g}s' if secs else ''}  {DIM}§{section} | {applies} | {transport}{RESET}")
        print(wrap(meaning))
    print()


def cmd_methods(cur, _args) -> None:
    cur.execute("SELECT name, defining_rfc, summary, creates_dialog, target_refresh,"
                " is_invite_txn, cancellable FROM sip_method ORDER BY name")
    for name, ref, summary, dialog, refresh, inv, canc in cur.fetchall():
        flags = ", ".join(f for f, on in [("creates dialog", dialog), ("target refresh", refresh),
                                          ("INVITE txn", inv), ("cancellable", canc)] if on)
        print(f"\n{BOLD}{name}{RESET}  {DIM}{ref}{' | ' + flags if flags else ''}{RESET}")
        print(wrap(summary))
    print()


def cmd_notes(cur, args) -> None:
    sql = "SELECT topic, note, rfc_refs FROM kb_note"
    params: list = []
    if args.topic:
        sql += " WHERE topic = %s"
        params.append(args.topic)
    cur.execute(sql + " ORDER BY topic", params)
    for topic, note, refs in cur.fetchall():
        print(f"\n{BOLD}{topic}{RESET}")
        print(wrap(note))
        if refs:
            print(f"  {DIM}{', '.join(refs)}{RESET}")
    print()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("code")
    s.add_argument("code", type=int)
    s.add_argument("-v", "--verbatim", action="store_true", help="include the RFC text")
    s.set_defaults(fn=cmd_code)

    s = sub.add_parser("check")
    s.add_argument("id", nargs="?")
    s.add_argument("-c", "--category")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("rule")
    s.add_argument("query", nargs="?")
    s.add_argument("-t", "--topic")
    s.add_argument("-k", "--kw")
    s.add_argument("-r", "--rfc", type=int)
    s.add_argument("-n", "--limit", type=int, default=15)
    s.set_defaults(fn=cmd_rule)

    s = sub.add_parser("section")
    s.add_argument("rfc", type=int)
    s.add_argument("section")
    s.set_defaults(fn=cmd_section)

    s = sub.add_parser("headers")
    s.add_argument("method")
    s.set_defaults(fn=cmd_headers)

    sub.add_parser("timers").set_defaults(fn=cmd_timers)
    sub.add_parser("methods").set_defaults(fn=cmd_methods)

    s = sub.add_parser("notes")
    s.add_argument("topic", nargs="?")
    s.set_defaults(fn=cmd_notes)

    args = p.parse_args()
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        args.fn(cur, args)


if __name__ == "__main__":
    main()
