"""Load structured protocol facts and the curated diagnostic layer.

Run after load_rfcs.py: response codes, methods, headers, timers and the failure
catalog, plus a citation check that every RFC reference resolves to a real section.
"""
from __future__ import annotations

import csv
import os
import pathlib
import re
import sys

import psycopg

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import curated  # noqa: E402
from header_tables import parse as parse_header_tables  # noqa: E402

DSN = os.environ.get("SIPTRACE_DSN",
                     "postgresql://siptrace:siptrace@localhost:55432/siptrace")
ROOT = pathlib.Path(__file__).parent.parent
IANA = ROOT / "iana"
RFC_DIR = ROOT / "rfc"

METHOD_ABBR = {"ACK": "ACK", "BYE": "BYE", "CAN": "CANCEL", "INV": "INVITE",
               "OPT": "OPTIONS", "REG": "REGISTER"}


def ref_rfc(value: str) -> tuple[int | None, str | None]:
    """'[RFC3515]' -> (3515, 'RFC3515'); empty means RFC 3261 in the IANA tables."""
    m = re.search(r"RFC(\d+)", value or "")
    if not m:
        return 3261, "RFC3261"
    return int(m.group(1)), f"RFC{m.group(1)}"


def load_response_codes(cur, corpus: set[int]) -> None:
    # RFC 3261 section 21 gives the verbatim prose; the IANA registry gives the
    # authoritative name and defining document for every code including extensions.
    cur.execute(
        "SELECT section, title, body FROM rfc_section"
        " WHERE rfc_number = 3261 AND section LIKE '21.%'"
    )
    rfc_text: dict[int, tuple[str, str]] = {}
    for section, title, body in cur.fetchall():
        m = re.match(r"^(\d{3})\s+(.+)$", title)
        if m:
            rfc_text[int(m.group(1))] = (section, body.strip())

    with (IANA / "sip-parameters-7.csv").open() as fh:
        rows = list(csv.DictReader(fh))

    for row in rows:
        code = int(row["Response Code"])
        num, ref = ref_rfc(row["Reference"])
        section, body = rfc_text.get(code, (None, None))
        d = curated.RESPONSE_DIAGNOSTICS.get(code)
        meaning, causes, checks, emits, sev, kills = d if d else (None, [], [], None, None, None)
        cur.execute(
            "INSERT INTO response_code (code, class, name, rfc_number, defining_rfc, section,"
            " rfc_text, is_final, terminates_dialog, meaning, likely_causes, next_checks,"
            " who_emits, severity) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (code, code // 100, row["Description"], num if num in corpus else None, ref,
             section, body, code >= 200, kills, meaning, causes, checks, emits, sev),
        )


def load_methods(cur, corpus: set[int]) -> None:
    with (IANA / "sip-parameters-6.csv").open() as fh:
        registry = {r["Methods"]: r["Reference"] for r in csv.DictReader(fh)}
    for name, (summary, dialog, indialog, refresh, inv, ack, cancellable) in curated.METHODS.items():
        num, ref = ref_rfc(registry.get(name, ""))
        cur.execute(
            "INSERT INTO sip_method (name, rfc_number, defining_rfc, summary, creates_dialog,"
            " within_dialog, target_refresh, is_invite_txn, ack_required, cancellable)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (name, num if num in corpus else None, ref, summary, dialog, indialog,
             refresh, inv, ack, cancellable),
        )


def load_headers(cur, corpus: set[int]) -> None:
    # Names and compact forms from IANA; one-line summaries from RFC 3261 section 20.
    cur.execute(
        "SELECT title, body FROM rfc_section WHERE rfc_number = 3261 AND section LIKE '20.%'"
    )
    summaries = {}
    for title, body in cur.fetchall():
        first = next((p.strip() for p in body.split("\n\n") if p.strip()), "")
        summaries[title.strip().lower()] = " ".join(first.split())[:400]

    dialog_id = {"call-id", "from", "to", "cseq"}
    routing = {"via", "route", "record-route", "contact", "path", "max-forwards"}

    with (IANA / "sip-parameters-2.csv").open() as fh:
        for row in csv.DictReader(fh):
            name = row["Header Name"].strip()
            if not name:
                continue
            num, ref = ref_rfc(row["Reference"])
            cur.execute(
                "INSERT INTO header_field (name, compact, rfc_number, defining_rfc, summary,"
                " is_dialog_id, is_routing) VALUES (%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (name) DO NOTHING",
                (name, row["compact"].strip() or None, num if num in corpus else None, ref,
                 summaries.get(name.lower()), name.lower() in dialog_id, name.lower() in routing),
            )


def load_header_usage(cur) -> None:
    rows = parse_header_tables((RFC_DIR / "rfc3261.txt").read_text())
    for r in rows:
        # Table rows can name headers the IANA CSV spells differently.
        cur.execute(
            "INSERT INTO header_field (name, defining_rfc) VALUES (%s,'RFC3261')"
            " ON CONFLICT (name) DO NOTHING", (r["header"],)
        )
        for abbr, req in r["requirements"].items():
            cur.execute(
                "INSERT INTO header_usage (header, applies_to, method, requirement, proxy_flags)"
                " VALUES (%s,%s,%s,%s,%s) ON CONFLICT (header, applies_to, method) DO NOTHING",
                (r["header"], r["where"], METHOD_ABBR[abbr], req, r["proxy"]),
            )


def load_timers(cur) -> None:
    for name, (default, secs, section, meaning, applies, transport) in curated.TIMERS.items():
        cur.execute(
            "INSERT INTO timer (name, default_value, seconds, rfc_number, section, meaning,"
            " applies_to, transport) VALUES (%s,%s,%s,3261,%s,%s,%s,%s)",
            (name, default, secs, section, meaning, applies, transport),
        )


def load_checks(cur) -> None:
    for (cid, cat, sev, title, symptom, detection, causes, remedy, refs, conf) in curated.CHECKS:
        cur.execute(
            "INSERT INTO diagnostic_check (id, category, severity, title, symptom, detection,"
            " root_causes, remediation, rfc_refs, confidence)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (cid, cat, sev, title, symptom, detection, causes, remedy, refs, conf),
        )
    for topic, note, refs, source in curated.NOTES:
        cur.execute(
            "INSERT INTO kb_note (topic, note, rfc_refs, source) VALUES (%s,%s,%s,%s)",
            (topic, note, refs, source),
        )


def validate_citations(cur) -> list[str]:
    """Every 'RFC#####section' reference must resolve to a section we actually hold."""
    cur.execute("SELECT id, rfc_refs FROM diagnostic_check")
    refs = [(cid, r) for cid, rs in cur.fetchall() for r in rs]
    cur.execute("SELECT id, rfc_refs FROM kb_note")
    refs += [(f"note:{nid}", r) for nid, rs in cur.fetchall() for r in rs]

    cur.execute("SELECT rfc_number, section FROM rfc_section")
    have = {(n, s) for n, s in cur.fetchall()}
    bad = []
    for owner, ref in refs:
        m = re.match(r"RFC(\d+)#(.+)$", ref)
        if not m:
            bad.append(f"{owner}: malformed ref {ref!r}")
            continue
        key = (int(m.group(1)), m.group(2))
        if key not in have:
            bad.append(f"{owner}: {ref} does not resolve")
    return bad


def main() -> None:
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        cur.execute("TRUNCATE response_code, sip_method, header_field, header_usage,"
                    " timer, diagnostic_check, kb_note RESTART IDENTITY CASCADE")
        cur.execute("SELECT number FROM rfc")
        corpus = {r[0] for r in cur.fetchall()}
        if not corpus:
            sys.exit("rfc table is empty - run load_rfcs.py first")

        load_response_codes(cur, corpus)
        load_methods(cur, corpus)
        load_headers(cur, corpus)
        load_header_usage(cur)
        load_timers(cur)
        load_checks(cur)

        bad = validate_citations(cur)
        for line in bad:
            print(f"  UNRESOLVED  {line}")
        conn.commit()

        for table in ("response_code", "sip_method", "header_field", "header_usage",
                      "timer", "diagnostic_check", "kb_note"):
            cur.execute(f"SELECT count(*) FROM {table}")
            print(f"{table:<18} {cur.fetchone()[0]:>5}")
        print(f"\n{len(bad)} unresolved citation(s)")


if __name__ == "__main__":
    main()
