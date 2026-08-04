"""Load the RFC corpus: rfc, rfc_section, normative_rule."""
from __future__ import annotations

import os
import pathlib
import sys

import psycopg

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from rfcparse import extract_rules, parse_sections  # noqa: E402

DSN = os.environ.get("SIPTRACE_DSN",
                     "postgresql://siptrace:siptrace@localhost:55432/siptrace")
RFC_DIR = pathlib.Path(__file__).parent.parent / "rfc"

# Why each RFC is in the corpus — this is what tells the bot where to look.
CATALOG = {
    3261: ("SIP: Session Initiation Protocol", "Core protocol: messages, transactions, dialogs, proxy behaviour, timers, response codes. The spine of every diagnosis."),
    3262: ("Reliability of Provisional Responses in SIP (100rel)", "PRACK. Explains stuck early dialogs and 'Require: 100rel' rejections."),
    3263: ("SIP: Locating SIP Servers", "NAPTR/SRV/A resolution and failover. Explains why a request went to the wrong host or never left."),
    3264: ("An Offer/Answer Model with SDP", "The rules for offer/answer. Most one-way-audio and 488 problems are violations here."),
    3265: ("SIP-Specific Event Notification", "SUBSCRIBE/NOTIFY dialogs, 489 Bad Event."),
    3311: ("The SIP UPDATE Method", "Early-media renegotiation without re-INVITE."),
    3323: ("A Privacy Mechanism for SIP", "Privacy header; explains anonymised From/asserted identity."),
    3325: ("Private Extensions to SIP for Asserted Identity", "P-Asserted-Identity. Trust-domain and CLI problems."),
    3326: ("The Reason Header Field for SIP", "Carries the real cause on CANCEL/BYE - often the only clue why a call dropped."),
    3327: ("SIP Extension Header Field for Registering Non-Adjacent Contacts", "Path header; registration routing through edge proxies."),
    3329: ("Security Mechanism Agreement for SIP", "Sec-Agree negotiation failures."),
    3515: ("The SIP REFER Method", "Transfers. NOTIFY/sipfrag progress and failed attended transfers."),
    3550: ("RTP: A Transport Protocol for Real-Time Applications", "RTP/RTCP semantics: SSRC, sequence numbers, timestamps, jitter, RTCP reports."),
    3581: ("An Extension to SIP for Symmetric Response Routing", "rport. Core to NAT diagnosis."),
    3665: ("SIP Basic Call Flow Examples", "Reference ladders for correct behaviour - the bot's 'known good' baselines."),
    3711: ("The Secure Real-time Transport Protocol (SRTP)", "SRTP/SDES; explains silent calls when crypto negotiation mismatches."),
    3725: ("Best Current Practices for Third Party Call Control (3pcc)", "3pcc flows that look broken but are not."),
    3856: ("A Presence Event Package for SIP", "Presence subscriptions."),
    3891: ("The SIP Replaces Header", "Attended transfer completion."),
    3892: ("The SIP Referred-By Mechanism", "Transfer attribution."),
    3903: ("SIP Extension for Event State Publication", "PUBLISH, 412 Conditional Request Failed."),
    4028: ("Session Timers in SIP", "Session-Expires/Min-SE. Explains calls dropping at exactly 30 min / 422 loops."),
    4566: ("SDP: Session Description Protocol", "SDP syntax and semantics: m/c/a lines, direction attributes, rtpmap."),
    4733: ("RTP Payload for DTMF Digits, Telephony Tones and Signals", "RFC2833 DTMF. Explains IVR digit failures."),
    5359: ("SIP Service Examples", "Reference flows for hold, transfer, conferencing, forwarding."),
    5626: ("Managing Client-Initiated Connections in SIP (Outbound)", "Flow tokens, keepalives, reg-id. NAT binding survival."),
    5806: ("Diversion Indicator in SIP", "Legacy Diversion header still widely deployed for forwarding history."),
    6026: ("Correct Transaction Handling for 2xx Responses to SIP INVITE", "Fixes RFC 3261's INVITE server transaction; explains 2xx retransmission storms."),
    6141: ("Re-INVITE and Target-Refresh Request Handling in SIP", "Clarifies re-INVITE without SDP, glare, and offerless behaviour."),
    6337: ("SIP Usage of the Offer/Answer Model", "Errata-grade clarification of the offer/answer corner cases - very high diagnostic value."),
    7315: ("Private Header (P-Header) Extensions to SIP for 3GPP", "P-Access-Network-Info etc. in IMS traces."),
    8760: ("The SIP Digest Access Authentication Scheme", "SHA-256/SHA-512-256 digest; modern auth failures."),
    8866: ("SDP: Session Description Protocol", "Current SDP spec, obsoletes RFC 4566."),
}


def main() -> None:
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        cur.execute("TRUNCATE rfc RESTART IDENTITY CASCADE")
        n_sec = n_rule = 0
        for path in sorted(RFC_DIR.glob("rfc*.txt")):
            num = int(path.stem.removeprefix("rfc"))
            raw = path.read_text(encoding="utf-8", errors="replace")
            title, relevance = CATALOG.get(num, (path.stem, None))
            cur.execute(
                "INSERT INTO rfc (number, title, relevance, local_path, line_count)"
                " VALUES (%s,%s,%s,%s,%s)",
                (num, title, relevance, str(path), raw.count("\n") + 1),
            )
            sections = parse_sections(raw)
            for s in sections:
                cur.execute(
                    "INSERT INTO rfc_section (rfc_number, section, title, depth,"
                    " start_line, end_line, body) VALUES (%s,%s,%s,%s,%s,%s,%s)"
                    " ON CONFLICT (rfc_number, section) DO NOTHING",
                    (num, s.number, s.title, s.depth, s.start_line, s.end_line, s.body),
                )
                n_sec += cur.rowcount
                seen: set[tuple[str, str]] = set()
                for r in extract_rules(s):
                    key = (r["keyword"], r["text"])
                    if key in seen:
                        continue
                    seen.add(key)
                    cur.execute(
                        "INSERT INTO normative_rule (rfc_number, section, section_title,"
                        " keyword, strength, text, topics) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (num, s.number, s.title, r["keyword"], r["strength"],
                         r["text"], r["topics"]),
                    )
                    n_rule += 1
            print(f"RFC {num}: {len(sections):4d} sections", flush=True)
        conn.commit()
        print(f"\nloaded {n_sec} sections, {n_rule} normative rules")


if __name__ == "__main__":
    main()
