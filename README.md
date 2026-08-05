# SIP Trace Analyzer

A bot that reads SIP traces and tells you what is wrong with them, deterministically
and with an RFC citation behind every finding.

Two parts: a **knowledge base** distilled from the RFCs into Postgres, and an
**analyser** that reconstructs calls from a capture and runs 56 checks against them.

No model inference anywhere in the pipeline.

## Run it

```bash
docker compose up -d --build      # or: make setup
```

That is the whole install — see [INSTALL.md](INSTALL.md). Docker is the only
requirement; the RFC corpus ships with the repository and the API builds its
knowledge base from it on first start, with **no network access**. Open
http://localhost:8080.

The CLI and test suite are optional developer extras (`make dev`):

```bash
./.venv/bin/python analyze.py capture.pcap
./.venv/bin/python kb.py code 481
./.venv/bin/python -m pytest tests/ -q
```

```
[CRITICAL] 200 OK to INVITE never acknowledged  SIP-ACK-MISSING
  call: alice -> bob  at 1.000s
  200 OK for INVITE (CSeq 1) was never acknowledged in dialog alice -> bob; the trace
  continues 7.500s after it, so the ACK is absent rather than merely outside the capture
    | 200 OK from 198.51.100.20:5060 to 203.0.113.10:5060
    | Contact in the 200 OK: sip:bob@198.51.100.20
    frames: 3
    RFC3261#13.2.2.4, RFC3261#17.1.1.3, RFC3261#17.2.1
```

Options: `--verbose` (root causes and remediation), `--json`, `--ladder` (message
ladder per call), `--only CHECK-ID,...`. Exit code is 1 when anything critical or
major was found, which makes it usable in CI.

## Input

| format | signalling | media |
|---|---|---|
| pcap / pcapng | UDP and TCP (with stream reassembly) | RTP and RTCP |
| text logs | `tcpdump -v`, sngrep/ngrep dumps, Asterisk and Kamailio debug logs, generic | not available |

Text logs work off the SIP start line as the anchor, taking timestamps, endpoints and
IP id/TTL from whatever preamble the tool wrote. Indentation is handled, so `tcpdump -v`
output — where SIP sits eight spaces under the IP line and endpoints are written
`10.1.0.150.5060 > 10.0.0.21.50210` — parses directly. RTP checks stay silent rather
than guess when there is no media layer.

VLAN-tagged and Linux cooked (`tcpdump -i any`) captures are read transparently, and a
file mixing link layers is reported — that usually means two capture points were merged.

## Query the knowledge base

```bash
./.venv/bin/python kb.py code 488
./.venv/bin/python kb.py check --category media
./.venv/bin/python kb.py rule "ACK for 2xx" --kw MUST
./.venv/bin/python kb.py section 3261 17.1.3
./.venv/bin/python kb.py headers INVITE
./.venv/bin/python kb.py timers
```

Postgres listens on `localhost:55432` (`siptrace` / `siptrace` / db `siptrace`).

| table | rows | source |
|---|---|---|
| `rfc` | 33 | bundled in `rfc/`; refresh with `make corpus` |
| `rfc_section` | 1 426 | parsed, de-paginated, full-text indexed |
| `normative_rule` | 3 241 | every RFC 2119 MUST/SHOULD/MAY sentence, tagged by topic |
| `response_code` | 75 | IANA registry + RFC 3261 §21 verbatim + curated diagnostics |
| `header_field` | 134 | IANA registry + RFC 3261 §20 summaries |
| `header_usage` | 390 | RFC 3261 Tables 2 and 3, machine-readable |
| `sip_method` | 14 | curated behavioural flags |
| `timer` | 14 | RFC 3261 Table 4 + what each timer causes in a trace |
| `diagnostic_check` | 56 | the failure catalog, all 56 implemented |
| `kb_note` | 8 | interop lore that does not fit a single check |

## Web UI

Three containers: Postgres, a FastAPI backend, and nginx serving a React build and
proxying `/api`. Upload by drag-and-drop, read the findings, walk the message
ladder, export as JSON / Markdown / CSV. Install steps are in [INSTALL.md](INSTALL.md).

### Calls versus Call-IDs

A Call-ID group is not a call. OPTIONS keepalives, REGISTERs and NOTIFYs each get
their own Call-ID, so a trunk capture yields far more Call-IDs than calls — one
real trace here holds 65 Call-IDs and 4 calls. Wireshark's *Telephony ▸ VoIP Calls*
window counts only the dialogs an INVITE started, and the report says both numbers
side by side, with a breakdown by kind whenever they differ:

| kind | what it is |
|---|---|
| `call` | a dialog-forming INVITE was captured — the VoIP-analyser count |
| `orphan` | in-dialog request only (BYE, re-INVITE): the call began before the capture |
| `registration` | REGISTER transactions |
| `subscription` | SUBSCRIBE, NOTIFY, PUBLISH or REFER |
| `keepalive` | OPTIONS ping only |
| `other` | no INVITE and no recognised non-call transaction |

The Call-ID table, the findings list and the ladder each filter by those kinds, by
severity and by method, with a free-text search; a call's **ladder** button opens
the ladder filtered to that Call-ID. **Re-analyse** re-runs the checks over a
stored capture, which is how an old report picks up new checks without a re-upload.
Exports always carry the whole trace, never the filtered view.

### Consult Anthropic — the one thing that leaves the machine

Everything else in SIP Trace Analyzer is local. **Consult** is a separate, explicitly-triggered
step behind a two-click confirmation:

1. *Prepare consult* shows exactly what would be sent, what would not, and a cost
   estimate. **This step makes no network request** — the estimate is computed
   locally, so nothing leaves the machine before you have seen the number.
2. *Send to Anthropic* makes **one** request to `claude-opus-5`.

It sends the diagnostic catalog, the knowledge-base notes, and this trace's
findings and call summaries. It does **not** send the capture file, message bodies,
or any other trace. The catalog half of the prompt is identical on every consult
and carries a cache breakpoint, so repeat consults are far cheaper.

Anything the model returns is **quarantined** in `kb_fact_candidate` — it never
touches the curated knowledge base directly. A candidate fact can only be promoted
to `kb_note` when a human approves it *and* every RFC citation on it resolves
against the local corpus. Citations are re-checked at approval time, so the same
invariant that governs the hand-written catalog governs LLM output too.

## Persistence

The data lives in the named volume `sip-trace-analyzer_siptrace-pgdata`, not in the container, so it
outlives the container itself.

| action | data |
|---|---|
| `docker compose restart` | survives |
| `docker compose down` then `up -d` (container destroyed and recreated) | survives |
| host reboot | survives |
| `docker compose down -v` | **destroyed** |
| `./rebuild.sh --wipe` | **destroyed** - it runs `down -v` |
| `./rebuild.sh` without `--wipe` | volume kept; the loaders `TRUNCATE` and reload |

**Editing `db/schema.sql` requires `--wipe`.** The file is mounted into
`/docker-entrypoint-initdb.d/`, and Postgres only runs that directory when the data
directory is empty. Without a wipe the old schema stays in place and the loaders fail
against it.

Losing the volume costs nothing but a few seconds. The RFCs and IANA registries are on
disk under `rfc/` and `iana/`, and every row is regenerated from them - nothing in the
database is hand-entered state. The curated knowledge lives in `ingest/curated.py`,
under version control rather than in the volume.

## Citation integrity

Every `rfc_refs` entry is checked against `rfc_section` when the knowledge base loads.
A citation that does not resolve fails the build rather than reaching a report.
Currently 0 unresolved. `test_every_check_id_exists_in_the_knowledge_base` closes the
loop from the other side: no check can report a finding the catalog cannot explain.

## What it checks

56 checks across capture quality, signalling, routing, NAT, auth, registration,
timers, SDP and RTP.
The ones that matter most in practice:

- **Capture quality** — the same frame recorded twice (mirrored port, merged taps),
  and the same packet recorded at two points on its path (either side of a NAT or
  SIP ALG). Both are excluded from transaction analysis, because otherwise one
  message counted twice reads as a retransmission, a doubled auth challenge, or a
  CSeq reuse. The capture-point check also reports the address translation map and
  whether an ALG rewrote the SIP itself.
- **Signalling** — unACKed 2xx and the Timer G/H retransmission ladder, INVITE
  retransmission into Timer B, missing 100 Trying, proxy Timer C cancellation, CANCEL
  racing a 200, 491 glare, branch reuse, merged requests, in-dialog 481.
- **Routing and NAT** — Record-Route asymmetry between provisional and final, in-dialog
  requests with no Route set, private addresses in Contact / Via / SDP `c=`, missing
  `received=` and `rport`, Via loops, oversized UDP.
- **Auth and registration** — repeated challenges, stale nonces, credentials in the
  wrong authorization header, 423 loops, registration flapping, bindings that outlive
  the NAT mapping.
- **Media** — missing answers, offerless INVITE with no answer in the ACK, codec and
  transport-profile mismatches, non-complementary direction attributes, port 0,
  inconsistent hold, unbumped `o=` versions, DTMF mismatches, reordered `m=` lines.
- **RTP** — no stream despite a completed negotiation, one-way audio, unnegotiated
  payload types, SSRC changes, sequence gaps, timestamp jumps, absent RTCP, high jitter.

`kb.py check --category media` lists any category in full.

## Tests

Thirteen synthetic traces, each planting a documented set of faults. The suite asserts
the analyser finds **exactly** those - missing findings and false positives both fail.
A clean call must produce silence.

```
./.venv/bin/python -m pytest tests/ -q      # 30 passed
```

The fixtures were written alongside the checks, so they prove internal consistency,
not real-world coverage. Running it against real captures is the next thing worth
doing.

## Layout

```
docker-compose.yml        db, api and web
Makefile                  make help lists every target
db/schema.sql             baseline schema; db/migrations/ for changes after that
rfc/  iana/               33 RFCs as text, IANA registries as CSV (committed)
ingest/rfcparse.py        RFC text -> sections + normative rules
ingest/header_tables.py   RFC 3261 Tables 2/3 -> rows
ingest/curated.py         the curated diagnostic knowledge
ingest/load_*.py          loaders + citation validation
scripts/fetch-corpus.sh   refresh the bundled corpus
kb.py                     knowledge base CLI
analyze.py                trace analysis CLI
analyzer/message.py       SIP message parsing
analyzer/sdp.py           SDP parsing
analyzer/readers.py       pcap and text log readers
analyzer/model.py         transactions, dialogs, offer/answer, RTP streams
analyzer/checks/          the 56 checks
analyzer/report.py        findings joined to the knowledge base
api/  web/                HTTP API and React UI
tests/                    builder, scenarios, assertions
```
