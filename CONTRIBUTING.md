# Working on SIP Trace Analyzer

Read [README.md](README.md) for what it does and [INSTALL.md](INSTALL.md) for how to
get it running. This file is about how the code is put together and the rules that
keep it honest.

```bash
make setup      # start db, api and web; builds the knowledge base on first run
make dev        # virtualenv for the test suite and the CLI tools
make test lint
```

`make help` lists everything.

---

## How it fits together

```
    trace file
        │
        ▼
 analyzer/readers.py ──── pcap (scapy) or text log → Message objects
        │                 marks duplicates and capture points here
        ▼
 analyzer/model.py ────── Call → Transaction → Dialog → SdpExchange
        │                 RTP packets → RtpStream
        ▼
 analyzer/checks/ ─────── 58 checks, each yielding Findings
        │
        ▼
 analyzer/report.py ───── joins findings to the knowledge base (severity,
        │                 title, remediation, RFC citations)
        ├──────────────▶ analyze.py         CLI
        └──────────────▶ api/ + web/        HTTP API and React UI
```

The knowledge base is built separately and read at report time:

```
 rfc/*.txt  iana/*.csv        ingest/curated.py
        │                            │
        ├── ingest/rfcparse.py       │   hand-written diagnostic knowledge
        ├── ingest/header_tables.py  │
        ▼                            ▼
    ingest/load_rfcs.py      ingest/load_protocol.py
        │                            │
        └────────────┬───────────────┘
                     ▼
                  Postgres
```

### Three layers of knowledge, deliberately separated

1. **Extracted** — `rfc`, `rfc_section`, `normative_rule`. Mechanical, reproducible,
   no judgement. This is what lets a finding cite chapter and verse.
2. **Structured** — response codes, headers, methods, timers. Part IANA registry,
   part RFC text, part curated attributes.
3. **Diagnostic** — `diagnostic_check` and the curated columns on `response_code`.
   What a code means in a trace, what causes it, what to look at next.

Never let layer 3 leak into layer 1. If you find yourself editing `rfc_section`
contents, something has gone wrong.

---

## Rules that keep this honest

**Every citation must resolve.** `ingest/load_protocol.py` checks every `rfc_refs`
entry against `rfc_section` and reports unresolved ones. It must print
`0 unresolved citation(s)`. This is what stops a plausible-looking but invented
section number reaching a report.

**Every check needs a catalog entry.** `test_every_check_id_exists_in_the_knowledge_base`
fails if a check can emit a finding the catalog cannot explain.

**Fixtures assert exact sets.** `test_scenario_finds_exactly_the_seeded_faults` fails
on a missing finding *and* on a false positive. When you add a check, expect to
update the expected set of any fixture it now fires on — and think hard before
assuming the new firing is correct rather than a false positive.

**Duplicates never reach a check.** `call.messages` has capture duplicates removed;
they live in `call.duplicates` and `trace.messages`. Any check that counts messages
must iterate `call.messages`. This is what stops a doubled capture reading as a
retransmission or a doubled auth challenge.

**Model output is quarantined.** Nothing from `api/consult.py` writes to `kb_note`
directly. It lands in `kb_fact_candidate` and can only be promoted by an explicit
approval whose citations re-resolve at that moment.

---

## Adding a check

1. **Write the catalog entry** in `ingest/curated.py` → `CHECKS`. Cite real RFC
   sections; verify each with `./.venv/bin/python kb.py section 3261 17.1.3`.
2. **Implement it** in `analyzer/checks/{signalling,routing,media}.py`:

   ```python
   @check("SIP-MY-NEW-CHECK")
   def my_new_check(ctx: Context) -> Iterable[Finding]:
       for call in ctx.calls:
           if ...:
               yield finding("SIP-MY-NEW-CHECK", call,
                             "what is wrong, with the actual numbers in it", msg)
   ```

   The `detail` string is the finding. Put the specific evidence in it — addresses,
   intervals, counts — not a restatement of the catalog title.
3. **Add a fixture** in `tests/scenarios.py` that plants the fault, and register it
   in `ALL`. Run `make test` and fix any *other* fixture it now fires on.
4. **Reload**: `make load`.

## Adding a knowledge-base column

`db/schema.sql` is the baseline and only runs on an empty database. For a change to
reach a running deployment, add `db/migrations/NNN_name.sql` **and** make the same
change in `schema.sql` so a fresh install matches. Migrations run at API startup, in
filename order, recorded in `schema_migration` so they apply once. Write them
idempotently (`ADD COLUMN IF NOT EXISTS`).

---

## Layout

| Path | What lives there |
|---|---|
| `analyzer/message.py` | SIP parsing: compact forms, folding, header order, L3 fields |
| `analyzer/sdp.py` | SDP parsing and the offer/answer model |
| `analyzer/readers.py` | pcap and text-log readers, duplicate and capture-point detection |
| `analyzer/model.py` | transactions, dialogs, offer/answer pairing, RTP streams |
| `analyzer/checks/base.py` | the `@check` registry, `Finding`, `Context`, RFC timer constants |
| `analyzer/checks/*.py` | the checks themselves |
| `analyzer/report.py` | findings joined to the knowledge base; text and JSON rendering |
| `ingest/` | RFC parsing and the loaders; `curated.py` is the hand-written knowledge |
| `api/` | FastAPI app; `consult.py` is the only file that calls Anthropic |
| `web/src/` | React UI |
| `db/` | `schema.sql` baseline plus `migrations/` |
| `tests/` | `builder.py` writes pcaps, `scenarios.py` plants faults |

---

## Things worth knowing before you change them

**Transaction matching** is branch + CSeq method only (RFC 3261 §17.1.3). It
deliberately ignores the Via sent-by, because a NATed peer's response carries a
rewritten one.

**`is_private()`** in `analyzer/sdp.py` is narrower than `ipaddress.is_private` on
purpose: the standard library also counts the documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which appear constantly in test
data and would silently disable every NAT check.

**Timestamps** use `Message.time_known`, not a non-zero test. A capture can start at
epoch 0, and a log can carry messages whose time was never recorded.

**The text reader** anchors on the SIP start line and strips whatever indentation it
carries, which is what makes `tcpdump -v` output work. Timestamps, endpoints, IP id
and TTL come from the preamble lines before it.

**Prompt caching** in `api/consult.py` depends on `knowledge_prefix()` being
byte-identical between consults. Anything trace-specific must go in the user
message, never the system prompt.

---

## Known gaps

- **No real-capture corpus.** The fixtures are synthetic and were written alongside
  the checks, so they agree with them by construction. Every genuine bug so far was
  found by running a real trace. Collect real captures and keep them (outside the
  repository — they are customer data).
- **The consult path has never run against the live API.** It was built without a key
  available. Expect to debug the first real call.
- **VLAN and Linux cooked captures are handled but untested** against a real capture
  of either.
- **SIP over TLS** cannot be read without decryption; there is no key-log support.
- **IPv6** is parsed but thinly tested; the duplicate heuristic uses the flow label
  in place of the IPv4 identification field, which is weaker.
