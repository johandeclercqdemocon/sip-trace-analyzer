# Installing SIP Trace Analyzer

Three containers — Postgres, a FastAPI backend, and nginx serving the React
frontend. One command brings all three up and builds the knowledge base.

**No network access is needed after cloning.** The RFC corpus and IANA registries
ship with the repository, and the API builds its knowledge base from them on first
start. Docker will pull its base images the first time, so do that once on a
connected machine if the target is offline.

---

## 1. Requirements

| | Minimum | Check with |
|---|---|---|
| Docker Engine / Desktop | 24 | `docker --version` |
| Docker Compose | v2 | `docker compose version` |
| Free ports | 8080, 55432 | see *Changing ports* |
| Disk | ~2 GB | images and uploads |

That is the whole list. **Python is not required to install or run SIP Trace Analyzer** — it is
only needed for the developer extras (test suite and the two command-line tools),
which are optional and covered in step 5.

Works on Linux and macOS, on both Intel and Apple Silicon: every base image is
published for `amd64` and `arm64`.

### macOS

```bash
brew install --cask docker      # or download Docker Desktop
open -a Docker                  # start it, and wait for the whale to settle
```

`make` comes with the Xcode command line tools (`xcode-select --install`). If you
prefer not to install those, run the `docker compose` commands from the Makefile
directly — they are plain Docker.

### Linux

Install Docker Engine and the Compose plugin from your distribution or from
docker.com. Add yourself to the `docker` group, or prefix the commands with `sudo`.

An Anthropic API key is **optional**. Upload, analysis, the message ladder and every
export work without one — only the Consult button needs it.

---

## 2. Get the code

```bash
git clone <your-remote> sip-trace-analyzer && cd sip-trace-analyzer
```

You should have `docker-compose.yml`, `db/`, `api/`, `web/`, `analyzer/`, `ingest/`,
`tests/`, and — already populated — `rfc/` (34 RFCs) and `iana/` (10 registries).

Confirm the corpus came with it:

```bash
ls rfc/*.txt | wc -l      # 33
```

---

## 3. Configure (optional)

```bash
cp .env.example .env
```

Edit `.env` and paste your key **into that file yourself** — nothing else reads it,
and it is git-ignored:

```
ANTHROPIC_API_KEY=sk-ant-...
```

Skip this entirely to run without the consult feature.

| Variable | Default | Meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | *(empty)* | Enables the Consult button. Nothing else uses it. |
| `SIPTRACE_CONSULT_MODEL` | `claude-opus-5` | Model used for a consult |
| `SIPTRACE_CONSULT_EFFORT` | `medium` | `low` / `medium` / `high` / `xhigh` / `max` |
| `SIPTRACE_MAX_UPLOAD_MB` | `200` | Upload ceiling (also raise `client_max_body_size` in `web/nginx.conf`) |

---

## 4. Start it

```bash
make setup
```

or, without `make`:

```bash
docker compose up -d --build
```

The first build compiles the frontend and pulls base images — a few minutes. On
first start the API applies its migrations and loads the knowledge base from the
bundled corpus, which takes a couple of seconds and is logged:

```
applied migration 001_trace_archive.sql
knowledge base is empty; loading the bundled corpus…
loaded 1440 sections, 3252 normative rules
0 unresolved citation(s)
knowledge base ready
```

**`0 unresolved citation(s)` is the line that matters.** It means every RFC citation
in the diagnostic catalog resolves to a section actually present in the corpus.

Open **http://localhost:8080**. The sidebar should read `65 checks · 1,440 RFC
sections`.

---

## 5. Developer extras (optional)

Only needed to run the test suite or the `analyze.py` / `kb.py` command line tools.
Requires Python 3.11 or newer (`python3 --version`; on macOS `brew install python`).

```bash
make dev            # virtualenv + dev dependencies
make test           # 30 passed
make lint
./.venv/bin/python analyze.py capture.pcap
./.venv/bin/python kb.py code 481
```

---

## Verifying the install

```bash
curl -s localhost:8080/api/health
```

```json
{"ok":true,"checks":65,"sections":1440,"traces":0,"anthropic_key_present":true}
```

Then generate a fixture with a known fault and upload it through the UI:

```bash
make dev
./.venv/bin/python -c "import sys;sys.path.insert(0,'.');from tests import scenarios;scenarios.nat_private()"
```

Drag `tests/data/nat.pcap` onto the drop zone — four findings, three critical.

---

## Day-to-day

| Task | Command |
|---|---|
| Start | `make up` |
| Stop, keeping data | `make down` |
| Logs | `make logs` |
| Rebuild after code changes | `make up` |
| Rebuild the knowledge base | `make load` |
| Refresh the RFC corpus from the internet | `make corpus` then `make load` |
| Wipe and start over | `make reset` |
| psql shell | `make shell-db` |

`make help` lists every target.

### Frontend development

For hot reload, run the frontend outside Docker against the containerised API:

```bash
cd web && npm install && npm run dev      # http://localhost:5173
```

`vite.config.ts` proxies `/api` to `localhost:8000`, so also publish the API port by
adding `ports: ["8000:8000"]` to the `api` service.

---

## Persistence

Data lives in two named Docker volumes, not in the containers:

| Volume | Holds | Survives |
|---|---|---|
| `sip-trace-analyzer_siptrace-pgdata` | knowledge base, traces, consults, candidate facts | restart, `down`, reboot |
| `sip-trace-analyzer_siptrace-uploads` | the uploaded capture files | same |

Both are destroyed by `docker compose down -v` (`make reset`), which is safe — the
next start rebuilds the knowledge base from the bundled corpus automatically.

**Schema changes no longer need a wipe.** `db/schema.sql` is the baseline for a fresh
database; anything after that goes in `db/migrations/NNN_name.sql` and is applied at
API startup, recorded in `schema_migration` so it runs once. See CONTRIBUTING.md.

---

## Changing ports

Both are in `docker-compose.yml`:

```yaml
web:
  ports: ["8080:80"]        # the UI
db:
  ports: ["55432:5432"]     # only needed if you want psql from the host
```

If you change the Postgres port and run the loaders from the host, point them at it:

```bash
SIPTRACE_DSN=postgresql://siptrace:siptrace@localhost:15432/siptrace ./.venv/bin/python ingest/load_rfcs.py
```

---

## What talks to the network

| Action | Leaves the machine |
|---|---|
| Install, start, build the knowledge base | **Nothing** (after the Docker base images are pulled) |
| Upload, analyse, ladder, export, KB queries | **Nothing** |
| `make corpus` | Fetches from rfc-editor.org and iana.org — only when you ask |
| **Consult** | One request to the Anthropic API, per click, after a confirmation step |

A consult sends the diagnostic catalog, the knowledge-base notes, and this trace's
findings and call summaries. **It does not send the capture file, message bodies, or
any other trace.** The confirmation panel shows the payload description and a cost
estimate first, and that estimate is computed locally — preparing a consult makes no
network request at all.

Anything the model returns is quarantined in `kb_fact_candidate`. It reaches the
knowledge base only when you approve it *and* its RFC citations resolve against the
local corpus.

---

## Troubleshooting

**Sidebar says "knowledge base unreachable"** — the API cannot reach Postgres, or the
bootstrap load failed. `make logs`.

**`0 unresolved citation(s)` shows a non-zero count** — the corpus is incomplete.
`ls rfc/*.txt | wc -l` should print 33; restore the missing files or run
`make corpus`.

**Upload returns "could not analyse that file"** — the file has no parseable SIP. For
a pcap, check with `tshark -r file.pcap -Y sip | head`. SIP over TLS cannot be read
without decryption.

**Consult button disabled** — `ANTHROPIC_API_KEY` is not set in `.env`, or the
container has not restarted since you set it: `docker compose up -d --force-recreate api`.

**Consult fails with 502** — read the real error: `make logs`.

**Port 8080 already in use** — change the `web` port mapping and restart. On macOS,
also check that nothing else (AirPlay Receiver uses 5000, not 8080) has claimed it:
`lsof -i :8080`.

**Apple Silicon: "image platform mismatch"** — every base image here is multi-arch,
so this normally means a stale cached image. `docker compose build --no-cache`.

**`make` not found on macOS** — `xcode-select --install`, or run the `docker compose`
commands from the Makefile directly.
