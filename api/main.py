"""SIP Trace Analyzer HTTP API.

Everything here runs locally except POST /api/traces/{id}/consult, which is the
single endpoint that talks to Anthropic and only when the user asks it to.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys
import traceback

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse, Response

sys.path.insert(0, "/app")

from analyzer import model as sipmodel  # noqa: E402
from analyzer import readers  # noqa: E402
from analyzer.checks import Context, run_all  # noqa: E402
from analyzer.report import Knowledge, Report  # noqa: E402

from . import consult as consult_mod  # noqa: E402
from . import db, exporters  # noqa: E402

UPLOADS = pathlib.Path(os.environ.get("SIPTRACE_UPLOADS", "/data/uploads"))
MAX_UPLOAD = int(os.environ.get("SIPTRACE_MAX_UPLOAD_MB", "200")) * 1024 * 1024

app = FastAPI(title="SIP Trace Analyzer", version="1.0")
SEVERITY_ORDER = {"critical": 0, "major": 1, "minor": 2, "info": 3}


def bootstrap_knowledge_base() -> None:
    """Build the knowledge base on first start, from the corpus shipped in the image.

    The RFCs and IANA registries are baked into the image, so this needs no network
    and takes a couple of seconds. Re-running the loaders by hand is still supported
    (`make load`); this only fires when the database is empty.
    """
    state = db.row("SELECT (SELECT count(*) FROM rfc) AS rfcs,"
                   " (SELECT count(*) FROM diagnostic_check) AS checks")
    if state["rfcs"] and state["checks"]:
        return

    print("knowledge base is empty; loading the bundled corpus…", flush=True)
    sys.path.insert(0, "/app/ingest")
    import load_protocol
    import load_rfcs

    load_rfcs.main()
    load_protocol.main()
    print("knowledge base ready", flush=True)


@app.on_event("startup")
def startup() -> None:
    UPLOADS.mkdir(parents=True, exist_ok=True)
    db.pool.open(wait=True, timeout=30)
    for name in db.migrate():
        print(f"applied migration {name}", flush=True)
    bootstrap_knowledge_base()


@app.get("/api/health")
def health() -> dict:
    counts = db.row("SELECT (SELECT count(*) FROM diagnostic_check) AS checks,"
                    " (SELECT count(*) FROM rfc_section) AS sections,"
                    " (SELECT count(*) FROM trace) AS traces")
    return {"ok": True, **counts, "anthropic_key_present": bool(
        os.environ.get("ANTHROPIC_API_KEY"))}


# ---------------------------------------------------------------- traces
def analyse(path: pathlib.Path) -> tuple[dict, str]:
    trace = readers.read(path)
    if not trace.messages:
        raise HTTPException(400, "no SIP messages found in that file")
    calls, streams = sipmodel.build(trace)
    ctx = Context(trace=trace, calls=calls, streams=streams)
    findings = run_all(ctx)

    notes = list(trace.notes)
    if not trace.has_media_layer:
        notes.append("text log: RTP checks were not run")
    parse_problems = sum(len(m.parse_errors) for m in trace.messages)
    if parse_problems:
        notes.append(f"{parse_problems} message parse problem(s)")

    report = Report(source=path.name, calls=calls, streams=streams, findings=findings,
                    knowledge=Knowledge.load(db.DSN), notes=notes)
    return json.loads(report.to_json()), ("pcap" if trace.has_media_layer else "text")


@app.post("/api/traces")
async def upload(file: UploadFile) -> dict:
    data = await file.read()
    if not data:
        raise HTTPException(400, "empty file")
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, f"file exceeds {MAX_UPLOAD // 1024 // 1024} MB")

    digest = hashlib.sha256(data).hexdigest()
    path = UPLOADS / f"{digest[:16]}-{pathlib.Path(file.filename or 'trace').name}"
    path.write_bytes(data)

    try:
        report, kind = analyse(path)
    except HTTPException:
        path.unlink(missing_ok=True)
        raise
    except Exception as exc:                                        # noqa: BLE001
        path.unlink(missing_ok=True)
        traceback.print_exc()
        raise HTTPException(400, f"could not analyse that file: {exc}") from exc

    report["source"] = file.filename
    findings = report.get("findings", [])
    worst = min((f["severity"] for f in findings),
                key=lambda s: SEVERITY_ORDER.get(s, 9), default=None)

    stored = db.execute(
        "INSERT INTO trace (filename, size_bytes, sha256, kind, stored_path, report,"
        " message_count, call_count, finding_count, worst_severity)"
        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (file.filename, len(data), digest, kind, str(path), json.dumps(report),
         sum(c["messages"] for c in report.get("calls", [])),
         len(report.get("calls", [])), len(findings), worst),
    )
    return {"id": stored["id"], **summary_of(stored["id"])}


def summary_of(trace_id: int) -> dict:
    t = db.row("SELECT id, filename, uploaded_at, size_bytes, kind, message_count,"
               " call_count, finding_count, worst_severity, archived_at"
               " FROM trace WHERE id=%s", (trace_id,))
    if not t:
        raise HTTPException(404, "no such trace")
    return t


@app.get("/api/traces")
def list_traces(archived: bool = False) -> list[dict]:
    """Active traces by default; pass archived=true for the ones cleared away."""
    return db.rows(
        "SELECT t.id, t.filename, t.uploaded_at, t.size_bytes, t.kind, t.message_count,"
        " t.call_count, t.finding_count, t.worst_severity, t.archived_at,"
        " (SELECT count(*) FROM consultation c WHERE c.trace_id = t.id) AS consultations"
        " FROM trace t WHERE t.archived_at IS " + ("NOT NULL" if archived else "NULL") +
        " ORDER BY t.uploaded_at DESC")


@app.get("/api/traces/counts")
def trace_counts() -> dict:
    return db.row("SELECT count(*) FILTER (WHERE archived_at IS NULL) AS active,"
                  " count(*) FILTER (WHERE archived_at IS NOT NULL) AS archived"
                  " FROM trace")


@app.post("/api/traces/{trace_id}/archive")
def archive_trace(trace_id: int) -> dict:
    """Clear a processed trace out of the working list. Reversible; keeps the file."""
    updated = db.execute("UPDATE trace SET archived_at = now() WHERE id=%s"
                         " AND archived_at IS NULL RETURNING id", (trace_id,))
    if not updated:
        raise HTTPException(404, "no such active trace")
    return {"id": trace_id, "archived": True}


@app.post("/api/traces/{trace_id}/restore")
def restore_trace(trace_id: int) -> dict:
    updated = db.execute("UPDATE trace SET archived_at = NULL WHERE id=%s"
                         " AND archived_at IS NOT NULL RETURNING id", (trace_id,))
    if not updated:
        raise HTTPException(404, "no such archived trace")
    return {"id": trace_id, "archived": False}


@app.get("/api/traces/{trace_id}")
def get_trace(trace_id: int) -> dict:
    t = db.row("SELECT id, filename, uploaded_at, kind, report FROM trace WHERE id=%s",
               (trace_id,))
    if not t:
        raise HTTPException(404, "no such trace")
    return {**t, "consultations": consultations_for(trace_id)}


@app.delete("/api/traces/{trace_id}")
def delete_trace(trace_id: int) -> dict:
    t = db.row("SELECT stored_path FROM trace WHERE id=%s", (trace_id,))
    if not t:
        raise HTTPException(404, "no such trace")
    pathlib.Path(t["stored_path"]).unlink(missing_ok=True)
    db.execute("DELETE FROM trace WHERE id=%s", (trace_id,))
    return {"deleted": trace_id}


def ladder_rows(trace_id: int) -> tuple[list[dict], str]:
    t = db.row("SELECT stored_path, filename FROM trace WHERE id=%s", (trace_id,))
    if not t:
        raise HTTPException(404, "no such trace")
    trace = readers.read(pathlib.Path(t["stored_path"]))
    # Keyed on time_known, not on a non-zero value: a capture may legitimately
    # start at epoch 0, and a log may carry messages with no recorded time.
    t0 = min((m.timestamp for m in trace.messages if m.time_known), default=0.0)
    rows = [{
        "frame": m.frame,
        "at": round(m.timestamp - t0, 6) if m.timestamp else 0.0,
        "src": m.src, "dst": m.dst,
        "request": m.is_request,
        "summary": m.summary(),
        "start_line": m.raw.replace("\r\n", "\n").split("\n", 1)[0],
        "call_id": m.call_id,
        "transport": m.transport,
        "ip_id": m.ip_id,
        "ttl": m.ttl,
        "duplicate_of": m.duplicate_of,
        "headers": m.header_lines(),
        "body": m.body_text,
        "parse_errors": m.parse_errors,
    } for m in trace.messages]
    return rows, t["filename"]


@app.get("/api/traces/{trace_id}/ladder")
def ladder(trace_id: int) -> list[dict]:
    return ladder_rows(trace_id)[0]


@app.get("/api/traces/{trace_id}/ladder/export")
def ladder_export(trace_id: int, fmt: str = "text") -> Response:
    rows, filename = ladder_rows(trace_id)
    stem = pathlib.Path(filename).stem

    if fmt == "text":
        body, media, ext = exporters.ladder_as_text(rows, filename), "text/plain", "txt"
    elif fmt == "markdown":
        body, media, ext = (exporters.ladder_as_markdown(rows, filename),
                            "text/markdown", "md")
    elif fmt == "csv":
        body, media, ext = exporters.ladder_as_csv(rows), "text/csv", "csv"
    elif fmt == "json":
        body, media, ext = json.dumps(rows, indent=2), "application/json", "json"
    else:
        raise HTTPException(400, "fmt must be text, markdown, csv or json")

    return Response(body, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{stem}-ladder.{ext}"'})


@app.get("/api/traces/{trace_id}/export")
def export(trace_id: int, fmt: str = "json") -> Response:
    t = db.row("SELECT filename, report FROM trace WHERE id=%s", (trace_id,))
    if not t:
        raise HTTPException(404, "no such trace")
    report = t["report"]
    stem = pathlib.Path(t["filename"]).stem
    cons = consultations_for(trace_id)

    if fmt == "markdown":
        body, media, ext = exporters.as_markdown(report, cons), "text/markdown", "md"
    elif fmt == "csv":
        body, media, ext = exporters.as_csv(report), "text/csv", "csv"
    elif fmt == "json":
        body, media, ext = exporters.as_json(report, cons), "application/json", "json"
    else:
        raise HTTPException(400, "fmt must be json, markdown or csv")

    return Response(body, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{stem}-analysis.{ext}"'})


# ---------------------------------------------------------------- knowledge base
@app.get("/api/kb/checks")
def kb_checks(category: str | None = None) -> list[dict]:
    sql = ("SELECT id, category, severity, title, symptom, detection, root_causes,"
           " remediation, rfc_refs, confidence FROM diagnostic_check")
    params: list = []
    if category:
        sql += " WHERE category=%s"
        params.append(category)
    return db.rows(sql + " ORDER BY array_position(ARRAY['critical','major','minor','info'],"
                         " severity), id", params)


@app.get("/api/kb/codes/{code}")
def kb_code(code: int) -> dict:
    r = db.row("SELECT code, name, defining_rfc, section, meaning, likely_causes,"
               " next_checks, who_emits, severity, rfc_text FROM response_code"
               " WHERE code=%s", (code,))
    if not r:
        raise HTTPException(404, "no such response code")
    return r


@app.get("/api/kb/rules")
def kb_rules(q: str = "", topic: str | None = None, limit: int = 20) -> list[dict]:
    sql = "SELECT citation, keyword, section_title, text FROM v_rule_search WHERE TRUE"
    params: list = []
    if q:
        sql += " AND to_tsvector('english', text) @@ plainto_tsquery('english', %s)"
        params.append(q)
    if topic:
        sql += " AND %s = ANY(topics)"
        params.append(topic)
    params.append(min(limit, 100))
    return db.rows(sql + " ORDER BY rfc_number, section LIMIT %s", params)


@app.get("/api/kb/section/{rfc}/{section}")
def kb_section(rfc: int, section: str) -> dict:
    r = db.row("SELECT rfc_number, section, title, body FROM rfc_section"
               " WHERE rfc_number=%s AND section=%s", (rfc, section))
    if not r:
        raise HTTPException(404, "no such section")
    return r


# ---------------------------------------------------------------- consult
def consultations_for(trace_id: int) -> list[dict]:
    out = db.rows(
        "SELECT id, created_at, model, served_by, question, interpretation, stop_reason,"
        " input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, error"
        " FROM consultation WHERE trace_id=%s ORDER BY created_at DESC", (trace_id,))
    for c in out:
        c["facts"] = db.rows(
            "SELECT id, topic, fact, rfc_refs, unresolved_refs, citations_ok, status"
            " FROM kb_fact_candidate WHERE consultation_id=%s ORDER BY id", (c["id"],))
    return out


@app.post("/api/traces/{trace_id}/consult/preview")
def consult_preview(trace_id: int, body: dict | None = None) -> dict:
    """What a consult would send and cost. Makes no network request of any kind."""
    t = db.row("SELECT report FROM trace WHERE id=%s", (trace_id,))
    if not t:
        raise HTTPException(404, "no such trace")
    return consult_mod.estimate(t["report"], (body or {}).get("question"))


@app.post("/api/traces/{trace_id}/consult")
def consult_trace(trace_id: int, body: dict | None = None) -> dict:
    """THE Anthropic call. One request, only from an explicit user action."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise HTTPException(400, "ANTHROPIC_API_KEY is not set on the api container; "
                                 "add it to .env and restart")
    t = db.row("SELECT report FROM trace WHERE id=%s", (trace_id,))
    if not t:
        raise HTTPException(404, "no such trace")
    try:
        return consult_mod.consult(trace_id, t["report"], (body or {}).get("question"))
    except Exception as exc:                                        # noqa: BLE001
        traceback.print_exc()
        raise HTTPException(502, f"the consult failed: {exc}") from exc


# ---------------------------------------------------------------- fact review
@app.get("/api/facts")
def facts(status: str = "pending") -> list[dict]:
    return db.rows(
        "SELECT f.id, f.topic, f.fact, f.rfc_refs, f.unresolved_refs, f.citations_ok,"
        " f.status, f.reviewed_at, c.model, c.created_at, t.id AS trace_id, t.filename"
        " FROM kb_fact_candidate f JOIN consultation c ON c.id = f.consultation_id"
        " LEFT JOIN trace t ON t.id = c.trace_id"
        " WHERE f.status = %s ORDER BY f.id DESC", (status,))


@app.post("/api/facts/{fact_id}/approve")
def approve_fact(fact_id: int) -> dict:
    f = db.row("SELECT f.*, c.model FROM kb_fact_candidate f"
               " JOIN consultation c ON c.id = f.consultation_id WHERE f.id=%s", (fact_id,))
    if not f:
        raise HTTPException(404, "no such candidate")
    if f["status"] != "pending":
        raise HTTPException(409, f"already {f['status']}")

    # Re-check citations at approval time; the corpus may have changed since.
    unresolved = db.resolve_citations(f["rfc_refs"] or [])
    if unresolved:
        db.execute("UPDATE kb_fact_candidate SET unresolved_refs=%s, citations_ok=FALSE"
                   " WHERE id=%s", (unresolved, fact_id))
        raise HTTPException(409, "cannot approve: these citations do not resolve against "
                                 f"the local RFC corpus: {', '.join(unresolved)}")

    note = db.execute(
        "INSERT INTO kb_note (topic, note, rfc_refs, source) VALUES (%s,%s,%s,%s)"
        " RETURNING id",
        (f["topic"], f["fact"], f["rfc_refs"] or [], f"anthropic:{f['model']} (reviewed)"))
    db.execute("UPDATE kb_fact_candidate SET status='approved', reviewed_at=now(),"
               " kb_note_id=%s WHERE id=%s", (note["id"], fact_id))
    return {"id": fact_id, "status": "approved", "kb_note_id": note["id"]}


@app.post("/api/facts/{fact_id}/reject")
def reject_fact(fact_id: int) -> dict:
    updated = db.execute("UPDATE kb_fact_candidate SET status='rejected', reviewed_at=now()"
                         " WHERE id=%s AND status='pending' RETURNING id", (fact_id,))
    if not updated:
        raise HTTPException(404, "no such pending candidate")
    return {"id": fact_id, "status": "rejected"}


@app.get("/api/notes", response_class=PlainTextResponse)
def notes_plain() -> str:
    return "\n".join(f"[{n['topic']}] {n['note']}  ({', '.join(n['rfc_refs'] or [])})"
                     f"  — {n['source'] or 'curated'}"
                     for n in db.rows("SELECT topic, note, rfc_refs, source FROM kb_note"
                                      " ORDER BY id"))
