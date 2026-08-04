"""The only place in SIP Trace Analyzer that calls Anthropic.

One request per consult, triggered explicitly by the user. Nothing else in the
product — upload, analysis, export, knowledge-base queries — sends anything
anywhere. Everything the model returns is quarantined in kb_fact_candidate until
a human approves it and its citations resolve against the local RFC corpus.
"""
from __future__ import annotations

import json
import os

import anthropic

from . import db

MODEL = os.environ.get("SIPTRACE_CONSULT_MODEL", "claude-opus-5")
EFFORT = os.environ.get("SIPTRACE_CONSULT_EFFORT", "medium")
MAX_TOKENS = int(os.environ.get("SIPTRACE_CONSULT_MAX_TOKENS", "16000"))

# Prices per million tokens, for the cost estimate shown before the user commits.
PRICING = {"claude-opus-5": (5.0, 25.0), "claude-sonnet-5": (3.0, 15.0),
           "claude-haiku-4-5": (1.0, 5.0)}

ROLE = """\
You are a SIP protocol analyst. You are given findings produced by a deterministic
analyser that has already reconstructed the transactions and dialogs of a packet
trace, plus the catalog of checks it can emit.

Your job is to interpret the findings as an engineer would: say what is actually
happening on this call, which finding is the cause and which are consequences, and
what the operator should look at. Be concrete and short. Do not restate the
findings back; the reader can already see them.

Then propose zero or more durable facts worth adding to the knowledge base. A good
candidate fact is general interop knowledge that would help diagnose a future
trace, not an observation about this specific capture. Propose none rather than
padding the list.

Rules for candidate facts:
- Cite RFC sections as "RFC3261#17.1.1.3" (RFC number, '#', section number).
- Only cite a section you are confident exists and says what you claim. Every
  citation is checked against a local copy of the RFC before the fact can be
  accepted, and a fact with a bad citation is rejected.
- If you are not confident of a citation, return the fact with an empty rfc_refs
  list rather than guessing a section number.
"""

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "interpretation": {
            "type": "string",
            "description": "Markdown. What is happening on this call, cause vs consequence, "
                           "and what to check next.",
        },
        "facts": {
            "type": "array",
            "description": "Durable interop facts worth storing. May be empty.",
            "items": {
                "type": "object",
                "properties": {
                    "topic": {"type": "string", "description": "Short slug, e.g. 'nat' or 'ack'."},
                    "fact": {"type": "string", "description": "One or two sentences."},
                    "rfc_refs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Citations as RFC3261#17.1.1.3. Empty if unsure.",
                    },
                },
                "required": ["topic", "fact", "rfc_refs"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["interpretation", "facts"],
    "additionalProperties": False,
}


def knowledge_prefix() -> str:
    """The stable half of the prompt: identical for every consult, so it caches."""
    parts = ["# Check catalog\n"]
    for c in db.rows(
        "SELECT id, category, severity, title, symptom, detection, root_causes,"
        " remediation, rfc_refs FROM diagnostic_check ORDER BY id"
    ):
        parts.append(
            f"## {c['id']} ({c['severity']}, {c['category']})\n"
            f"{c['title']}\n"
            f"Symptom: {c['symptom']}\n"
            f"Detection: {c['detection']}\n"
            f"Causes: {'; '.join(c['root_causes'] or [])}\n"
            f"Fix: {c['remediation']}\n"
            f"Refs: {', '.join(c['rfc_refs'] or [])}\n"
        )
    parts.append("\n# Interop notes already in the knowledge base\n")
    for n in db.rows("SELECT topic, note, rfc_refs FROM kb_note ORDER BY id"):
        parts.append(f"- [{n['topic']}] {n['note']} ({', '.join(n['rfc_refs'] or [])})")
    parts.append("\n# Response code meanings already in the knowledge base\n")
    for r in db.rows("SELECT code, name, meaning FROM response_code"
                     " WHERE meaning IS NOT NULL ORDER BY code"):
        parts.append(f"- {r['code']} {r['name']}: {r['meaning']}")
    return "\n".join(parts)


def trace_context(report: dict, question: str | None) -> str:
    """The volatile half: this trace only. Goes after the cached prefix."""
    lines = [f"# Trace: {report.get('source', 'unknown')}\n", "## Calls"]
    for c in report.get("calls", []):
        lines.append(f"- {c.get('label')} — {c.get('outcome')}, {c.get('messages')} messages, "
                     f"{c.get('dialogs')} dialog(s)")
    streams = report.get("streams", [])
    if streams:
        lines.append("\n## RTP streams")
        for s in streams:
            lines.append(f"- {s['src']} -> {s['dst']} ssrc 0x{s['ssrc']:08x}: "
                         f"{s['packets']} packets over {s['duration']}s, "
                         f"loss {s['loss_ratio'] * 100:.2f}%, jitter {s['jitter_ms']} ms")
    lines.append("\n## Findings")
    if not report.get("findings"):
        lines.append("(none — the analyser found no problems)")
    for f in report.get("findings", []):
        lines.append(f"\n### [{f['severity']}] {f['check_id']} — {f.get('title')}")
        lines.append(f"call: {f.get('call') or '-'}  at +{f.get('at_relative', 0)}s")
        lines.append(f["detail"])
        for e in f.get("evidence", [])[:4]:
            lines.append(f"  | {e}")
    for note in report.get("notes", []):
        lines.append(f"\nAnalyser note: {note}")
    lines.append("\n# Question\n" + (question or
                 "Interpret these findings and propose any durable facts worth storing."))
    return "\n".join(lines)


def estimate(report: dict, question: str | None) -> dict:
    """Local cost estimate. Deliberately does not call the API - counting tokens
    server-side would itself be a request, and the point of this step is that the
    user sees the cost before anything leaves the machine."""
    prefix = knowledge_prefix()
    context = trace_context(report, question)
    # ~3.6 characters per token is a reasonable approximation for English prose.
    prefix_tokens = int(len(prefix) / 3.6)
    context_tokens = int(len(ROLE + context) / 3.6)
    out_tokens = 2000
    in_price, out_price = PRICING.get(MODEL, (5.0, 25.0))
    cold = (prefix_tokens * 1.25 + context_tokens) * in_price / 1e6 + \
        out_tokens * out_price / 1e6
    warm = (prefix_tokens * 0.1 + context_tokens) * in_price / 1e6 + \
        out_tokens * out_price / 1e6
    return {
        "model": MODEL,
        "effort": EFFORT,
        "approx_input_tokens": prefix_tokens + context_tokens,
        "cached_prefix_tokens": prefix_tokens,
        "approx_output_tokens": out_tokens,
        "estimated_usd_first_call": round(cold, 4),
        "estimated_usd_cached": round(warm, 4),
        "sends": ["the check catalog and knowledge-base notes (identical every time)",
                  "this trace's findings, call summaries and RTP statistics",
                  "your question"],
        "does_not_send": ["the packet capture itself", "message bodies", "any other trace"],
    }


def _request(client: anthropic.Anthropic, system: list, user: str, *, with_fallback: bool):
    kwargs = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "output_config": {"effort": EFFORT,
                          "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}},
    }
    if with_fallback:
        # A refused request is re-served by Anthropic's recommended fallback model
        # inside the same call, instead of coming back empty.
        return client.beta.messages.create(
            betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
    return client.messages.create(**kwargs)


def consult(trace_id: int, report: dict, question: str | None) -> dict:
    """Make the one Anthropic request and quarantine everything it returns."""
    client = anthropic.Anthropic()

    system = [
        {"type": "text", "text": ROLE},
        # Stable prefix last in the system array, with the cache breakpoint on it:
        # tools -> system -> messages is the render order, so this caches the lot.
        {"type": "text", "text": knowledge_prefix(),
         "cache_control": {"type": "ephemeral"}},
    ]
    user = trace_context(report, question)

    try:
        response = _request(client, system, user, with_fallback=True)
    except anthropic.BadRequestError:
        # The fallback beta is not enabled for this key; the consult still works.
        response = _request(client, system, user, with_fallback=False)

    usage = response.usage
    consultation = db.execute(
        "INSERT INTO consultation (trace_id, model, served_by, question, interpretation,"
        " stop_reason, input_tokens, output_tokens, cache_read_tokens,"
        " cache_creation_tokens, error)"
        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (trace_id, MODEL, getattr(response, "model", None), question, None,
         response.stop_reason, usage.input_tokens, usage.output_tokens,
         getattr(usage, "cache_read_input_tokens", None),
         getattr(usage, "cache_creation_input_tokens", None), None),
    )
    cid = consultation["id"]

    if response.stop_reason == "refusal":
        detail = getattr(response, "stop_details", None)
        reason = f"declined ({getattr(detail, 'category', None) or 'no category'})"
        db.execute("UPDATE consultation SET error=%s WHERE id=%s", (reason, cid))
        return {"id": cid, "error": reason, "interpretation": None, "facts": []}

    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        db.execute("UPDATE consultation SET error=%s WHERE id=%s",
                   (f"unparseable response: {exc}", cid))
        return {"id": cid, "error": "the model returned malformed JSON",
                "interpretation": text[:2000], "facts": []}

    db.execute("UPDATE consultation SET interpretation=%s WHERE id=%s",
               (parsed.get("interpretation"), cid))

    facts = []
    for f in parsed.get("facts", []):
        refs = [r.strip() for r in (f.get("rfc_refs") or []) if r and r.strip()]
        unresolved = db.resolve_citations(refs)
        stored = db.execute(
            "INSERT INTO kb_fact_candidate (consultation_id, topic, fact, rfc_refs,"
            " unresolved_refs, citations_ok) VALUES (%s,%s,%s,%s,%s,%s)"
            " RETURNING id, topic, fact, rfc_refs, unresolved_refs, citations_ok, status",
            (cid, (f.get("topic") or "general")[:64], f.get("fact") or "",
             refs, unresolved, not unresolved),
        )
        facts.append(stored)

    return {
        "id": cid,
        "error": None,
        "interpretation": parsed.get("interpretation"),
        "facts": facts,
        "usage": {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", 0),
            "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", 0),
            "served_by": getattr(response, "model", MODEL),
        },
    }
