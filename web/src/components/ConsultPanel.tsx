import { useState } from "react";
import { api, type ConsultEstimate, type Consultation, type FactCandidate } from "../api";

function Fact({ fact, onChanged }: { fact: FactCandidate; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function act(kind: "approve" | "reject") {
    setBusy(true);
    setError(null);
    try {
      await (kind === "approve" ? api.approveFact(fact.id) : api.rejectFact(fact.id));
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={`fact${fact.citations_ok ? "" : " bad-citation"}`}>
      <span className="topic">{fact.topic}</span>
      <p style={{ margin: "4px 0" }}>{fact.fact}</p>

      {fact.rfc_refs.length > 0 && (
        <p className="mono" style={{ color: "var(--dim)", margin: 0 }}>
          {fact.rfc_refs.join("  ·  ")}
        </p>
      )}
      {fact.rfc_refs.length === 0 && (
        <p style={{ color: "var(--dim)", margin: 0 }}>no citation offered</p>
      )}
      {fact.unresolved_refs.length > 0 && (
        <p style={{ color: "var(--major)", margin: "4px 0 0" }}>
          These citations do not exist in the local RFC corpus, so this fact cannot be
          accepted: <span className="mono">{fact.unresolved_refs.join(", ")}</span>
        </p>
      )}

      {fact.status === "pending" ? (
        <div className="row">
          <button
            className="primary"
            disabled={busy || !fact.citations_ok}
            title={fact.citations_ok ? "" : "citations must resolve first"}
            onClick={() => void act("approve")}
          >
            Add to knowledge base
          </button>
          <button disabled={busy} onClick={() => void act("reject")}>Reject</button>
          {error && <span className="error">{error}</span>}
        </div>
      ) : (
        <p style={{ margin: "8px 0 0", color: "var(--dim)" }}>
          {fact.status === "approved" ? "Added to the knowledge base." : "Rejected."}
        </p>
      )}
    </div>
  );
}

function PastConsult({ c, onChanged }: { c: Consultation; onChanged: () => void }) {
  const cached = c.cache_read_tokens ?? 0;
  return (
    <div className="panel">
      <h3>
        {c.model}
        {c.served_by && c.served_by !== c.model ? ` (answered by ${c.served_by})` : ""}
        {" — "}
        {new Date(c.created_at).toLocaleString()}
      </h3>

      {c.error ? (
        <p className="error">{c.error}</p>
      ) : (
        <p className="interpretation">{c.interpretation}</p>
      )}

      {c.facts.length > 0 && (
        <>
          <h3 style={{ marginTop: 18 }}>Candidate facts</h3>
          {c.facts.map((f) => <Fact key={f.id} fact={f} onChanged={onChanged} />)}
        </>
      )}

      <p style={{ color: "var(--dim)", fontSize: 12, marginBottom: 0 }}>
        {c.input_tokens} input · {c.output_tokens} output
        {cached > 0 ? ` · ${cached} read from cache` : ""}
        {c.question ? ` · asked: "${c.question}"` : ""}
      </p>
    </div>
  );
}

export function ConsultPanel({
  traceId, consultations, keyPresent, onChanged,
}: {
  traceId: number;
  consultations: Consultation[];
  keyPresent: boolean;
  onChanged: () => void;
}) {
  const [question, setQuestion] = useState("");
  const [estimate, setEstimate] = useState<ConsultEstimate | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function prepare() {
    setBusy(true);
    setError(null);
    try {
      setEstimate(await api.consultPreview(traceId, question));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function send() {
    setBusy(true);
    setError(null);
    try {
      const result = await api.consult(traceId, question);
      if (result.error) setError(result.error);
      setEstimate(null);
      setQuestion("");
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="panel">
        <h2>Consult Anthropic</h2>
        <p style={{ color: "var(--dim)", marginTop: 0 }}>
          Everything above was produced locally. This is the only feature that sends
          anything off this machine, and only when you press the second button.
        </p>

        {!keyPresent && (
          <div className="warn">
            <strong>No API key.</strong> Set <code>ANTHROPIC_API_KEY</code> in{" "}
            <code>.env</code> and restart the api container to enable this.
          </div>
        )}

        <textarea
          rows={2}
          placeholder="Optional: ask something specific about this trace."
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
        />

        {!estimate ? (
          <div className="row" style={{ marginTop: 10 }}>
            <button disabled={busy || !keyPresent} onClick={() => void prepare()}>
              {busy ? "…" : "Prepare consult"}
            </button>
          </div>
        ) : (
          <>
            <div className="warn" style={{ marginTop: 14 }}>
              <strong>Nothing has been sent yet.</strong> Pressing the button below makes
              one request to the Anthropic API.
              <dl className="estimate">
                <dt>Model</dt><dd>{estimate.model}, effort {estimate.effort}</dd>
                <dt>Sends</dt>
                <dd>{estimate.sends.join("; ")}</dd>
                <dt>Does not send</dt>
                <dd>{estimate.does_not_send.join("; ")}</dd>
                <dt>Approx. size</dt>
                <dd>
                  ~{estimate.approx_input_tokens.toLocaleString()} input tokens, of which{" "}
                  {estimate.cached_prefix_tokens.toLocaleString()} are the cacheable
                  knowledge-base prefix
                </dd>
                <dt>Estimated cost</dt>
                <dd>
                  ${estimate.estimated_usd_first_call.toFixed(4)} cold,{" "}
                  ${estimate.estimated_usd_cached.toFixed(4)} once the prefix is cached
                  <span style={{ color: "var(--dim)" }}> — a local estimate, not a token count</span>
                </dd>
              </dl>
            </div>
            <div className="row" style={{ display: "flex", gap: 8 }}>
              <button className="primary" disabled={busy} onClick={() => void send()}>
                {busy ? "Waiting for Anthropic…" : "Send to Anthropic"}
              </button>
              <button disabled={busy} onClick={() => setEstimate(null)}>Cancel</button>
            </div>
          </>
        )}

        {error && <p className="error">{error}</p>}
      </div>

      {consultations.map((c) => (
        <PastConsult key={c.id} c={c} onChanged={onChanged} />
      ))}
    </>
  );
}
