import { useCallback, useEffect, useState } from "react";
import { api, type TraceDetail, type TraceSummary } from "./api";
import { ConsultPanel } from "./components/ConsultPanel";
import { Ladder } from "./components/Ladder";
import { ReportView } from "./components/ReportView";
import { Upload } from "./components/Upload";

type Tab = "findings" | "ladder" | "consult";

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export default function App() {
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [detail, setDetail] = useState<TraceDetail | null>(null);
  const [tab, setTab] = useState<Tab>("findings");
  // Set when a call row asks the ladder to show just that Call-ID.
  const [ladderCall, setLadderCall] = useState<string | null>(null);
  const [showArchived, setShowArchived] = useState(false);
  const [counts, setCounts] = useState({ active: 0, archived: 0 });
  const [health, setHealth] = useState<{ checks: number; sections: number;
    anthropic_key_present: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refreshList = useCallback(async () => {
    try {
      const [list, c] = await Promise.all([
        api.listTraces(showArchived),
        api.traceCounts(),
      ]);
      setTraces(list);
      setCounts(c);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [showArchived]);

  async function setArchived(id: number, archived: boolean) {
    // Drop the row first and reconcile after. Archiving is two round trips — the
    // list and the counts — and waiting for both leaves the entry sitting there
    // long enough to read as 'nothing happened', which is the one thing this
    // button must never look like.
    const previous = traces;
    setTraces((list) => list.filter((t) => t.id !== id));
    // The trace leaves whichever list is on screen, so drop the open report too.
    if (selected === id) setSelected(null);
    setError(null);
    try {
      await (archived ? api.archiveTrace(id) : api.restoreTrace(id));
      void refreshList();
    } catch (e) {
      setTraces(previous);                  // it never left the server; put it back
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  const refreshDetail = useCallback(async () => {
    if (selected === null) return;
    try {
      setDetail(await api.getTrace(selected));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [selected]);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
    void refreshList();
  }, [refreshList]);

  useEffect(() => {
    setDetail(null);
    setLadderCall(null);          // a Call-ID belongs to the trace it came from
    void refreshDetail();
  }, [selected, refreshDetail]);

  async function reanalyse(id: number) {
    setBusy(true);
    setError(null);
    try {
      await api.reanalyse(id);
      await Promise.all([refreshDetail(), refreshList()]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: number) {
    await api.deleteTrace(id);
    if (selected === id) setSelected(null);
    void refreshList();
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <h1>SIP Trace Analyzer</h1>
          <span>deterministic, RFC-cited</span>
        </div>
        <p className="kbline">
          {health
            ? `${health.checks} checks · ${health.sections.toLocaleString()} RFC sections`
            : "knowledge base unreachable"}
        </p>

        <Upload
          onUploaded={(t) => {
            setShowArchived(false);
            void refreshList();
            setSelected(t.id);
            setTab("findings");
          }}
        />

        <div className="listhead">
          <span>{showArchived ? "Archived" : "Traces"}</span>
          <button
            className="linkish"
            disabled={!showArchived && counts.archived === 0}
            onClick={() => { setShowArchived(!showArchived); setSelected(null); }}
          >
            {showArchived
              ? `back to ${counts.active} active`
              : `${counts.archived} archived`}
          </button>
        </div>

        <ul className="tracelist">
          {traces.map((t) => (
            <li
              key={t.id}
              className={t.id === selected ? "active" : ""}
              onClick={() => setSelected(t.id)}
            >
              <div className="name">
                {t.filename}
                <button
                  className="dismiss"
                  title={showArchived
                    ? "Put this back in the working list"
                    : "Archive: remove from this list, keeping the file and its report"}
                  onClick={(e) => {
                    e.stopPropagation();          // do not also select the trace
                    void setArchived(t.id, !showArchived);
                  }}
                >
                  {showArchived ? "↩" : "×"}
                </button>
              </div>
              <div className="meta">
                {/* Both numbers, always: the Call-ID count on its own is the one
                    that disagrees with what a VoIP analyser reports. */}
                <span title="calls (INVITE dialogs) of total Call-IDs">
                  {t.call_count} call{t.call_count === 1 ? "" : "s"}
                  {t.call_id_count != null && t.call_id_count !== t.call_count
                    ? ` / ${t.call_id_count} Call-IDs`
                    : ""}
                </span>
                <span>{bytes(t.size_bytes)}</span>
                <span>{t.kind}</span>
                {t.consultations ? <span>{t.consultations} consult</span> : null}
              </div>
              <div className="meta" style={{ marginTop: 3 }}>
                {t.worst_severity ? (
                  <span className={`badge ${t.worst_severity}`}>
                    {t.finding_count} finding{t.finding_count === 1 ? "" : "s"}
                  </span>
                ) : (
                  <span className="badge clean">clean</span>
                )}
              </div>
            </li>
          ))}
        </ul>
        {traces.length === 0 && (
          <p style={{ color: "var(--dim)", fontSize: 12 }}>
            {showArchived
              ? "Nothing archived."
              : counts.archived > 0
                ? "No traces here — drop one above, or bring one back from the archive."
                : "No traces uploaded yet."}
          </p>
        )}
      </aside>

      <main className="main">
        {error && <p className="error">{error}</p>}

        {!detail ? (
          <div className="empty">
            {selected === null
              ? "Upload a trace, or pick one from the list."
              : "Loading…"}
          </div>
        ) : (
          <>
            <div className="toolbar">
              <h2 className="title">{detail.filename}</h2>
              <span className="grow" />
              <button
                disabled={busy}
                title="Re-run the checks over the stored capture, in place"
                onClick={() => void reanalyse(detail.id)}
              >
                {busy ? "Re-analysing…" : "Re-analyse"}
              </button>
              <a href={api.exportUrl(detail.id, "json")}><button>Export JSON</button></a>
              <a href={api.exportUrl(detail.id, "markdown")}><button>Export Markdown</button></a>
              <a href={api.exportUrl(detail.id, "csv")}><button>Export CSV</button></a>
              <button className="danger" onClick={() => void remove(detail.id)}>Delete</button>
            </div>

            <div className="toolbar">
              {(["findings", "ladder", "consult"] as const).map((t) => (
                <button
                  key={t}
                  className={tab === t ? "primary" : ""}
                  onClick={() => setTab(t)}
                >
                  {t === "consult"
                    ? `Consult${detail.consultations.length ? ` (${detail.consultations.length})` : ""}`
                    : t[0].toUpperCase() + t.slice(1)}
                </button>
              ))}
            </div>

            {tab === "findings" && (
              <ReportView
                trace={detail}
                onOpenLadder={(callId) => { setLadderCall(callId); setTab("ladder"); }}
              />
            )}
            {tab === "ladder" && (
              <Ladder
                traceId={detail.id}
                focusCallId={ladderCall}
                onClearFocus={() => setLadderCall(null)}
              />
            )}
            {tab === "consult" && (
              <ConsultPanel
                traceId={detail.id}
                consultations={detail.consultations}
                keyPresent={health?.anthropic_key_present ?? false}
                onChanged={() => { void refreshDetail(); void refreshList(); }}
              />
            )}
          </>
        )}
      </main>
    </div>
  );
}
