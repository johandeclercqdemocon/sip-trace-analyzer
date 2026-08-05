import { useEffect, useMemo, useState } from "react";
import { api, type LadderRow } from "../api";
import { Chips, FilterBar, matches, Search, Toggle, tally } from "./Filters";

function Row({ row, open, onToggle }: {
  row: LadderRow; open: boolean; onToggle: () => void;
}) {
  const l3 = [
    row.ip_id !== null ? `ip-id ${row.ip_id}` : null,
    row.ttl !== null ? `ttl ${row.ttl}` : null,
    row.transport,
  ].filter(Boolean).join(" · ");

  return (
    <>
      <tr
        onClick={onToggle}
        className={row.duplicate_of ? "dup" : ""}
        title={row.duplicate_of ? `duplicate of frame ${row.duplicate_of}` : "click to expand"}
      >
        <td className="dim right">{open ? "▾" : "▸"} {row.frame}</td>
        <td className="dim right">{row.at ? `${row.at.toFixed(3)}s` : ""}</td>
        <td className="right">{row.src}</td>
        <td className="arrow">{row.request ? "──▶" : "◀──"}</td>
        <td>{row.dst}</td>
        <td className={row.request ? "req" : "res"}>
          {row.summary}
          {row.duplicate_of ? (
            <span className="dupflag" title={`duplicate of frame ${row.duplicate_of}`}>
              {" "}⧉ dup of {row.duplicate_of}
            </span>
          ) : null}
        </td>
      </tr>
      {open && (
        <tr className="expansion">
          <td colSpan={6}>
            <div className="msg">
              <div className="dim l3">{l3}</div>
              <div className="startline">{row.start_line}</div>
              <table className="headers">
                <tbody>
                  {row.headers.map(([name, value], i) => (
                    <tr key={i}>
                      <td className="hname">{name}</td>
                      <td className="hvalue">{value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {row.body && <pre className="body">{row.body.trimEnd()}</pre>}
              {row.parse_errors.length > 0 && (
                <p className="error">{row.parse_errors.join("; ")}</p>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export function Ladder({ traceId, focusCallId, onClearFocus }: {
  traceId: number;
  focusCallId?: string | null;
  onClearFocus?: () => void;
}) {
  const [rows, setRows] = useState<LadderRow[] | null>(null);
  const [open, setOpen] = useState<Set<number>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [methods, setMethods] = useState<Set<string>>(new Set());
  const [hideDuplicates, setHideDuplicates] = useState(false);

  useEffect(() => {
    setRows(null);
    setOpen(new Set());
    setError(null);
    api.ladder(traceId).then(setRows).catch((e) => setError(String(e)));
  }, [traceId]);

  const methodCounts = useMemo(
    () => tally(rows ?? [], (r) => r.method || "?"), [rows]);

  function toggle(frame: number) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (!next.delete(frame)) next.add(frame);
      return next;
    });
  }

  if (error) return <div className="panel error">{error}</div>;
  if (!rows) return <div className="panel spinner">Loading the message ladder…</div>;

  // Ordered by how much of the trace each method accounts for: on a trunk
  // capture that puts OPTIONS first, which is exactly what you want to switch off.
  const methodOptions = Object.entries(methodCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([m, n]) => ({ value: m, label: m, count: n }));

  const shown = rows.filter((r) =>
    (!focusCallId || r.call_id === focusCallId) &&
    (methods.size === 0 || methods.has(r.method || "?")) &&
    (!hideDuplicates || !r.duplicate_of) &&
    matches(query, r.summary, r.src, r.dst, r.call_id, r.frame, r.status,
            r.start_line));

  const duplicates = shown.filter((r) => r.duplicate_of).length;
  const allOpen = shown.length > 0 && shown.every((r) => open.has(r.frame));
  const filtered = shown.length !== rows.length;

  return (
    <div className="panel">
      <div className="toolbar" style={{ marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Message ladder</h2>
        <span className="grow" />
        <button onClick={() => setOpen(allOpen ? new Set() : new Set(shown.map((r) => r.frame)))}>
          {allOpen ? "Collapse all" : "Expand all"}
        </button>
        <a href={api.ladderExportUrl(traceId, "text")}><button>Export .txt</button></a>
        <a href={api.ladderExportUrl(traceId, "markdown")}><button>Export .md</button></a>
        <a href={api.ladderExportUrl(traceId, "csv")}><button>Export CSV</button></a>
        <a href={api.ladderExportUrl(traceId, "json")}><button>Export JSON</button></a>
      </div>

      <FilterBar>
        <Chips
          options={methodOptions}
          selected={methods}
          onChange={setMethods}
          allLabel={`all ${rows.length}`}
        />
        <Toggle
          on={hideDuplicates}
          onChange={setHideDuplicates}
          label="hide duplicates"
          title="Hide the frames the capture recorded more than once"
        />
        <span className="grow" />
        <Search value={query} onChange={setQuery} placeholder="address, status, text…" />
      </FilterBar>

      {focusCallId && (
        <p className="focus">
          One Call-ID only: <span className="mono">{focusCallId}</span>{" "}
          <button className="linkish" onClick={onClearFocus}>show the whole trace</button>
        </p>
      )}

      <p className="dim" style={{ marginTop: 0 }}>
        {shown.length} message{shown.length === 1 ? "" : "s"}
        {filtered && <> of {rows.length}</>}
        {duplicates > 0 && (
          <> · <span className="dupflag">{duplicates} duplicated frame
            {duplicates === 1 ? "" : "s"}</span>, excluded from transaction analysis</>
        )}
        {" "}· click a row to expand its headers
        {filtered && <> · the exports above always carry the whole trace</>}
      </p>

      <div className="scroll-x">
        <table className="ladder mono">
          <tbody>
            {shown.map((r) => (
              <Row key={r.frame} row={r} open={open.has(r.frame)}
                   onToggle={() => toggle(r.frame)} />
            ))}
          </tbody>
        </table>
      </div>
      {shown.length === 0 && <p className="dim">No message matches these filters.</p>}
    </div>
  );
}
