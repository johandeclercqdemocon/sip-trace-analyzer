import { useEffect, useState } from "react";
import { api, type LadderRow } from "../api";

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

export function Ladder({ traceId }: { traceId: number }) {
  const [rows, setRows] = useState<LadderRow[] | null>(null);
  const [open, setOpen] = useState<Set<number>>(new Set());
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setRows(null);
    setOpen(new Set());
    setError(null);
    api.ladder(traceId).then(setRows).catch((e) => setError(String(e)));
  }, [traceId]);

  function toggle(frame: number) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (!next.delete(frame)) next.add(frame);
      return next;
    });
  }

  if (error) return <div className="panel error">{error}</div>;
  if (!rows) return <div className="panel spinner">Loading the message ladder…</div>;

  const duplicates = rows.filter((r) => r.duplicate_of).length;
  const allOpen = open.size === rows.length;

  return (
    <div className="panel">
      <div className="toolbar" style={{ marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Message ladder</h2>
        <span className="grow" />
        <button onClick={() => setOpen(allOpen ? new Set() : new Set(rows.map((r) => r.frame)))}>
          {allOpen ? "Collapse all" : "Expand all"}
        </button>
        <a href={api.ladderExportUrl(traceId, "text")}><button>Export .txt</button></a>
        <a href={api.ladderExportUrl(traceId, "markdown")}><button>Export .md</button></a>
        <a href={api.ladderExportUrl(traceId, "csv")}><button>Export CSV</button></a>
        <a href={api.ladderExportUrl(traceId, "json")}><button>Export JSON</button></a>
      </div>

      <p className="dim" style={{ marginTop: 0 }}>
        {rows.length} message{rows.length === 1 ? "" : "s"}
        {duplicates > 0 && (
          <> · <span className="dupflag">{duplicates} duplicated frame
            {duplicates === 1 ? "" : "s"}</span>, excluded from transaction analysis</>
        )}
        {" "}· click a row to expand its headers
      </p>

      <div className="scroll-x">
        <table className="ladder mono">
          <tbody>
            {rows.map((r) => (
              <Row key={r.frame} row={r} open={open.has(r.frame)}
                   onToggle={() => toggle(r.frame)} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
