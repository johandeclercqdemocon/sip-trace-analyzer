import { useEffect, useMemo, useState } from "react";
import { api, type LadderPayload, type LadderRow, type MediaRow } from "../api";
import { Chips, FilterBar, matches, Search, Toggle, tally } from "./Filters";
import {
  columnKey, columnsFor, DEFAULT_ZOOM, Flow, type FlowItem, ZOOM_STEPS,
} from "./Flow";

function Expansion({ row, onCollapse }: {
  row: LadderRow; onCollapse: () => void;
}) {
  const l3 = [
    row.ip_id !== null ? `ip-id ${row.ip_id}` : null,
    row.ttl !== null ? `ttl ${row.ttl}` : null,
    row.link_type || null,
    row.transport,
    row.leg !== null ? `leg ${row.leg}` : null,
    row.src_device && row.dst_device ? `${row.src_device} → ${row.dst_device}` : null,
    row.src_realms.length ? `realms ${row.src_realms.join(", ")}` : null,
  ].filter(Boolean).join(" · ");

  return (
    <div className="msg">
      {/* A long message pushes its own row off the top of the screen, so without
          this the only way back to the toggle was to scroll up for it. */}
      <button
        className="close"
        onClick={(e) => { e.stopPropagation(); onCollapse(); }}
        title={`Collapse frame ${row.frame} (Esc collapses all)`}
        aria-label={`Collapse frame ${row.frame}`}
      >
        ×
      </button>
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
  );
}

function Row({ row, open, onToggle }: {
  row: LadderRow; open: boolean; onToggle: () => void;
}) {
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
          <td colSpan={6}><Expansion row={row} onCollapse={onToggle} /></td>
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
  const [data, setData] = useState<LadderPayload | null>(null);
  const [open, setOpen] = useState<Set<number>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [methods, setMethods] = useState<Set<string>>(new Set());
  const [hideDuplicates, setHideDuplicates] = useState(false);
  const [hiddenDevices, setHiddenDevices] = useState<Set<string>>(new Set());
  const [legs, setLegs] = useState<Set<string>>(new Set());
  const [showMedia, setShowMedia] = useState(true);
  const [view, setView] = useState<"flow" | "rows">("flow");
  const [zoom, setZoom] = useState(DEFAULT_ZOOM);

  useEffect(() => {
    setData(null);
    setOpen(new Set());
    setError(null);
    setHiddenDevices(new Set());
    setLegs(new Set());
    api.ladder(traceId).then(setData).catch((e) => setError(String(e)));
  }, [traceId]);

  const rows = data?.rows ?? [];
  const media = useMemo(() => data?.media ?? [], [data]);

  const methodCounts = useMemo(() => tally(rows, (r) => r.method || "?"), [rows]);

  // Legs are the source's own numbering and differ from call to call: they need
  // not start at zero, be contiguous, or be present at all. Built from the data
  // every time rather than assumed, and sorted numerically so 10 follows 9.
  const legCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const r of [...rows, ...media]) {
      if (r.leg === null) continue;
      out[String(r.leg)] = (out[String(r.leg)] ?? 0) + 1;
    }
    return out;
  }, [rows, media]);
  const legOptions = useMemo(
    () => Object.entries(legCounts)
      .sort((a, b) => Number(a[0]) - Number(b[0]))
      .map(([leg, n]) => ({ value: leg, label: `leg ${leg}`, count: n })),
    [legCounts]);

  // Every column the trace uses, whether the source named devices or not. Built
  // before any filter so switching a device off never removes it from the list
  // that switches it back on.
  const allColumns = useMemo(() => {
    const items = [
      ...rows.map((r) => ({ from: columnKey(r.src_device, r.src),
                            to: columnKey(r.dst_device, r.dst) })),
      ...media.map((m) => ({ from: columnKey(m.src_device, m.src),
                             to: columnKey(m.dst_device, m.dst) })),
    ] as FlowItem[];
    return columnsFor(items, data?.device_order ?? []);
  }, [rows, media, data]);

  // Esc collapses everything, so "Expand all" on a big trace is always one key
  // away from being undone.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen((prev) => (prev.size ? new Set() : prev));
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  function toggle(frame: number) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (!next.delete(frame)) next.add(frame);
      return next;
    });
  }

  function toggleDevice(name: string) {
    setHiddenDevices((prev) => {
      const next = new Set(prev);
      if (!next.delete(name)) next.add(name);
      return next;
    });
  }

  if (error) return <div className="panel error">{error}</div>;
  if (!data) return <div className="panel spinner">Loading the message ladder…</div>;

  // Ordered by how much of the trace each method accounts for: on a trunk
  // capture that puts OPTIONS first, which is exactly what you want to switch off.
  const methodOptions = Object.entries(methodCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([m, n]) => ({ value: m, label: m, count: n }));

  // Switching a device off hides its column *and* every arrow touching it — a
  // half-drawn arrow to a column that is no longer there says nothing.
  function onVisibleDevices(from: string, to: string): boolean {
    return !hiddenDevices.has(from) && !hiddenDevices.has(to);
  }

  const shown = rows.filter((r) =>
    (!focusCallId || r.call_id === focusCallId) &&
    (methods.size === 0 || methods.has(r.method || "?")) &&
    (!hideDuplicates || !r.duplicate_of) &&
    (legs.size === 0 || (r.leg !== null && legs.has(String(r.leg)))) &&
    onVisibleDevices(columnKey(r.src_device, r.src), columnKey(r.dst_device, r.dst)) &&
    matches(query, r.summary, r.src, r.dst, r.call_id, r.frame, r.status,
            r.start_line, r.src_device, r.dst_device));

  // Media rows carry no Call-ID and no method, so the SIP filters cannot speak
  // for them: they answer to their own toggle, the device filter and the search.
  const shownMedia: MediaRow[] = showMedia
    ? media.filter((m) =>
        (legs.size === 0 || (m.leg !== null && legs.has(String(m.leg)))) &&
        onVisibleDevices(columnKey(m.src_device, m.src), columnKey(m.dst_device, m.dst)) &&
        matches(query, m.label, m.src, m.dst, m.reporter, m.frame,
                m.codecs.join(" "), m.src_device, m.dst_device))
    : [];

  const items: FlowItem[] = [
    ...shown.map((r) => ({
      frame: r.frame, at: r.at, kind: "sip" as const, row: r,
      from: columnKey(r.src_device, r.src), to: columnKey(r.dst_device, r.dst),
    })),
    ...shownMedia.map((m) => ({
      frame: m.frame, at: m.at, kind: "media" as const, media: m,
      from: columnKey(m.src_device, m.src), to: columnKey(m.dst_device, m.dst),
    })),
  ].sort((a, b) => a.at - b.at || a.frame - b.frame);

  // Only the columns something still runs between. Filtering to one leg of a
  // four-leg call leaves two devices in play, and a ladder padded out with six
  // empty columns is harder to read than the unfiltered one. The chips above are
  // built from every column the trace has, so nothing becomes unreachable.
  const drawnColumns = allColumns.filter(
    (c) => items.some((it) => it.from === c || it.to === c));

  const duplicates = shown.filter((r) => r.duplicate_of).length;
  const allOpen = shown.length > 0 && shown.every((r) => open.has(r.frame));
  const filtered = shown.length !== rows.length || shownMedia.length !== media.length;

  return (
    <div className="panel">
      <div className="toolbar" style={{ marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Message ladder</h2>
        <div className="segmented">
          <button className={view === "flow" ? "on" : ""} onClick={() => setView("flow")}
                  title="Devices as columns, messages as arrows">Flow</button>
          <button className={view === "rows" ? "on" : ""} onClick={() => setView("rows")}
                  title="One message per line">Rows</button>
        </div>
        {view === "flow" && (
          <div className="segmented">
            <button onClick={() => setZoom((z) => Math.max(0, z - 1))}
                    disabled={zoom === 0} title="Narrower columns">Zoom out −</button>
            <button onClick={() => setZoom((z) => Math.min(ZOOM_STEPS.length - 1, z + 1))}
                    disabled={zoom === ZOOM_STEPS.length - 1}
                    title="Wider columns">Zoom in +</button>
          </div>
        )}
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
        {media.length > 0 && (
          <Toggle
            on={showMedia}
            onChange={setShowMedia}
            label={`media ${media.length}`}
            title="Streams the source's probe measured, shown between the signalling"
          />
        )}
        <span className="grow" />
        <Search value={query} onChange={setQuery} placeholder="address, status, device…" />
      </FilterBar>

      {legOptions.length > 1 && (
        <FilterBar>
          <span className="dim" style={{ marginRight: 4 }}>Legs</span>
          <Chips
            options={legOptions}
            selected={legs}
            onChange={setLegs}
            allLabel={`all ${legOptions.length}`}
          />
          <span className="dim">
            one hop of a correlated call — how many a call has depends on the call
          </span>
        </FilterBar>
      )}

      {allColumns.length > 1 && (
        <FilterBar>
          <span className="dim" style={{ marginRight: 4 }}>Devices</span>
          <div className="chips">
            {allColumns.map((c) => (
              <button
                key={c}
                className={`chip ${hiddenDevices.has(c) ? "" : "on"}`}
                title={hiddenDevices.has(c) ? `Show ${c}` : `Hide ${c} and every message it sends or receives`}
                onClick={() => toggleDevice(c)}
              >
                {c}
              </button>
            ))}
          </div>
          {hiddenDevices.size > 0 && (
            <button className="linkish" onClick={() => setHiddenDevices(new Set())}>
              show all
            </button>
          )}
        </FilterBar>
      )}

      {focusCallId && (
        <p className="focus">
          One Call-ID only: <span className="mono">{focusCallId}</span>{" "}
          <button className="linkish" onClick={onClearFocus}>show the whole trace</button>
        </p>
      )}

      <p className="dim" style={{ marginTop: 0 }}>
        {shown.length} message{shown.length === 1 ? "" : "s"}
        {filtered && <> of {rows.length}</>}
        {shownMedia.length > 0 && <> · {shownMedia.length} media row(s)</>}
        {duplicates > 0 && (
          <> · <span className="dupflag">{duplicates} duplicated frame
            {duplicates === 1 ? "" : "s"}</span>, excluded from transaction analysis</>
        )}
        {" "}· click a message to expand its headers, × or Esc to collapse
        {filtered && <> · the exports above always carry the whole trace</>}
      </p>

      {view === "flow" ? (
        <Flow
          items={items}
          columns={drawnColumns}
          devices={data.devices}
          zoom={zoom}
          open={open}
          onToggle={toggle}
          renderExpansion={(row) => (
            <Expansion row={row} onCollapse={() => toggle(row.frame)} />
          )}
        />
      ) : (
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
      )}
      {items.length === 0 && <p className="dim">No message matches these filters.</p>}
    </div>
  );
}
