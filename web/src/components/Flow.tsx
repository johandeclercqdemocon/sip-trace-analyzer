/**
 * The call flow drawn as a ladder: one column per device, one row per message.
 *
 * This is the view an OCOM export is a picture of, and the reason the reader
 * carries device names at all. A correlated trace is four hops of the same call,
 * and reading it as a flat list of addresses means holding the topology in your
 * head; drawn as columns, the hop where something changes is where the arrow
 * changes.
 *
 * Each device gets a dotted lifeline per interface rather than one down its
 * middle, and an arrow starts and stops at the interface that actually carried
 * it. On a B2BUA that is the whole point of the picture: the message arrives on
 * one address and leaves on another, and a single centre line hides exactly that.
 *
 * It is not limited to exports. When the source names no devices the columns fall
 * back to the addresses themselves, which is the same picture a capture supports.
 */
import { useMemo, useState } from "react";
import type { Device, LadderRow, MediaRow } from "../api";

/** Column pitch in px, widest first. Zoom moves between neighbouring steps. */
export const ZOOM_STEPS = [96, 132, 176, 230, 300, 380];
export const DEFAULT_ZOOM = 3;

/** Distance from the column edge to an edge lifeline — the entity box's margin,
 *  so the line drops from the border of the device it belongs to. */
const EDGE_INSET = 6;
/** Shaft length for a message that starts and ends on the same interface. */
const SELF_STUB = 28;
const GUTTER = 86;

export interface FlowItem {
  frame: number;
  at: number;
  from: string;                 // column key
  to: string;
  kind: "sip" | "media";
  row?: LadderRow;
  media?: MediaRow;
}

/** The column a message end belongs to: its device where known, else its address. */
export function columnKey(device: string, endpoint: string): string {
  return device || hostOf(endpoint);
}

export function hostOf(endpoint: string): string {
  if (!endpoint) return "";
  if (endpoint.startsWith("[")) {
    const close = endpoint.indexOf("]");
    return close === -1 ? endpoint : endpoint.slice(0, close + 1);
  }
  const cut = endpoint.lastIndexOf(":");
  return cut === -1 ? endpoint : endpoint.slice(0, cut);
}

/**
 * Column order.
 *
 * The source's own order wins where it has one — it is the order the operator
 * has already looked at. Otherwise it is order of first appearance, which puts
 * the caller on the left and follows the call outward, and is what makes the
 * arrows mostly point one way instead of criss-crossing.
 */
export function columnsFor(items: FlowItem[], deviceOrder: string[]): string[] {
  const seen: string[] = [];
  for (const it of items) {
    for (const key of [it.from, it.to]) {
      if (key && !seen.includes(key)) seen.push(key);
    }
  }
  const ordered = deviceOrder.filter((d) => seen.includes(d));
  return [...ordered, ...seen.filter((s) => !ordered.includes(s))];
}

/**
 * Move one column to where another sits.
 *
 * Neither the export's order nor first appearance is always the order the reader
 * wants: an export can name its devices in any order, and a trace that starts
 * mid-call can put the callee first, so the INVITE that opens the call arrives
 * pointing right to left. Reordering is the fix, and it is a view preference —
 * nothing about the trace changes, only which column each device is drawn in.
 *
 * Dragging right drops after the target and dragging left drops before it, which
 * is what makes a drag onto the neighbour read as a swap.
 */
export function moveColumn(order: string[], key: string, target: string): string[] {
  const from = order.indexOf(key);
  const to = order.indexOf(target);
  if (from === -1 || to === -1 || from === to) return order;
  const next = order.filter((c) => c !== key);
  next.splice(next.indexOf(target) + (from < to ? 1 : 0), 0, key);
  return next;
}

/**
 * The trace's own column list, re-sorted by whatever the reader dragged.
 *
 * The preference is kept as names rather than positions so it survives a filter:
 * hiding a device and showing it again puts it back where it was put, and a name
 * the trace no longer has is simply ignored.
 */
export function orderedBy(columns: string[], preference: string[] | null): string[] {
  if (!preference) return columns;
  const chosen = preference.filter((c) => columns.includes(c));
  return [...chosen, ...columns.filter((c) => !chosen.includes(c))];
}

export interface Interface {
  side: "left" | "mid" | "right";
  hosts: string[];
}

/** Where a device's interfaces sit, and which addresses each one carries. */
export type Interfaces = Map<string, Interface[]>;

/**
 * Split each device's addresses across its interfaces.
 *
 * One address is one interface, drawn down the middle. Two or more become a left
 * and a right lifeline, and which address belongs to which is decided by where it
 * talks: an address whose peers sit to the left of this column is the left-hand
 * interface. Sorting by that and splitting at the median means the edges are
 * assigned even when every peer happens to be on one side — a device at the end
 * of the chain still gets two lines, because it still has two interfaces.
 */
export function interfacesFor(items: FlowItem[], columns: string[]): Interfaces {
  const index = new Map(columns.map((c, i) => [c, i]));
  // column -> host -> peer column indices
  const peers = new Map<string, Map<string, number[]>>();

  function note(column: string, endpoint: string, peerColumn: string) {
    const i = index.get(column);
    const p = index.get(peerColumn);
    if (i === undefined) return;
    if (!peers.has(column)) peers.set(column, new Map());
    const hosts = peers.get(column)!;
    const host = hostOf(endpoint);
    if (!hosts.has(host)) hosts.set(host, []);
    if (p !== undefined) hosts.get(host)!.push(p);
  }

  for (const it of items) {
    const src = it.row ? it.row.src : it.media!.src;
    const dst = it.row ? it.row.dst : it.media!.dst;
    note(it.from, src, it.to);
    note(it.to, dst, it.from);
  }

  const out: Interfaces = new Map();
  for (const column of columns) {
    const hosts = peers.get(column) ?? new Map<string, number[]>();
    const self = index.get(column) ?? 0;
    const names = [...hosts.keys()];
    if (names.length <= 1) {
      out.set(column, [{ side: "mid", hosts: names }]);
      continue;
    }
    const mean = (h: string) => {
      const p = hosts.get(h)!;
      return p.length ? p.reduce((a, b) => a + b, 0) / p.length : self;
    };
    names.sort((a, b) => mean(a) - mean(b) || a.localeCompare(b));
    const cut = Math.max(1, Math.round(names.length / 2));
    out.set(column, [
      { side: "left", hosts: names.slice(0, cut) },
      { side: "right", hosts: names.slice(cut) },
    ]);
  }
  return out;
}

/** Offset of an interface within its column, in px. */
function offsetOf(side: Interface["side"], pitch: number): number {
  if (side === "left") return EDGE_INSET;
  if (side === "right") return pitch - EDGE_INSET;
  return pitch / 2;
}

/**
 * Which interface of `column` carried this endpoint.
 *
 * Falls back to the side facing the peer when the address is not one the column
 * is known to own — a source that named no devices, or a stray address.
 */
function interfaceOffset(
  interfaces: Interfaces, column: string, endpoint: string,
  towards: "left" | "right", pitch: number,
): number {
  const host = hostOf(endpoint);
  const own = interfaces.get(column) ?? [];
  const match = own.find((i) => i.hosts.includes(host));
  if (match) return offsetOf(match.side, pitch);
  if (own.length <= 1) return offsetOf("mid", pitch);
  return offsetOf(towards, pitch);
}

function mediaTitle(m: MediaRow): string {
  const lines = Object.entries(m.stats).map(([k, v]) => `${k}: ${v}`);
  return lines.length ? lines.join("\n") : `${m.label} ${m.src} -> ${m.dst}`;
}

/** A media row is only worth colouring when the probe found something wrong. */
function mediaSeverity(m: MediaRow): string {
  if (m.mos !== null && m.mos < 3.6) return "bad";
  if (m.loss_ratio !== null && m.loss_ratio > 0.005) return "bad";
  if (m.jitter_avg_ms !== null && m.jitter_avg_ms > 30) return "bad";
  return "ok";
}

function mediaSummary(m: MediaRow): string {
  const bits = [
    m.codecs.length ? m.codecs.join(", ") : "",
    m.packets !== null ? `${m.packets} pkts` : "",
    m.loss_ratio !== null ? `${(m.loss_ratio * 100).toFixed(2)}% loss` : "",
    m.jitter_avg_ms !== null ? `${m.jitter_avg_ms.toFixed(2)} ms jitter` : "",
    m.mos !== null ? `MOS ${m.mos.toFixed(1)}` : "",
  ].filter(Boolean);
  return bits.join(" · ");
}

function Arrow({ item, columns, interfaces, pitch, onToggle, open }: {
  item: FlowItem;
  columns: string[];
  interfaces: Interfaces;
  pitch: number;
  onToggle: () => void;
  open: boolean;
}) {
  const a = columns.indexOf(item.from);
  const b = columns.indexOf(item.to);
  // A row whose other end is filtered out has nothing to span, so it is dropped
  // by the caller; reaching here with -1 would silently draw the wrong arrow.
  if (a === -1 || b === -1) return null;

  const m = item.media;
  const srcEnd = m ? m.src : item.row!.src;
  const dstEnd = m ? m.dst : item.row!.dst;

  // The interface a message leaves by is the one facing where it is going, and
  // the one it arrives on is the one facing where it came from.
  const srcX = (a - Math.min(a, b)) * pitch
    + interfaceOffset(interfaces, item.from, srcEnd, b > a ? "right" : "left", pitch);
  const dstX = (b - Math.min(a, b)) * pitch
    + interfaceOffset(interfaces, item.to, dstEnd, b > a ? "left" : "right", pitch);

  const span = Math.abs(b - a) + 1;
  const width = span * pitch;
  const rightwards = dstX > srcX || (dstX === srcX && b >= a);
  let from = Math.min(srcX, dstX);
  let to = Math.max(srcX, dstX);
  if (to - from < SELF_STUB) {
    // Both ends on one interface: a device talking to itself, or the only end of
    // the path this trace saw. Drawn as a stub rather than a line of zero length.
    to = Math.min(from + SELF_STUB, width);
    from = to - SELF_STUB;
  }

  const classes = [
    "flowarrow",
    item.kind,
    m ? `media-${mediaSeverity(m)}` : item.row!.request ? "req" : "res",
    item.row?.duplicate_of ? "dup" : "",
    open ? "open" : "",
  ].filter(Boolean).join(" ");

  return (
    <div
      className={classes}
      title={m ? mediaTitle(m) : open ? "click to collapse" : "click to expand"}
      onClick={onToggle}
      style={{
        gridColumn: `${Math.min(a, b) + 2} / ${Math.max(a, b) + 3}`,
        paddingLeft: from,
        paddingRight: width - to,
      }}
    >
      <div className="flowlabel">
        <span className="n">[{item.frame}]</span>{" "}
        {m ? m.label.trim() : item.row!.summary}
        {item.row?.duplicate_of ? (
          <span className="dupflag"> ⧉ dup of {item.row.duplicate_of}</span>
        ) : null}
        {item.row ? <span className="caret">{open ? " ▾" : " ▸"}</span> : null}
      </div>
      <div className="flowline">
        {!rightwards && <span className="head left">◀</span>}
        <span className="shaft" />
        {rightwards && <span className="head right">▶</span>}
      </div>
      <div className="flowdetail">
        {m ? mediaSummary(m) : `${item.row!.src} → ${item.row!.dst}`}
      </div>
    </div>
  );
}

export function Flow({
  items, columns, devices, zoom, open, onToggle, onReorder, renderExpansion,
}: {
  items: FlowItem[];
  columns: string[];
  devices: Device[];
  zoom: number;
  open: Set<number>;
  onToggle: (frame: number) => void;
  /** Put `key`'s column where `target`'s is. Omit to pin the column order. */
  onReorder?: (key: string, target: string) => void;
  renderExpansion: (row: LadderRow) => React.ReactNode;
}) {
  const pitch = ZOOM_STEPS[Math.min(Math.max(zoom, 0), ZOOM_STEPS.length - 1)];
  const byName = useMemo(
    () => new Map(devices.map((d) => [d.name, d])), [devices]);
  const interfaces = useMemo(
    () => interfacesFor(items, columns), [items, columns]);

  // Which box is being dragged and which one the pointer is over, so the header
  // can show where the drop will land before the reader commits to it.
  const [dragging, setDragging] = useState<string | null>(null);
  const [over, setOver] = useState<string | null>(null);
  const movable = Boolean(onReorder) && columns.length > 1;

  function move(key: string, target: string) {
    if (key !== target) onReorder?.(key, target);
  }


  const style = {
    gridTemplateColumns: `${GUTTER}px repeat(${columns.length}, ${pitch}px)`,
  } as React.CSSProperties;

  return (
    <div className="flowscroll">
      <div className="flow" style={{ minWidth: GUTTER + columns.length * pitch }}>
        <div className="flowhead" style={style}>
          <div />
          {columns.map((c, i) => {
            const d = byName.get(c);
            const own = interfaces.get(c) ?? [];
            const dropping = movable && dragging !== null && over === c && dragging !== c;
            const classes = [
              "entity",
              movable ? "movable" : "",
              dragging === c ? "dragging" : "",
              // The edge the box would move towards, marked on that side.
              dropping ? (columns.indexOf(dragging!) < i ? "over-right" : "over-left") : "",
            ].filter(Boolean).join(" ");
            return (
              <div
                className={classes}
                key={c}
                title={[d?.description || c, movable ? "drag to reorder the columns" : ""]
                  .filter(Boolean).join(" — ")}
                draggable={movable}
                onDragStart={(e) => {
                  setDragging(c);
                  e.dataTransfer.effectAllowed = "move";
                  e.dataTransfer.setData("text/plain", c);
                }}
                onDragEnd={() => { setDragging(null); setOver(null); }}
                onDragOver={(e) => {
                  if (!dragging || dragging === c) return;
                  // Without this the drop is refused and the box springs back.
                  e.preventDefault();
                  e.dataTransfer.dropEffect = "move";
                  setOver(c);
                }}
                onDragLeave={() => setOver((prev) => (prev === c ? null : prev))}
                onDrop={(e) => {
                  e.preventDefault();
                  if (dragging) move(dragging, c);
                  setDragging(null);
                  setOver(null);
                }}
              >
                {movable && (
                  /* The same move one step at a time, for a trackpad that fights
                     a drag and for anyone working from the keyboard. */
                  <div className="emove">
                    <button
                      disabled={i === 0}
                      title={`Move ${c} one column left`}
                      aria-label={`Move ${c} one column left`}
                      onClick={() => move(c, columns[i - 1])}
                    >◀</button>
                    <button
                      disabled={i === columns.length - 1}
                      title={`Move ${c} one column right`}
                      aria-label={`Move ${c} one column right`}
                      onClick={() => move(c, columns[i + 1])}
                    >▶</button>
                  </div>
                )}
                <div className="ename">{c}</div>
                {d?.type && <div className="etype">{d.type}</div>}
                {/* Addresses sit over the lifeline that carries them, so the
                    column header reads as the device's interface list. */}
                <div className={`eaddr mono sides-${own.length}`}>
                  {own.map((i) => (
                    <span className={`iface ${i.side}`} key={i.side}>
                      {i.hosts.join("\n")}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        <div className="flowbody" style={style}>
          <div className="lifelines" aria-hidden="true">
            {columns.flatMap((c, i) =>
              (interfaces.get(c) ?? []).map((iface) => (
                <span
                  className={`lifeline ${iface.side}`}
                  key={`${c}-${iface.side}`}
                  title={iface.hosts.join(", ")}
                  style={{ left: GUTTER + i * pitch + offsetOf(iface.side, pitch) }}
                />
              )))}
          </div>
          {items.map((it) => (
            <div className="flowrow" key={`${it.kind}-${it.frame}`}
                 style={{ ...style, gridColumn: `1 / -1` }}>
              <div className="flowtime mono">{it.at.toFixed(6)}</div>
              <Arrow item={it} columns={columns} interfaces={interfaces} pitch={pitch}
                     open={open.has(it.frame)}
                     onToggle={() => it.row && onToggle(it.frame)} />
              {it.row && open.has(it.frame) && (
                <div className="flowexpansion" style={{ gridColumn: "1 / -1" }}>
                  {renderExpansion(it.row)}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
