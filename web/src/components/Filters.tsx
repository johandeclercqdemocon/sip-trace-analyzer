/**
 * The filter controls shared by the report and the ladder.
 *
 * One convention throughout: an empty selection means "everything". That keeps
 * the default state honest — a freshly opened trace shows every row, and the
 * chips never have to be pre-checked to get there.
 */
import type { ReactNode } from "react";

export function FilterBar({ children }: { children: ReactNode }) {
  return <div className="filterbar">{children}</div>;
}

export function Search({ value, onChange, placeholder }: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
}) {
  return (
    <div className="searchbox">
      <input
        type="search"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
      {value && (
        <button className="clear" title="Clear the search" onClick={() => onChange("")}>
          ×
        </button>
      )}
    </div>
  );
}

export interface ChipSpec {
  value: string;
  label: string;
  count?: number;
  title?: string;
}

export function Chips({ options, selected, onChange, allLabel = "all" }: {
  options: ChipSpec[];
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  allLabel?: string;
}) {
  function toggle(v: string) {
    const next = new Set(selected);
    if (!next.delete(v)) next.add(v);
    onChange(next);
  }

  return (
    <div className="chips">
      <button
        className={`chip ${selected.size === 0 ? "on" : ""}`}
        onClick={() => onChange(new Set())}
      >
        {allLabel}
      </button>
      {options.map((o) => (
        <button
          key={o.value}
          title={o.title}
          disabled={o.count === 0}
          className={`chip ${selected.has(o.value) ? "on" : ""}`}
          onClick={() => toggle(o.value)}
        >
          {o.label}
          {o.count !== undefined && <span className="n">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Toggle({ on, onChange, label, title }: {
  on: boolean;
  onChange: (v: boolean) => void;
  label: string;
  title?: string;
}) {
  return (
    <button className={`chip ${on ? "on" : ""}`} title={title} onClick={() => onChange(!on)}>
      {label}
    </button>
  );
}

/** Case-insensitive substring match across a row's searchable fields. */
export function matches(needle: string, ...fields: (string | number | null | undefined)[]) {
  const q = needle.trim().toLowerCase();
  if (!q) return true;
  return fields.some((f) => f != null && String(f).toLowerCase().includes(q));
}

/** Counts per key, so a chip can show how many rows it would keep. */
export function tally<T>(rows: T[], key: (row: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of rows) {
    const k = key(r);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}
