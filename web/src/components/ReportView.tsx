import { useMemo, useState } from "react";
import type { Call, CallKind, Census, Finding, Report, Severity, TraceDetail } from "../api";
import { Chips, FilterBar, matches, Search, Toggle, tally } from "./Filters";

/** Reported in this order: what a VoIP analyser counts first. */
const KIND_ORDER: CallKind[] = [
  "call", "orphan", "registration", "subscription", "keepalive", "other",
];
const SEVERITIES: Severity[] = ["critical", "major", "minor", "info"];

/**
 * Reports stored before the census landed carry neither counts nor per-call
 * kinds, but 'no INVITE' as an outcome is the same test, so an old report still
 * lands on the number a re-analysis would give.
 */
function kindOf(c: Call): CallKind {
  return c.kind ?? (c.outcome === "no INVITE" ? "other" : "call");
}

function censusOf(report: Report): Census {
  if (report.counts) return report.counts;
  const by_kind: Partial<Record<CallKind, number>> = {};
  for (const c of report.calls) {
    const k = kindOf(c);
    by_kind[k] = (by_kind[k] ?? 0) + 1;
  }
  return {
    call_ids: report.calls.length,
    calls: by_kind.call ?? 0,
    by_kind,
    kind_help: {},
  };
}

/**
 * The count reconciliation.
 *
 * A Call-ID group is not a call: OPTIONS keepalives and REGISTERs get their own
 * Call-ID, so grouping by Call-ID always yields a bigger number than Wireshark's
 * VoIP Calls window. Showing only the big number reads as a bug, which is why
 * this sits at the top of the report whenever the two disagree.
 */
function CallCensus({ census }: { census: Census }) {
  const others = KIND_ORDER.filter((k) => k !== "call" && census.by_kind[k]);
  if (census.call_ids === census.calls) return null;

  return (
    <div className="panel flag">
      <h2>
        <span className="flagmark">⚑</span> {census.calls} call
        {census.calls === 1 ? "" : "s"} in {census.call_ids} Call-IDs
      </h2>
      <p>
        A VoIP analyser — Wireshark's <strong>Telephony ▸ VoIP Calls</strong> window —
        counts only the dialogs started by an INVITE, which is{" "}
        <strong>{census.calls}</strong> here. This analyser groups every SIP
        transaction by Call-ID, so it also lists the {census.call_ids - census.calls}{" "}
        Call-IDs that carry no call:
      </p>
      <ul className="kinds">
        {others.map((k) => (
          <li key={k}>
            <span className={`badge kind-${k}`}>{census.by_kind[k]} {k}</span>
            {census.kind_help[k] ? <span className="dim"> — {census.kind_help[k]}</span> : null}
          </li>
        ))}
      </ul>
      {census.by_kind.orphan ? (
        <p className="dim">
          Orphans are worth a look: an in-dialog request with no INVITE in the
          capture means the call was already up when the capture started, so its
          setup cannot be checked.
        </p>
      ) : null}
    </div>
  );
}

function FindingCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(f.severity === "critical");
  return (
    <div className={`finding ${f.severity}`}>
      <header onClick={() => setOpen(!open)}>
        <span className={`badge ${f.severity}`}>{f.severity}</span>
        <h4>{f.title ?? f.check_id}</h4>
        <span className="mono" style={{ color: "var(--dim)" }}>{f.check_id}</span>
        <span style={{ color: "var(--dim)" }}>{open ? "−" : "+"}</span>
      </header>

      <p className="where">
        {f.call ? <>call <strong>{f.call}</strong></> : "no call"}
        {f.at_relative ? ` · at +${f.at_relative.toFixed(3)}s` : ""}
        {f.frames.length ? ` · frames ${f.frames.slice(0, 8).join(", ")}` : ""}
      </p>

      <p>{f.detail}</p>

      {f.response_meaning && (
        <p className="dim">{f.response_meaning}</p>
      )}

      {open && (
        <>
          {f.evidence.length > 0 && (
            <pre className="evidence mono">{f.evidence.join("\n")}</pre>
          )}
          {f.remediation && (
            <p><strong>Fix.</strong> {f.remediation}</p>
          )}
          {f.rfc_refs.length > 0 && (
            <p className="refs mono">{f.rfc_refs.join("  ·  ")}</p>
          )}
        </>
      )}
    </div>
  );
}

export function ReportView({ trace, onOpenLadder }: {
  trace: TraceDetail;
  onOpenLadder?: (callId: string) => void;
}) {
  const report: Report = trace.report;
  const { calls, streams, findings, notes } = report;
  // Sources that summarise media instead of capturing it fill this instead
  // of `streams`; a pcap fills `streams` and leaves this empty.
  const mediaReports = report.media_reports ?? [];
  const devices = report.devices ?? [];
  // How many hops a call crossed is a fact about that call: two calls in one
  // trace routinely differ, so the column only appears when something says so.
  const anyLegs = calls.some((c) => (c.legs ?? []).length > 0);
  const census = useMemo(() => censusOf(report), [report]);

  const [callQuery, setCallQuery] = useState("");
  const [kinds, setKinds] = useState<Set<string>>(new Set());
  const [onlyFlagged, setOnlyFlagged] = useState(false);
  const [picked, setPicked] = useState<string | null>(null);   // a Call-ID
  const [findingQuery, setFindingQuery] = useState("");
  const [severities, setSeverities] = useState<Set<string>>(new Set());

  const perCall = useMemo(() => tally(findings, (f) => f.call_id), [findings]);
  const kindCounts = useMemo(() => tally(calls, kindOf), [calls]);
  const sevCounts = useMemo(() => tally(findings, (f) => f.severity), [findings]);

  const shownCalls = calls.filter((c) =>
    (kinds.size === 0 || kinds.has(kindOf(c))) &&
    (!onlyFlagged || (perCall[c.call_id] ?? 0) > 0) &&
    matches(callQuery, c.label, c.call_id, c.outcome, (c.methods ?? []).join(" ")));

  const shownFindings = findings.filter((f) =>
    (severities.size === 0 || severities.has(f.severity)) &&
    (picked === null || f.call_id === picked) &&
    matches(findingQuery, f.check_id, f.title, f.detail, f.call,
            (f.rfc_refs ?? []).join(" ")));

  const pickedCall = picked ? calls.find((c) => c.call_id === picked) : null;

  return (
    <>
      <div className="panel">
        <h2>Summary</h2>
        <p>
          {census.calls} call{census.calls === 1 ? "" : "s"}{" "}
          <span className="dim">
            ({census.call_ids} Call-ID{census.call_ids === 1 ? "" : "s"})
          </span>{" "}
          · {streams.length > 0 || mediaReports.length === 0
              ? `${streams.length} RTP stream${streams.length === 1 ? "" : "s"}`
              : `${mediaReports.length} media report${mediaReports.length === 1 ? "" : "s"}`} ·{" "}
          {findings.length} finding{findings.length === 1 ? "" : "s"}
          {" "}
          {SEVERITIES
            .filter((s) => sevCounts[s])
            .map((s) => (
              <span key={s} className={`badge ${s}`} style={{ marginLeft: 6 }}>
                {sevCounts[s]} {s}
              </span>
            ))}
          {findings.length === 0 && <span className="badge clean" style={{ marginLeft: 6 }}>clean</span>}
        </p>
        {notes.map((n) => (
          <p key={n} style={{ color: "var(--dim)" }}>note: {n}</p>
        ))}
      </div>

      <CallCensus census={census} />

      {calls.length > 0 && (
        <div className="panel">
          <h2>Call-IDs</h2>
          <FilterBar>
            <Chips
              options={KIND_ORDER.filter((k) => kindCounts[k]).map((k) => ({
                value: k,
                label: k,
                count: kindCounts[k],
                title: census.kind_help[k],
              }))}
              selected={kinds}
              onChange={setKinds}
              allLabel={`all ${calls.length}`}
            />
            <Toggle
              on={onlyFlagged}
              onChange={setOnlyFlagged}
              label="with findings"
              title="Only the Call-IDs a check fired on"
            />
            <span className="grow" />
            <Search
              value={callQuery}
              onChange={setCallQuery}
              placeholder="number, Call-ID, method…"
            />
          </FilterBar>

          <div className="scroll-x"><table>
            <thead>
              <tr>
                <th>Kind</th><th>Call</th><th>Outcome</th>
                <th className="num">Messages</th><th className="num">Dialogs</th>
                {anyLegs && <th>Path</th>}
                <th className="num">Findings</th>
                <th>Call-ID</th><th></th>
              </tr>
            </thead>
            <tbody>
              {shownCalls.map((c) => (
                <tr
                  key={c.call_id}
                  className={`pick ${picked === c.call_id ? "sel" : ""}`}
                  title="Click to filter the findings below to this Call-ID"
                  onClick={() => setPicked(picked === c.call_id ? null : c.call_id)}
                >
                  <td><span className={`badge kind-${kindOf(c)}`}>{kindOf(c)}</span></td>
                  <td>{c.label}</td>
                  <td>{c.outcome}</td>
                  <td className="num">{c.messages}</td>
                  <td className="num">{c.dialogs}</td>
                  {anyLegs && (
                    <td className="dim" title={(c.devices ?? []).join(" → ")}>
                      {(c.legs ?? []).length} leg{(c.legs ?? []).length === 1 ? "" : "s"}
                      {" · "}
                      {(c.devices ?? []).length} device
                      {(c.devices ?? []).length === 1 ? "" : "s"}
                    </td>
                  )}
                  <td className="num">{perCall[c.call_id] ?? 0}</td>
                  <td className="mono" style={{ color: "var(--dim)" }}>{c.call_id}</td>
                  <td>
                    {onOpenLadder && (
                      <button
                        className="linkish"
                        title="Show only this Call-ID in the ladder"
                        onClick={(e) => { e.stopPropagation(); onOpenLadder(c.call_id); }}
                      >
                        ladder
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
          {shownCalls.length === 0 && (
            <p className="dim">No Call-ID matches these filters.</p>
          )}
        </div>
      )}

      {devices.length > 0 && (
        <div className="panel">
          <h2>Devices</h2>
          <p className="dim" style={{ marginTop: 0 }}>
            Named by the trace source, in call-flow order. Grouping addresses by
            device is what stops two legs of one SBC reading as two hosts.
          </p>
          <div className="scroll-x"><table>
            <thead>
              <tr><th></th><th>Device</th><th>Type</th><th>Addresses seen</th></tr>
            </thead>
            <tbody>
              {(report.device_order ?? devices.map((d) => d.name)).map((name, i) => {
                const d = devices.find((x) => x.name === name);
                const seen = new Set<string>();
                for (const m of mediaReports) {
                  if (m.src_device === name) seen.add(m.src.replace(/:[0-9]+$/, ""));
                }
                return (
                  <tr key={name}>
                    <td className="num dim">{i + 1}</td>
                    <td>{name}</td>
                    <td className="dim">{d?.type ?? ""}</td>
                    <td className="mono dim">{[...seen].sort().join(", ")}</td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        </div>
      )}

      {mediaReports.length > 0 && (
        <div className="panel">
          <h2>Media reported by probe</h2>
          <p className="dim" style={{ marginTop: 0 }}>
            Stream summaries, not packets: loss, jitter and MOS are the probe's own
            measurements, and the per-packet RTP checks cannot run on them.
          </p>
          <div className="scroll-x"><table>
            <thead>
              <tr>
                <th>From</th><th>To</th><th>Reporter</th><th>Codecs</th>
                <th className="num">Packets</th><th className="num">Loss</th>
                <th className="num">Jitter</th><th className="num">MOS</th>
              </tr>
            </thead>
            <tbody>
              {mediaReports.filter((m) => m.ends || mediaReports.every((o) => !o.ends))
                .map((m, i) => (
                <tr key={i}>
                  <td className="mono">{m.src}</td>
                  <td className="mono">{m.dst}</td>
                  <td className="dim">{m.reporter}</td>
                  <td className="dim">{m.codecs.join(", ")}</td>
                  <td className="num">{m.packets ?? ""}</td>
                  <td className="num" style={{ color: (m.loss_ratio ?? 0) > 0.005 ? "var(--major)" : undefined }}>
                    {m.loss_ratio === null ? "" : `${(m.loss_ratio * 100).toFixed(2)}%`}
                  </td>
                  <td className="num" style={{ color: (m.jitter_avg_ms ?? 0) > 30 ? "var(--major)" : undefined }}>
                    {m.jitter_avg_ms === null ? "" : `${m.jitter_avg_ms.toFixed(2)} ms`}
                  </td>
                  <td className="num" style={{ color: (m.mos ?? 5) < 3.6 ? "var(--major)" : undefined }}>
                    {m.mos === null ? "" : m.mos.toFixed(1)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </div>
      )}

      {streams.length > 0 && (
        <div className="panel">
          <h2>RTP streams</h2>
          <div className="scroll-x"><table>
            <thead>
              <tr>
                <th>From</th><th>To</th><th>SSRC</th>
                <th className="num">Packets</th><th className="num">Duration</th>
                <th className="num">Loss</th><th className="num">Jitter</th>
              </tr>
            </thead>
            <tbody>
              {streams.map((s, i) => (
                <tr key={i}>
                  <td className="mono">{s.src}</td>
                  <td className="mono">{s.dst}</td>
                  <td className="mono">0x{s.ssrc.toString(16).padStart(8, "0")}</td>
                  <td className="num">{s.packets}</td>
                  <td className="num">{s.duration.toFixed(1)}s</td>
                  <td className="num" style={{ color: s.loss_ratio > 0.005 ? "var(--major)" : undefined }}>
                    {(s.loss_ratio * 100).toFixed(2)}%
                  </td>
                  <td className="num">{s.jitter_ms.toFixed(1)} ms</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </div>
      )}

      <div className="toolbar" style={{ marginBottom: 12 }}>
        <h2 style={{ fontSize: 15, letterSpacing: "0.02em", margin: 0 }}>Findings</h2>
        <span className="grow" />
        <FilterBar>
          <Chips
            options={SEVERITIES.filter((s) => sevCounts[s]).map((s) => ({
              value: s, label: s, count: sevCounts[s],
            }))}
            selected={severities}
            onChange={setSeverities}
            allLabel={`all ${findings.length}`}
          />
          <Search
            value={findingQuery}
            onChange={setFindingQuery}
            placeholder="check, text, RFC…"
          />
        </FilterBar>
      </div>

      {picked && (
        <p className="dim" style={{ marginTop: 0 }}>
          Showing findings for <strong>{pickedCall?.label ?? picked}</strong>{" "}
          <button className="linkish" onClick={() => setPicked(null)}>show all</button>
        </p>
      )}

      {findings.length === 0 ? (
        <div className="panel"><p style={{ margin: 0, color: "var(--ok)" }}>
          No problems found. Every check passed against this trace.
        </p></div>
      ) : shownFindings.length === 0 ? (
        <div className="panel"><p className="dim" style={{ margin: 0 }}>
          No finding matches these filters.
        </p></div>
      ) : (
        shownFindings.map((f, i) => <FindingCard key={`${f.check_id}-${i}`} f={f} />)
      )}
    </>
  );
}
