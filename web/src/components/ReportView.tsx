import { useState } from "react";
import type { Finding, Report, TraceDetail } from "../api";

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

export function ReportView({ trace }: { trace: TraceDetail }) {
  const report: Report = trace.report;
  const { calls, streams, findings, notes } = report;

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <>
      <div className="panel">
        <h2>Summary</h2>
        <p>
          {calls.length} call{calls.length === 1 ? "" : "s"} ·{" "}
          {streams.length} RTP stream{streams.length === 1 ? "" : "s"} ·{" "}
          {findings.length} finding{findings.length === 1 ? "" : "s"}
          {" "}
          {(["critical", "major", "minor", "info"] as const)
            .filter((s) => counts[s])
            .map((s) => (
              <span key={s} className={`badge ${s}`} style={{ marginLeft: 6 }}>
                {counts[s]} {s}
              </span>
            ))}
          {findings.length === 0 && <span className="badge clean" style={{ marginLeft: 6 }}>clean</span>}
        </p>
        {notes.map((n) => (
          <p key={n} style={{ color: "var(--dim)" }}>note: {n}</p>
        ))}
      </div>

      {calls.length > 0 && (
        <div className="panel">
          <h2>Calls</h2>
          <div className="scroll-x"><table>
            <thead>
              <tr>
                <th>Call</th><th>Outcome</th>
                <th className="num">Messages</th><th className="num">Dialogs</th>
                <th>Call-ID</th>
              </tr>
            </thead>
            <tbody>
              {calls.map((c) => (
                <tr key={c.call_id}>
                  <td>{c.label}</td>
                  <td>{c.outcome}</td>
                  <td className="num">{c.messages}</td>
                  <td className="num">{c.dialogs}</td>
                  <td className="mono" style={{ color: "var(--dim)" }}>{c.call_id}</td>
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

      <h2 style={{ fontSize: 15, letterSpacing: "0.02em", margin: "0 0 12px" }}>Findings</h2>
      {findings.length === 0 ? (
        <div className="panel"><p style={{ margin: 0, color: "var(--ok)" }}>
          No problems found. Every check passed against this trace.
        </p></div>
      ) : (
        findings.map((f, i) => <FindingCard key={`${f.check_id}-${i}`} f={f} />)
      )}
    </>
  );
}
