export type Severity = "critical" | "major" | "minor" | "info";

export interface TraceSummary {
  id: number;
  filename: string;
  uploaded_at: string;
  size_bytes: number;
  kind: "pcap" | "text";
  message_count: number;
  call_count: number;
  finding_count: number;
  worst_severity: Severity | null;
  archived_at: string | null;
  consultations?: number;
}

export interface Finding {
  check_id: string;
  severity: Severity;
  title: string | null;
  detail: string;
  call: string;
  call_id: string;
  at: number;
  at_relative: number;
  frames: number[];
  evidence: string[];
  rfc_refs: string[];
  remediation: string | null;
}

export interface Call {
  call_id: string;
  label: string;
  outcome: string;
  messages: number;
  dialogs: number;
  start: number;
  end: number;
}

export interface Stream {
  src: string;
  dst: string;
  ssrc: number;
  packets: number;
  duration: number;
  loss_ratio: number;
  jitter_ms: number;
}

export interface Report {
  source: string;
  calls: Call[];
  streams: Stream[];
  findings: Finding[];
  notes: string[];
}

export interface FactCandidate {
  id: number;
  topic: string;
  fact: string;
  rfc_refs: string[];
  unresolved_refs: string[];
  citations_ok: boolean;
  status: "pending" | "approved" | "rejected";
}

export interface Consultation {
  id: number;
  created_at: string;
  model: string;
  served_by: string | null;
  question: string | null;
  interpretation: string | null;
  stop_reason: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  cache_read_tokens: number | null;
  cache_creation_tokens: number | null;
  error: string | null;
  facts: FactCandidate[];
}

export interface TraceDetail {
  id: number;
  filename: string;
  uploaded_at: string;
  kind: string;
  report: Report;
  consultations: Consultation[];
}

export interface ConsultEstimate {
  model: string;
  effort: string;
  approx_input_tokens: number;
  cached_prefix_tokens: number;
  approx_output_tokens: number;
  estimated_usd_first_call: number;
  estimated_usd_cached: number;
  sends: string[];
  does_not_send: string[];
}

export interface LadderRow {
  frame: number;
  at: number;
  src: string;
  dst: string;
  request: boolean;
  summary: string;
  start_line: string;
  call_id: string;
  transport: string;
  ip_id: number | null;
  ttl: number | null;
  duplicate_of: number | null;
  headers: [string, string][];
  body: string;
  parse_errors: string[];
}

export interface Check {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  symptom: string;
  detection: string;
  root_causes: string[];
  remediation: string;
  rfc_refs: string[];
  confidence: string;
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) message = body.detail;
    } catch {
      /* the body was not JSON; the status line is all we have */
    }
    throw new Error(message);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ ok: boolean; checks: number; sections: number; traces: number;
    anthropic_key_present: boolean }>("/api/health"),

  listTraces: (archived = false) =>
    request<TraceSummary[]>(`/api/traces?archived=${archived}`),

  traceCounts: () => request<{ active: number; archived: number }>("/api/traces/counts"),

  archiveTrace: (id: number) =>
    request<{ archived: boolean }>(`/api/traces/${id}/archive`, { method: "POST" }),

  restoreTrace: (id: number) =>
    request<{ archived: boolean }>(`/api/traces/${id}/restore`, { method: "POST" }),

  getTrace: (id: number) => request<TraceDetail>(`/api/traces/${id}`),

  deleteTrace: (id: number) =>
    request<{ deleted: number }>(`/api/traces/${id}`, { method: "DELETE" }),

  upload: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<TraceSummary>("/api/traces", { method: "POST", body: form });
  },

  ladder: (id: number) => request<LadderRow[]>(`/api/traces/${id}/ladder`),

  consultPreview: (id: number, question: string) =>
    request<ConsultEstimate>(`/api/traces/${id}/consult/preview`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ question }),
    }),

  consult: (id: number, question: string) =>
    request<{ id: number; error: string | null; interpretation: string | null }>(
      `/api/traces/${id}/consult`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ question }),
      },
    ),

  approveFact: (id: number) =>
    request<{ status: string }>(`/api/facts/${id}/approve`, { method: "POST" }),

  rejectFact: (id: number) =>
    request<{ status: string }>(`/api/facts/${id}/reject`, { method: "POST" }),

  checks: () => request<Check[]>("/api/kb/checks"),

  exportUrl: (id: number, fmt: "json" | "markdown" | "csv") =>
    `/api/traces/${id}/export?fmt=${fmt}`,

  ladderExportUrl: (id: number, fmt: "text" | "markdown" | "csv" | "json") =>
    `/api/traces/${id}/ladder/export?fmt=${fmt}`,
};
