import type {
  BlastResult,
  EntitySummary,
  EventRow,
  FileSummary,
  GraphData,
  Incident,
  IncidentListItem,
  PathResult,
  Settings,
  Summary,
  Backend,
  ContainmentPlan,
  WhatIfResult,
  Deviation,
} from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init);
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") msg = body.detail;
      else if (Array.isArray(body.detail)) msg = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, msg);
  }
  return (await res.json()) as T;
}

const enc = encodeURIComponent;
const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  health: () => call<{ status: string; version: string; events: number; entities: number; backend: Backend }>("/api/health"),
  summary: () => call<Summary>("/api/summary"),
  rules: () => call<Record<string, { kind: string; title: string; description: string }>>("/api/rules"),
  sources: () => call<{ name: string; label: string; required_fields: string[]; context: boolean }[]>("/api/sources"),
  datasets: () => call<{ files: FileSummary[]; cross_file: Record<string, number> }>("/api/datasets"),
  loadSample: () => call<{ files: FileSummary[] }>("/api/datasets/sample", { method: "POST" }),
  clear: () => call<{ status: string }>("/api/datasets/clear", { method: "POST" }),
  upload: (files: File[], sourceType: string, mode: "append" | "replace") => {
    const fd = new FormData();
    files.forEach((f) => fd.append("files", f));
    fd.append("source_type", sourceType);
    fd.append("mode", mode);
    return call<{ files: FileSummary[] }>("/api/datasets/upload", { method: "POST", body: fd });
  },
  entities: (type?: string, q?: string) => {
    const p = new URLSearchParams();
    if (type) p.set("type", type);
    if (q) p.set("q", q);
    return call<EntitySummary[]>(`/api/entities?${p}`);
  },
  entity: (id: string) => call<any>(`/api/entities/${enc(id)}`),
  setStatus: (id: string, status: string | null) => call<unknown>(`/api/entities/${enc(id)}/status`, json("POST", { status })),
  relationship: (id: string) => call<any>(`/api/relationships/${enc(id)}`),
  event: (uid: string) => call<any>(`/api/events/${enc(uid)}`),
  events: (params: Record<string, string | number | undefined>) => {
    const p = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== "" && p.set(k, String(v)));
    return call<{ total: number; offset: number; limit: number; events: EventRow[] }>(`/api/events?${p}`);
  },
  graph: (params: Record<string, string | number | boolean | undefined>) => {
    const p = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== "" && p.set(k, String(v)));
    return call<GraphData>(`/api/graph?${p}`);
  },
  paths: (body: { source: string; targets?: string[] | null; max_hops: number; max_paths?: number; rel_types?: string[] | null; since?: string | null }) =>
    call<PathResult>("/api/paths", json("POST", body)),
  blast: (id: string, hops: number, temporal: boolean, includeProcesses: boolean, since?: string) => {
    const p = new URLSearchParams({ hops: String(hops), temporal: String(temporal), include_processes: String(includeProcesses) });
    if (since) p.set("since", since);
    return call<BlastResult>(`/api/blast-radius/${enc(id)}?${p}`);
  },
  incidents: () => call<IncidentListItem[]>("/api/incidents"),
  incident: (id: string) => call<Incident>(`/api/incidents/${enc(id)}`),
  reportUrl: (id: string, format: "html" | "md" | "json") => `/api/incidents/${enc(id)}/report?format=${format}`,
  containment: (id: string, at?: string) =>
    call<ContainmentPlan>(`/api/incidents/${enc(id)}/containment${at ? `?at=${enc(at)}` : ""}`),
  whatIf: (source: string, actions: string[], at?: string | null) =>
    call<WhatIfResult>("/api/whatif", json("POST", { source, actions, at: at || null })),
  deviations: (limit = 20) =>
    call<{ reference_d2: number; suspicion_cap: number; models: Record<string, any>; deviations: Deviation[] }>(`/api/deviations?limit=${limit}`),
  manifest: () => call<any>("/api/evidence/manifest"),
  settings: () => call<Settings>("/api/settings"),
  saveSettings: (s: Settings) => call<Settings>("/api/settings", json("PUT", s)),
  resetSettings: () => call<Settings>("/api/settings/reset", { method: "POST" }),
  backend: () => call<Backend>("/api/backend"),
  neo4jSync: () => call<Backend>("/api/backend/neo4j/sync", { method: "POST" }),
};
