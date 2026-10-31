import { useEffect, useRef, useState } from "react";
import { Activity, Database, RefreshCcw, Save, Trash2, Upload } from "lucide-react";
import { Button, ErrorBox, Field, Loading, Panel, inputCls } from "../components/ui";
import { api } from "../lib/api";
import { fmtBytes, fmtTime, useAsync, useDataVersion } from "../lib/hooks";
import type { FileSummary, Settings } from "../lib/types";

const WEIGHT_LABELS: Record<string, string> = {
  criticality: "Asset criticality", suspicion: "Event suspicion", corroboration: "Independent corroboration",
  evidence_quality: "Evidence quality", path_length: "Path compactness", recency: "Recency",
};

export function SettingsPage() {
  const { bump } = useDataVersion();
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const flash = (ok: boolean, text: string) => { setMsg({ ok, text }); setTimeout(() => setMsg(null), 6000); };
  return (
    <div className="space-y-4">
      {msg && <div role="status" className={`rounded-md border px-3 py-2 text-sm ${msg.ok ? "border-ok/40 bg-ok/10 text-ok" : "border-crit/40 bg-crit/10 text-crit"}`}>{msg.text}</div>}
      <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        <DataPanel onDone={(ok, t) => { flash(ok, t); bump(); }} />
        <div className="space-y-4">
          <BackendPanel onDone={flash} />
          <HealthPanel />
        </div>
      </div>
      <SettingsForm onDone={(ok, t) => { flash(ok, t); if (ok) bump(); }} />
      <FilesPanel />
      <RulesPanel />
    </div>
  );
}

function DataPanel({ onDone }: { onDone: (ok: boolean, text: string) => void }) {
  const { data: sources } = useAsync(() => api.sources(), []);
  const [files, setFiles] = useState<File[]>([]);
  const [sourceType, setSourceType] = useState("");
  const [mode, setMode] = useState<"append" | "replace">("append");
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<FileSummary[] | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    try { await fn(); onDone(true, ok); } catch (e) { onDone(false, (e as Error).message); } finally { setBusy(false); }
  };
  return (
    <Panel title={<span className="flex items-center gap-2"><Database size={14} /> Data management</span>}>
      <div className="mb-4 flex flex-wrap gap-2">
        <Button disabled={busy} onClick={() => act(async () => setResults((await api.loadSample()).files), "Synthetic sample dataset reloaded.")}><RefreshCcw size={14} /> Reset to sample dataset</Button>
        <Button variant="danger" disabled={busy} onClick={() => confirm("Remove all loaded data from this session?") && act(() => api.clear(), "All data cleared.")}><Trash2 size={14} /> Clear all data</Button>
      </div>
      <div className="rounded-md border border-dashed border-ink-600 p-3">
        <div className="mb-2 text-[13px] font-medium">Import dataset</div>
        <div className="grid gap-3 md:grid-cols-[1.3fr_1fr_1fr]">
          <Field label="Files (.csv, .json, .jsonl · max 20 MB each)">
            <input ref={input} aria-label="Dataset files" type="file" multiple accept=".csv,.json,.jsonl,.ndjson" onChange={(e) => setFiles([...(e.target.files || [])])}
              className="block w-full text-xs text-ink-300 file:mr-2 file:rounded file:border-0 file:bg-ink-700 file:px-2 file:py-1 file:text-ink-100" />
          </Field>
          <Field label="Source type">
            <select className={inputCls} value={sourceType} onChange={(e) => setSourceType(e.target.value)}>
              <option value="">Auto-detect from fields</option>
              {sources?.map((s) => <option key={s.name} value={s.name}>{s.label}</option>)}
            </select>
          </Field>
          <Field label="Mode">
            <select className={inputCls} value={mode} onChange={(e) => setMode(e.target.value as "append")}>
              <option value="append">Append to loaded data</option>
              <option value="replace">Replace loaded data</option>
            </select>
          </Field>
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Button variant="primary" disabled={busy || files.length === 0} onClick={() => act(async () => {
            const r = await api.upload(files, sourceType, mode);
            setResults(r.files);
            if (input.current) input.current.value = "";
            setFiles([]);
            const failed = r.files.filter((f) => f.error);
            if (failed.length) throw new Error(failed.map((f) => `${f.file_name}: ${f.error}`).join("; "));
          }, "Upload processed.")}><Upload size={14} /> Upload &amp; rebuild graph</Button>
          <span className="text-[11px] text-ink-400">Files are parsed as data only and never executed. Field schemas per source type are listed below.</span>
        </div>
        {sources && (
          <details className="mt-3 text-[11px] text-ink-400">
            <summary className="cursor-pointer text-ink-300">Supported source schemas</summary>
            <ul className="mt-1 space-y-0.5">{sources.map((s) => <li key={s.name}><span className="mono text-ink-200">{s.name}</span>: {s.label}: requires <span className="mono">{s.required_fields.join(", ")}</span></li>)}</ul>
          </details>
        )}
      </div>
      {results && (
        <div className="mt-3 space-y-1 text-xs">
          {results.map((r) => (
            <div key={r.file_name} className={r.error ? "text-crit" : "text-ink-300"}>
              <span className="mono">{r.file_name}</span>: {r.error ? r.error : `${r.source_system} · ${r.accepted} accepted, ${r.rejected} rejected, ${r.duplicates} duplicate, ${r.conflicts} conflict`}
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function BackendPanel({ onDone }: { onDone: (ok: boolean, text: string) => void }) {
  const { data: b, reload } = useAsync(() => api.backend(), []);
  const [busy, setBusy] = useState(false);
  if (!b) return <Loading />;
  return (
    <Panel title="Graph backend">
      <dl className="grid grid-cols-[140px_1fr] gap-y-1 text-[13px]">
        <dt className="text-ink-400">Active mode</dt><dd className="mono">{b.mode}</dd>
        <dt className="text-ink-400">Local engine</dt><dd>{b.local_engine}</dd>
        <dt className="text-ink-400">Neo4j</dt><dd>{b.neo4j.configured ? `${b.neo4j.uri_host} / ${b.neo4j.database}` : "not configured"}</dd>
        <dt className="text-ink-400">Neo4j status</dt><dd className={b.neo4j.synced ? "text-ok" : "text-ink-300"}>{b.neo4j.message}</dd>
      </dl>
      <div className="mt-3 flex items-center gap-2">
        <Button disabled={!b.neo4j.configured || busy} onClick={async () => {
          setBusy(true);
          try { const r = await api.neo4jSync(); onDone(r.neo4j.synced, r.neo4j.message); reload(); } catch (e) { onDone(false, (e as Error).message); } finally { setBusy(false); }
        }}>Connect &amp; sync to Neo4j</Button>
      </div>
      <p className="mt-2 text-[11px] leading-snug text-ink-400">
        Neo4j is optional. To enable it, set <span className="mono">NEO4J_URI</span>, <span className="mono">NEO4J_USERNAME</span>, <span className="mono">NEO4J_PASSWORD</span> and
        <span className="mono"> AGL_GRAPH_BACKEND=neo4j</span> in <span className="mono">.env</span> and restart. Credentials are read from the environment only and are never shown here.
      </p>
    </Panel>
  );
}

function HealthPanel() {
  const { data, error, reload, loading } = useAsync(() => api.health(), []);
  return (
    <Panel title={<span className="flex items-center gap-2"><Activity size={14} /> Application health</span>} actions={<Button variant="ghost" onClick={reload} disabled={loading}>Check</Button>}>
      {error ? <ErrorBox msg={error} /> : !data ? <Loading /> : (
        <dl className="grid grid-cols-[140px_1fr] gap-y-1 text-[13px]">
          <dt className="text-ink-400">API</dt><dd className="text-ok">{data.status}</dd>
          <dt className="text-ink-400">Version</dt><dd className="mono">{data.version}</dd>
          <dt className="text-ink-400">Events in graph</dt><dd className="tabular">{data.events.toLocaleString()}</dd>
          <dt className="text-ink-400">Entities</dt><dd className="tabular">{data.entities.toLocaleString()}</dd>
        </dl>
      )}
    </Panel>
  );
}

function SettingsForm({ onDone }: { onDone: (ok: boolean, text: string) => void }) {
  const { data } = useAsync(() => api.settings(), []);
  const [s, setS] = useState<Settings | null>(null);
  useEffect(() => { if (data) setS(data); }, [data]);
  if (!s) return <Loading />;
  const num = (k: keyof Settings, label: string, hint: string, step = 1) => (
    <Field label={label} hint={hint}>
      <input type="number" step={step} className={inputCls} value={s[k] as number} onChange={(e) => setS({ ...s, [k]: Number(e.target.value) })} />
    </Field>
  );
  const total = Object.values(s.weights).reduce((a, b) => a + b, 0) || 1;
  return (
    <Panel title="Analysis &amp; risk-ranking configuration" actions={
      <>
        <Button variant="ghost" onClick={async () => { try { setS(await api.resetSettings()); onDone(true, "Defaults restored."); } catch (e) { onDone(false, (e as Error).message); } }}>Restore defaults</Button>
        <Button variant="primary" onClick={async () => { try { setS(await api.saveSettings(s)); onDone(true, "Settings saved; analysis recomputed."); } catch (e) { onDone(false, (e as Error).message); } }}><Save size={14} /> Save &amp; recompute</Button>
      </>
    }>
      <div className="grid gap-4 md:grid-cols-4">
        {num("correlation_window_minutes", "Correlation window (min)", "Max gap between linked signals")}
        {num("max_hop_gap_hours", "Max gap between path steps (h)", "0 = unlimited", 0.5)}
        {num("clock_skew_seconds", "Clock-skew tolerance (s)", "Between source systems")}
        {num("suspicion_threshold", "Suspicion threshold", "0 to 1; seeds & 'suspected' tier", 0.05)}
        {num("default_max_hops", "Default max hops", "Incident hypotheses (1 to 8)")}
        {num("max_paths", "Paths returned", "Per search (1 to 100)")}
        {num("search_budget", "Search budget", "Edge expansions per search", 1000)}
        {num("recency_half_life_hours", "Recency half-life (h)", "Relative to newest event", 1)}
      </div>
      <div className="mt-5">
        <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-ink-400">Ranking weights: score = 100 × Σ wₖ·cₖ (weights are normalised to sum to 1)</div>
        <div className="grid gap-3 md:grid-cols-6">
          {Object.keys(WEIGHT_LABELS).map((k) => (
            <Field key={k} label={WEIGHT_LABELS[k]} hint={`effective ${((100 * (s.weights[k] ?? 0)) / total).toFixed(0)}%`}>
              <input type="number" step={0.05} min={0} className={inputCls} value={s.weights[k]} onChange={(e) => setS({ ...s, weights: { ...s.weights, [k]: Number(e.target.value) } })} />
            </Field>
          ))}
        </div>
        <p className="mt-2 text-[11px] text-ink-400">Scores are deterministic triage rankings for ordering work. They are not calibrated probabilities of compromise. See docs/METHODOLOGY.md for every formula.</p>
      </div>
    </Panel>
  );
}

function FilesPanel() {
  const { data } = useAsync(() => api.datasets(), []);
  if (!data) return null;
  return (
    <Panel title={`Loaded files (${data.files.length})`} bodyClass="p-0">
      <table className="w-full text-[12px]">
        <thead className="text-left text-[10px] uppercase tracking-wider text-ink-400">
          <tr><th className="px-4 py-2">File</th><th>Detected source</th><th>Size</th><th>Read</th><th>Accepted</th><th>Rejected</th><th>Dup.</th><th>Conflict</th><th>Notes</th><th className="pr-4">Time range</th></tr>
        </thead>
        <tbody className="divide-y divide-ink-700">
          {data.files.map((f) => {
            const grouped = new Map<string, { level: string; rows: (number | null)[] }>();
            f.issues.forEach((i) => {
              const key = i.message.replace(/\b(AUTH|FW|EDR|DNS|DB)-\d+\b/g, "<id>");
              const g = grouped.get(key) || { level: i.level, rows: [] };
              g.rows.push(i.source_row);
              grouped.set(key, g);
            });
            return (
              <tr key={f.file_name + f.loaded_at} className="align-top">
                <td className="mono px-4 py-1.5">{f.file_name}</td>
                <td className="text-ink-300">{f.source_system}</td>
                <td className="tabular text-ink-400">{fmtBytes(f.size_bytes)}</td>
                <td className="tabular">{f.records_read}</td>
                <td className="tabular">{f.accepted}</td>
                <td className={`tabular ${f.rejected ? "text-mod" : ""}`}>{f.rejected}</td>
                <td className="tabular">{f.duplicates}</td>
                <td className={`tabular ${f.conflicts ? "text-mod" : ""}`}>{f.conflicts}</td>
                <td className="max-w-[360px]">
                  {grouped.size === 0 ? <span className="text-ink-500">-</span> : (
                    <details>
                      <summary className="cursor-pointer text-ink-300">{f.issues.length} issue(s)</summary>
                      <ul className="mt-1 space-y-0.5 text-[11px]">
                        {[...grouped.entries()].map(([m, g]) => (
                          <li key={m} className={g.level === "error" || g.level === "conflict" ? "text-mod" : "text-ink-400"}>
                            [{g.level}] {m}, row{g.rows.length > 1 ? "s" : ""} {g.rows.slice(0, 6).join(", ")}{g.rows.length > 6 ? ` +${g.rows.length - 6}` : ""}
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                </td>
                <td className="mono pr-4 text-[10px] text-ink-400">{fmtTime(f.first_event)}<br />{fmtTime(f.last_event)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Panel>
  );
}

function RulesPanel() {
  const { data } = useAsync(() => api.rules(), []);
  if (!data) return null;
  return (
    <Panel title="Rule catalogue (every graph element, suspicion value and correlation link cites one of these)">
      <div className="grid gap-2 md:grid-cols-2">
        {Object.entries(data).map(([id, r]) => (
          <div key={id} className="rounded border border-ink-700 bg-ink-850 px-3 py-2">
            <div className="flex items-center gap-2"><span className="mono text-[11px] text-signal">{id}</span><span className="text-[13px] font-medium">{r.title}</span><span className="ml-auto text-[10px] uppercase tracking-wider text-ink-500">{r.kind}</span></div>
            <p className="mt-0.5 text-[12px] leading-snug text-ink-300">{r.description}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}
