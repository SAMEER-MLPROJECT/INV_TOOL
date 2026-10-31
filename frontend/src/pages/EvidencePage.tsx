import { useState } from "react";
import { Download, FileJson, Fingerprint } from "lucide-react";
import { useInspector } from "../components/Inspector";
import { Button, ErrorBox, Field, Loading, Panel, inputCls } from "../components/ui";
import { api } from "../lib/api";
import { fmtBytes, fmtTime, useAsync } from "../lib/hooks";

const PAGE = 100;

function downloadText(name: string, text: string, mime: string) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function EvidencePage() {
  const { open } = useInspector();
  const [q, setQ] = useState("");
  const [source, setSource] = useState("");
  const [category, setCategory] = useState("");
  const [minSev, setMinSev] = useState(0);
  const [offset, setOffset] = useState(0);
  const params = { q, source, category, min_severity: minSev || undefined, offset, limit: PAGE };
  const { data, error, loading } = useAsync(() => api.events(params), [q, source, category, minSev, offset]);
  const { data: manifest } = useAsync(() => api.manifest(), []);
  const { data: summary } = useAsync(() => api.summary(), []);

  const exportCsv = async () => {
    const all = await api.events({ ...params, offset: 0, limit: 1000 });
    const cols = ["uid", "timestamp", "source_system", "source_file", "source_row", "category", "action", "outcome", "severity", "description"] as const;
    const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const rows = all.events.map((e) => cols.map((c) => esc(e[c])).join(","));
    downloadText("attackgraph_events.csv", [cols.join(","), ...rows].join("\n"), "text/csv");
  };

  return (
    <div className="space-y-4">
      <Panel title="Raw event viewer" actions={<Button onClick={exportCsv} title="Export the filtered records (max 1000) as CSV"><Download size={13} /> Export CSV</Button>} bodyClass="p-0">
        <div className="grid gap-3 border-b border-ink-700 p-3 md:grid-cols-[1.5fr_1fr_1fr_1fr]">
          <Field label="Search (description, id, file)"><input className={inputCls} value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} placeholder="e.g. powershell, FINANCE-DB, AUTH-0001" /></Field>
          <Field label="Source system">
            <select className={inputCls} value={source} onChange={(e) => { setSource(e.target.value); setOffset(0); }}>
              <option value="">All</option>
              {Object.keys(summary?.events_by_source || {}).map((s) => <option key={s}>{s}</option>)}
            </select>
          </Field>
          <Field label="Category">
            <select className={inputCls} value={category} onChange={(e) => { setCategory(e.target.value); setOffset(0); }}>
              <option value="">All</option>
              {["authentication", "process", "network", "dns", "db_access", "privilege", "service", "alert"].map((c) => <option key={c}>{c}</option>)}
            </select>
          </Field>
          <Field label={`Minimum severity: ${minSev.toFixed(2)}`}>
            <input type="range" min={0} max={1} step={0.05} value={minSev} onChange={(e) => { setMinSev(Number(e.target.value)); setOffset(0); }} className="mt-2 w-full" />
          </Field>
        </div>
        {error && <div className="p-3"><ErrorBox msg={error} /></div>}
        {loading && !data && <Loading />}
        {data && (
          <>
            <div className="max-h-[520px] overflow-auto">
              <table className="w-full text-[12px]">
                <thead className="sticky top-0 bg-ink-900 text-left text-[10px] uppercase tracking-wider text-ink-400">
                  <tr><th className="px-4 py-2">Time (UTC)</th><th>Event</th><th>Source</th><th>File · row</th><th>Description</th><th className="pr-4 text-right">Sev.</th></tr>
                </thead>
                <tbody className="divide-y divide-ink-700">
                  {data.events.map((e) => (
                    <tr key={e.uid} onClick={() => open({ kind: "event", id: e.uid })} className="cursor-pointer hover:bg-ink-850">
                      <td className="mono whitespace-nowrap px-4 py-1.5 text-ink-400">{fmtTime(e.timestamp)}</td>
                      <td className="mono text-signal">{e.event_id}</td>
                      <td className="text-ink-300">{e.source_system}</td>
                      <td className="mono whitespace-nowrap text-ink-400">{e.source_file} · {e.source_row}</td>
                      <td className={`max-w-[520px] truncate ${e.severity >= 0.5 ? "text-high" : "text-ink-200"}`}>
                        {e.description}{e.notes.length > 0 && <span className="ml-1 text-mod" title={e.notes.join("; ")}>†</span>}
                      </td>
                      <td className="tabular pr-4 text-right text-ink-300">{e.severity.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-ink-700 px-4 py-2 text-xs text-ink-400">
              <span>{data.total.toLocaleString()} record(s) · showing {data.total ? offset + 1 : 0}–{Math.min(offset + PAGE, data.total)} · † normalization note</span>
              <div className="flex gap-2">
                <Button disabled={offset === 0} onClick={() => setOffset(Math.max(offset - PAGE, 0))}>Previous</Button>
                <Button disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>Next</Button>
              </div>
            </div>
          </>
        )}
      </Panel>

      <Panel
        title={<span className="flex items-center gap-2"><Fingerprint size={14} /> Evidence hash manifest (SHA-256)</span>}
        actions={<a href="/api/evidence/manifest?download=true" download className="inline-flex items-center gap-1 rounded-md border border-ink-600 bg-ink-800 px-2.5 py-1 text-xs hover:bg-ink-700"><FileJson size={12} /> Download manifest</a>}
        bodyClass="p-0"
      >
        {!manifest ? <Loading /> : (
          <>
            <table className="w-full text-[12px]">
              <thead className="text-left text-[10px] uppercase tracking-wider text-ink-400"><tr><th className="px-4 py-2">Source file</th><th>Source system</th><th>Size</th><th>Accepted / read</th><th className="pr-4">SHA-256</th></tr></thead>
              <tbody className="divide-y divide-ink-700">
                {manifest.source_files.map((f: any) => (
                  <tr key={f.file_name + f.loaded_at}>
                    <td className="mono px-4 py-1.5">{f.file_name}</td>
                    <td className="text-ink-300">{f.source_system}</td>
                    <td className="tabular text-ink-400">{fmtBytes(f.size_bytes)}</td>
                    <td className="tabular text-ink-300">{f.accepted} / {f.records_read}</td>
                    <td className="mono break-all pr-4 text-[10px] text-ink-300">{f.sha256}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {manifest.exports.length > 0 && (
              <div className="border-t border-ink-700 px-4 py-3">
                <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-400">Exported reports this session</div>
                {manifest.exports.map((x: any) => (
                  <div key={x.exported_at + x.file_name} className="mono flex flex-wrap gap-x-3 text-[11px] text-ink-300">
                    <span>{x.file_name}</span><span className="text-ink-400">{fmtTime(x.exported_at)}</span><span className="break-all text-ink-400">{x.sha256}</span>
                  </div>
                ))}
              </div>
            )}
            <p className="border-t border-ink-700 px-4 py-3 text-[12px] text-mod">{manifest.limitation}</p>
          </>
        )}
      </Panel>
    </div>
  );
}
