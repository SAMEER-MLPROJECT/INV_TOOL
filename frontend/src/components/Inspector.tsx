import { createContext, useContext, useState, type ReactNode } from "react";
import { Crosshair, GitBranch, Radar, Share2, X } from "lucide-react";
import { api } from "../lib/api";
import { fmtTime, go, shortName, useAsync, useDataVersion } from "../lib/hooks";
import { BasisTag, Button, CritDots, ErrorBox, Loading, TypeIcon } from "./ui";

type Target = { kind: "entity" | "relationship" | "event"; id: string };
const Ctx = createContext<{ open: (t: Target) => void }>({ open: () => {} });
export const useInspector = () => useContext(Ctx);

export function InspectorProvider({ children }: { children: ReactNode }) {
  const [stack, setStack] = useState<Target[]>([]);
  const current = stack[stack.length - 1];
  return (
    <Ctx.Provider value={{ open: (t) => setStack((s) => [...s.slice(-8), t]) }}>
      {children}
      {current && (
        <aside
          aria-label="Evidence inspector"
          className="fixed inset-y-0 right-0 z-40 flex w-[520px] max-w-[95vw] flex-col border-l border-ink-600 bg-ink-900 shadow-2xl shadow-black/60"
        >
          <header className="flex items-center justify-between border-b border-ink-700 px-4 py-2.5">
            <div className="flex items-center gap-2 text-xs text-ink-400">
              {stack.length > 1 && (
                <button className="rounded px-1.5 py-0.5 hover:bg-ink-800 hover:text-ink-100" onClick={() => setStack((s) => s.slice(0, -1))}>
                  ← back
                </button>
              )}
              <span className="uppercase tracking-wider">{current.kind} evidence</span>
            </div>
            <button aria-label="Close inspector" className="rounded p-1 text-ink-300 hover:bg-ink-800 hover:text-ink-100" onClick={() => setStack([])}>
              <X size={16} />
            </button>
          </header>
          <div className="flex-1 overflow-y-auto p-4 text-[13px]">
            {current.kind === "entity" && <EntityView id={current.id} close={() => setStack([])} />}
            {current.kind === "relationship" && <RelView id={current.id} />}
            {current.kind === "event" && <EventView uid={current.id} />}
          </div>
        </aside>
      )}
    </Ctx.Provider>
  );
}

export function EntityLink({ id, className = "" }: { id: string; className?: string }) {
  const { open } = useInspector();
  const type = id.split(":")[0];
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        open({ kind: "entity", id });
      }}
      className={`inline-flex max-w-full items-center gap-1 truncate rounded px-1 text-left text-ink-100 hover:bg-ink-700 ${className}`}
      title={id}
    >
      <TypeIcon type={type} size={12} className="shrink-0 text-ink-400" />
      <span className="truncate">{shortName(id)}</span>
    </button>
  );
}

export function EventLink({ uid }: { uid: string }) {
  const { open } = useInspector();
  return (
    <button onClick={(e) => { e.stopPropagation(); open({ kind: "event", id: uid }); }} className="mono rounded px-1 text-signal hover:bg-ink-700" title="Open source record">
      {uid}
    </button>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mb-5">
      <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-ink-400">{title}</h3>
      {children}
    </div>
  );
}

function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[130px_1fr] gap-x-3 gap-y-1">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-ink-400">{k}</dt>
          <dd className="min-w-0 break-words text-ink-100">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function suspicionColor(s: number) {
  return s >= 0.75 ? "text-crit" : s >= 0.5 ? "text-high" : s > 0 ? "text-mod" : "text-ink-400";
}

function EntityView({ id, close }: { id: string; close: () => void }) {
  const { open } = useInspector();
  const { bump } = useDataVersion();
  const { data, error, loading, reload } = useAsync(() => api.entity(id), [id]);
  const [busy, setBusy] = useState(false);
  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox msg={error} />;
  if (!data) return null;
  const setStatus = async (s: string | null) => {
    setBusy(true);
    try {
      await api.setStatus(id, s);
      reload();
      bump();
    } finally {
      setBusy(false);
    }
  };
  const relRow = (r: any) => (
    <button key={r.id} onClick={() => open({ kind: "relationship", id: r.id })} className="grid w-full grid-cols-[1fr_auto] gap-2 rounded px-1.5 py-1 text-left hover:bg-ink-800">
      <span className="truncate">
        <span className="mono text-[11px] text-ink-400">{r.type}</span>{" "}
        {shortName(r.source === id ? r.target : r.source)}
      </span>
      <span className="tabular text-[11px] text-ink-400">
        ×{r.count} <span className={suspicionColor(r.max_suspicion)}>{r.max_suspicion > 0 ? `susp ${r.max_suspicion.toFixed(2)}` : ""}</span>
      </span>
    </button>
  );
  return (
    <div>
      <div className="mb-4 flex items-start gap-3">
        <div className="rounded-md border border-ink-600 bg-ink-800 p-2 text-ink-200">
          <TypeIcon type={data.type} category={data.category} size={20} />
        </div>
        <div className="min-w-0">
          <div className="truncate text-base font-semibold">{data.name}</div>
          <div className="mono text-[11px] text-ink-400">{data.id}</div>
          <div className="mt-1 flex items-center gap-2 text-xs text-ink-300">
            {data.type} · {data.category || "uncategorised"} · <CritDots n={data.criticality} />
          </div>
        </div>
      </div>
      <Section title="Why it exists">
        <p className="text-ink-200">{data.why_it_exists}</p>
        <p className="mt-1 text-xs text-ink-400">
          First seen {fmtTime(data.first_seen)} · last seen {fmtTime(data.last_seen)}
        </p>
      </Section>
      <div className="mb-5 flex flex-wrap gap-2">
        <Button onClick={() => { close(); go("blast", { entity: id }); }}><Radar size={14} /> Blast radius</Button>
        <Button onClick={() => { close(); go("paths", { source: id }); }}><GitBranch size={14} /> Paths from here</Button>
        <Button onClick={() => { close(); go("graph", { focus: id, depth: 1 }); }}><Share2 size={14} /> Focus in graph</Button>
      </div>
      <Section title="Analyst disposition">
        <p className="mb-2 text-xs text-ink-400">
          Only an analyst can mark an entity as a confirmed compromise; the engine never does this automatically.
          Current: <b className="text-ink-200">{data.analyst_status || "none"}</b>
        </p>
        <div className="flex gap-2">
          <Button variant="danger" disabled={busy || data.analyst_status === "confirmed"} onClick={() => setStatus("confirmed")}>
            <Crosshair size={14} /> Mark confirmed compromise
          </Button>
          <Button disabled={busy || data.analyst_status === "cleared"} onClick={() => setStatus("cleared")}>Mark cleared</Button>
          <Button variant="ghost" disabled={busy || !data.analyst_status} onClick={() => setStatus(null)}>Reset</Button>
        </div>
      </Section>
      {data.alerts.length > 0 && (
        <Section title={`Alerts naming this entity (${data.alerts.length})`}>
          {data.alerts.map((a: any) => (
            <div key={a.alert} className="mb-1 flex justify-between gap-2 rounded bg-ink-850 px-2 py-1">
              <span className="truncate">{a.rule}</span>
              <span className="tabular shrink-0 text-[11px] text-ink-400">{fmtTime(a.timestamp)} · {a.disposition}</span>
            </div>
          ))}
        </Section>
      )}
      {data.incidents?.length > 0 && (
        <Section title="Incidents">
          <div className="flex flex-wrap gap-2">
            {data.incidents.map((i: string) => (
              <Button key={i} variant="ghost" onClick={() => { close(); go("incidents", { id: i }); }}>{i}</Button>
            ))}
          </div>
        </Section>
      )}
      <Section title={`Outbound relationships (${data.outbound.length})`}>{data.outbound.slice(0, 40).map(relRow)}</Section>
      <Section title={`Inbound relationships (${data.inbound.length})`}>{data.inbound.slice(0, 40).map(relRow)}</Section>
      <Section title={`Source records (${data.event_count}${data.event_count > data.events.length ? `, latest ${data.events.length}` : ""})`}>
        {data.events.slice().reverse().map((e: any) => (
          <button key={e.uid} onClick={() => open({ kind: "event", id: e.uid })} className="block w-full rounded px-1.5 py-1 text-left hover:bg-ink-800">
            <div className="flex justify-between gap-2 text-[11px] text-ink-400">
              <span className="mono">{fmtTime(e.timestamp)}</span>
              <span>{e.source_system}</span>
            </div>
            <div className={`truncate ${e.severity >= 0.5 ? "text-high" : "text-ink-200"}`}>{e.description}</div>
          </button>
        ))}
      </Section>
    </div>
  );
}

function RelView({ id }: { id: string }) {
  const { open } = useInspector();
  const { data, error, loading } = useAsync(() => api.relationship(id), [id]);
  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox msg={error} />;
  if (!data) return null;
  return (
    <div>
      <div className="mb-4 rounded-md border border-ink-700 bg-ink-850 p-3">
        <div className="flex flex-wrap items-center gap-1.5 text-sm">
          <EntityLink id={data.source} />
          <span className="mono text-[11px] text-signal">—{data.type}→</span>
          <EntityLink id={data.target} />
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-ink-300">
          <BasisTag basis={data.basis} /> {data.occurrence_count} occurrence(s) · {data.independent_sources} source system(s) ·
          max suspicion <span className={suspicionColor(data.max_suspicion)}>{data.max_suspicion.toFixed(2)}</span>
        </div>
      </div>
      <Section title="Why it exists">
        <p className="mb-2 text-ink-200">{data.basis_explanation}</p>
        {data.rules.map((r: any) => (
          <div key={r.id} className="mb-1.5 rounded bg-ink-850 px-2 py-1.5">
            <span className="mono mr-2 text-[11px] text-signal">{r.id}</span>
            <span className="font-medium">{r.title}</span>
            <p className="text-xs text-ink-300">{r.description}</p>
          </div>
        ))}
        <p className="mt-2 text-xs italic text-ink-400">{data.caveat}</p>
      </Section>
      <Section title="Time span">
        <KV rows={[["First seen", fmtTime(data.first_seen)], ["Last seen", fmtTime(data.last_seen)], ["Sources", data.sources.join(", ")]]} />
      </Section>
      {data.incidents?.length > 0 && (
        <Section title="Contributes to incidents">
          <div className="flex gap-2">{data.incidents.map((i: string) => <Button key={i} variant="ghost" onClick={() => go("incidents", { id: i })}>{i}</Button>)}</div>
        </Section>
      )}
      <Section title={`Supporting occurrences (${data.occurrence_count}) · most suspicious first`}>
        <div className="space-y-1">
          {[...data.occurrences].sort((a: any, b: any) => b.suspicion - a.suspicion || a.timestamp.localeCompare(b.timestamp)).map((o: any) => (
            <button key={o.event_uid} onClick={() => open({ kind: "event", id: o.event_uid })} className="block w-full rounded border border-transparent px-2 py-1.5 text-left hover:border-ink-600 hover:bg-ink-850">
              <div className="flex items-center justify-between gap-2 text-[11px]">
                <span className="mono text-ink-300">{fmtTime(o.timestamp)}</span>
                <span className="flex items-center gap-1.5">
                  <span className="mono text-ink-400">{o.rule}</span>
                  <BasisTag basis={o.basis} />
                  <span className={`tabular ${suspicionColor(o.suspicion)}`}>{o.suspicion.toFixed(2)}</span>
                </span>
              </div>
              <div className="truncate text-ink-200">{o.description}</div>
              {o.deviation && o.deviation.d2 > 18.47 && (
                <div className="text-[11px] text-mod" title={`Robust Mahalanobis D² ${o.deviation.d2} against ${o.deviation.baseline}`}>
                  MD deviation D² {o.deviation.d2.toFixed(1)} · {o.deviation.explanation}
                </div>
              )}
              <div className="mono truncate text-[10px] text-ink-400">
                {o.event_uid} · {o.source_file}#{o.source_row}
                {o.suspicion_rule && ` · ${o.suspicion_rule}${o.alert ? ` via ${o.alert}` : ""}`}
              </div>
            </button>
          ))}
        </div>
      </Section>
    </div>
  );
}

function EventView({ uid }: { uid: string }) {
  const { open } = useInspector();
  const { data, error, loading } = useAsync(() => api.event(uid), [uid]);
  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox msg={error} />;
  if (!data) return null;
  return (
    <div>
      <div className="mb-4 rounded-md border border-ink-700 bg-ink-850 p-3">
        <div className={`font-medium ${data.severity >= 0.5 ? "text-high" : "text-ink-100"}`}>{data.description}</div>
        <div className="mono mt-1 text-[11px] text-ink-400">{data.uid}</div>
      </div>
      <Section title="Provenance">
        <KV
          rows={[
            ["Event ID", <span className="mono">{data.event_id}</span>],
            ["Timestamp (UTC)", <span className="mono">{fmtTime(data.timestamp)}</span>],
            ["Source system", data.source_system],
            ["Source file", <span className="mono">{data.source_file} · row {data.source_row}</span>],
            ["Category", `${data.category} / ${data.action} / ${data.outcome}`],
            ["Severity", data.severity.toFixed(2)],
          ]}
        />
        {data.notes.length > 0 && (
          <ul className="mt-2 list-disc pl-5 text-xs text-mod">{data.notes.map((n: string) => <li key={n}>{n}</li>)}</ul>
        )}
      </Section>
      {data.unresolved_evidence_refs?.length > 0 && (
        <Section title="Unresolved evidence references">
          <p className="text-xs text-mod">
            This alert cites record(s) that are not present in the loaded data: {data.unresolved_evidence_refs.join(", ")}. The evidence is incomplete.
          </p>
        </Section>
      )}
      <Section title="Graph elements created by this record">
        {data.graph_relationships.length === 0 && <p className="text-xs text-ink-400">None (e.g. failed logon, blocked flow, or context record).</p>}
        {data.graph_relationships.map((r: string) => (
          <button key={r} onClick={() => open({ kind: "relationship", id: r })} className="mono block w-full truncate rounded px-1.5 py-1 text-left text-[11px] text-ink-200 hover:bg-ink-800">
            {r}
          </button>
        ))}
      </Section>
      {(data.cited_by_alerts.length > 0 || data.incidents?.length > 0) && (
        <Section title="Referenced by">
          <div className="flex flex-wrap gap-2">
            {data.cited_by_alerts.map((a: string) => <EventLink key={a} uid={a} />)}
            {data.incidents?.map((i: string) => <Button key={i} variant="ghost" onClick={() => go("incidents", { id: i })}>{i}</Button>)}
          </div>
        </Section>
      )}
      <Section title="Original record (verbatim)">
        <pre className="mono max-h-72 overflow-auto rounded bg-ink-950 p-2 text-[11px] text-ink-200">{JSON.stringify(data.raw, null, 2)}</pre>
      </Section>
      <Section title="Normalized form">
        <pre className="mono max-h-72 overflow-auto rounded bg-ink-950 p-2 text-[11px] text-ink-300">
          {JSON.stringify(Object.fromEntries(Object.entries(data.normalized).filter(([, v]) => v !== null && !(Array.isArray(v) && v.length === 0))), null, 2)}
        </pre>
      </Section>
    </div>
  );
}
