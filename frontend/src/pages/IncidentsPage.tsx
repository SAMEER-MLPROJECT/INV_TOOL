import { useEffect, useState } from "react";
import { Download, GitBranch, Radar } from "lucide-react";
import { IncidentChannelMatrix, PathChannelMatrix } from "../components/ChannelMatrix";
import { ContainmentPanel } from "../components/Containment";
import { EntityLink, EventLink } from "../components/Inspector";
import { PathChain } from "../components/PathChain";
import { BasisTag, Button, Empty, ErrorBox, Loading, Panel, PriorityPill, ScoreBreakdown } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime, go, setParams, useAsync, type Route } from "../lib/hooks";

export function IncidentsPage({ route }: { route: Route }) {
  const { data: list, error } = useAsync(() => api.incidents(), []);
  const [id, setId] = useState(route.params.get("id") || "");
  useEffect(() => {
    if (!id && list?.length) setId(list[0].id);
  }, [list, id]);
  useEffect(() => {
    const p = route.params.get("id");
    if (p) setId(p);
  }, [route]);
  useEffect(() => {
    if (id) setParams("incidents", { id });
  }, [id]);
  if (error) return <ErrorBox msg={error} />;
  if (!list) return <Loading />;
  if (!list.length) return <Empty>No incidents: no alert or high-severity record in the loaded data.</Empty>;
  return (
    <div className="grid gap-4 xl:grid-cols-[340px_1fr]">
      <Panel title={`Incidents (${list.length})`} bodyClass="p-0">
        <ul className="divide-y divide-ink-700">
          {list.map((i) => (
            <li key={i.id}>
              <button onClick={() => setId(i.id)} className={`w-full px-3 py-2.5 text-left ${i.id === id ? "bg-ink-800" : "hover:bg-ink-850"}`}>
                <div className="flex items-center justify-between gap-2">
                  <span className="mono text-[11px] text-ink-400">{i.id}</span>
                  <PriorityPill priority={i.priority} score={i.score} />
                </div>
                <div className="mt-1 text-[13px] leading-snug">{i.title}</div>
                <div className="mt-0.5 text-[11px] text-ink-400">
                  {fmtTime(i.start)} · {i.alerts} alert(s) · {i.supporting_events} records · {i.independent_sources} source(s)
                  {i.dismissed_by_source && " · dismissed by source"}
                </div>
              </button>
            </li>
          ))}
        </ul>
      </Panel>
      {id && <IncidentDetail id={id} />}
    </div>
  );
}

function IncidentDetail({ id }: { id: string }) {
  const { data: inc, error, loading } = useAsync(() => api.incident(id), [id]);
  if (loading && !inc) return <Loading />;
  if (error) return <ErrorBox msg={error} />;
  if (!inc) return null;
  const h = inc.hypothesis;
  return (
    <div className="min-w-0 space-y-4">
      <Panel>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="mono text-xs text-ink-400">{inc.id}</div>
            <h1 className="text-xl font-semibold leading-snug">{inc.title}</h1>
            <div className="mono mt-1 text-xs text-ink-400">{fmtTime(inc.start)} → {fmtTime(inc.end)}</div>
          </div>
          <div className="flex flex-col items-end gap-2">
            <PriorityPill priority={inc.priority} score={inc.score} />
            <div className="flex gap-1.5">
              {(["html", "md", "json"] as const).map((f) => (
                <a key={f} href={api.reportUrl(inc.id, f)} download className="inline-flex items-center gap-1 rounded-md border border-ink-600 bg-ink-800 px-2.5 py-1 text-xs hover:bg-ink-700">
                  <Download size={12} /> {f === "md" ? "Markdown" : f.toUpperCase()}
                </a>
              ))}
            </div>
          </div>
        </div>
        <ul className="mt-3 list-disc space-y-1 pl-5 text-[13px] text-ink-200">{inc.explanation.map((e) => <li key={e}>{e}</li>)}</ul>
        {inc.dismissed_by_source && <p className="mt-2 text-xs text-mod">All seed alerts were closed as benign by the originating tool; the priority is reduced but the incident stays visible.</p>}
      </Panel>

      <div className="grid gap-4 2xl:grid-cols-2">
        <Panel title="Attack-path hypothesis" actions={h && (
          <>
            <Button onClick={() => go("paths", { source: h.source, target: h.target })}><GitBranch size={13} /> Path explorer</Button>
            <Button onClick={() => go("blast", { entity: h.source })}><Radar size={13} /> Blast radius</Button>
          </>
        )}>
          {!h ? (
            <p className="text-sm text-ink-400">No temporally consistent path from the incident's identities reaches a critical asset.</p>
          ) : (
            <div className="space-y-3">
              <PathChain nodes={h.nodes} rels={h.steps.map((s) => s.relationship)} />
              <ol className="space-y-1.5">
                {h.steps.map((s, i) => (
                  <li key={i} className="grid grid-cols-[18px_1fr] gap-2 text-[12px]">
                    <span className="text-ink-500">{i + 1}</span>
                    <div>
                      <div className="flex flex-wrap items-center gap-2"><span className="mono text-ink-400">{fmtTime(s.timestamp)}</span><BasisTag basis={s.basis} />{s.suspicion >= 0.5 && <span className="text-[11px] text-high">suspicion {s.suspicion.toFixed(2)}</span>}</div>
                      <div className="text-ink-200">{s.description}</div>
                      <div className="text-[10px] text-ink-400"><EventLink uid={s.event_uid} /> · {s.source_file}#{s.source_row}</div>
                    </div>
                  </li>
                ))}
              </ol>
              <ul className="list-disc pl-5 text-[12px] text-ink-300">{h.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
            </div>
          )}
        </Panel>
        <Panel title="Priority breakdown"><ScoreBreakdown breakdown={inc.breakdown} disclaimer={inc.disclaimer} /></Panel>
      </div>

      <Panel title="Containment planner & what-if simulation">
        <ContainmentPanel incidentId={inc.id} defaultAt={inc.start} />
      </Panel>

      {inc.channels && (
        <div className="grid gap-4">
          <Panel title="Multichannel corroboration: incident entities">
            <IncidentChannelMatrix data={inc.channels} />
          </Panel>
          {h?.channels && (
            <Panel title="Multichannel corroboration: attack-path hypothesis">
              <PathChannelMatrix data={h.channels} />
            </Panel>
          )}
        </div>
      )}

      <div className="grid gap-4 2xl:grid-cols-[1fr_1fr]">
        <Panel title={`Correlated alerts (${inc.alerts.length})`} bodyClass="p-0">
          <table className="w-full text-[12px]">
            <thead className="text-left text-[10px] uppercase tracking-wider text-ink-400"><tr><th className="px-4 py-2">Time</th><th>Rule</th><th>ATT&amp;CK</th><th>Sev.</th><th className="pr-4">Disposition</th></tr></thead>
            <tbody className="divide-y divide-ink-700">
              {inc.alerts.map((a) => (
                <tr key={a.uid}>
                  <td className="mono whitespace-nowrap px-4 py-1.5 text-ink-400">{fmtTime(a.timestamp, false)}</td>
                  <td className="pr-3"><EventLink uid={a.uid} /> <span className="text-ink-200">{a.rule}</span></td>
                  <td className="mono whitespace-nowrap pr-3 text-ink-300">{a.technique || "-"}</td>
                  <td className={`tabular pr-3 ${a.severity >= 0.75 ? "text-crit" : a.severity >= 0.5 ? "text-high" : "text-ink-300"}`}>{a.severity.toFixed(2)}</td>
                  <td className="pr-4 text-ink-400">{a.disposition}</td>
                </tr>
              ))}
              {inc.alerts.length === 0 && <tr><td colSpan={5} className="px-4 py-3 text-ink-400">No SIEM alert: this incident was seeded by high-severity source records only.</td></tr>}
            </tbody>
          </table>
        </Panel>
        <Panel title="Involved entities">
          <div className="space-y-2">
            {Object.entries(inc.entities).map(([type, ids]) => (
              <div key={type} className="grid grid-cols-[80px_1fr] gap-2 text-[12px]">
                <span className="text-[11px] uppercase tracking-wider text-ink-400">{type}</span>
                <div className="flex flex-wrap gap-1">{ids.map((e) => <EntityLink key={e} id={e} className="border border-ink-700 bg-ink-850 py-0.5" />)}</div>
              </div>
            ))}
          </div>
          <div className="mt-3 text-[12px] text-ink-400">Evidence sources: {inc.evidence_sources.join(", ")}</div>
        </Panel>
      </div>

      <Panel title={`How these signals were grouped (${inc.correlation_links.length} links)`}>
        {inc.correlation_links.length === 0 ? (
          <p className="text-sm text-ink-400">A single seed signal; nothing else correlated with it inside the window.</p>
        ) : (
          <ul className="space-y-1 text-[12px]">
            {inc.correlation_links.map((l, i) => (
              <li key={i} className="flex flex-wrap items-center gap-1.5">
                <span className="mono rounded bg-ink-800 px-1.5 text-[10px] text-signal" title="See Settings → Rules">{l.rule}</span>
                <EventLink uid={l.a} /> <span className="text-ink-500">↔</span> <EventLink uid={l.b} />
                <span className="text-ink-300">{l.detail}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title={`Timeline (${inc.timeline.length} records)`} bodyClass="p-0">
        <ol className="relative max-h-[560px] overflow-y-auto py-2">
          {inc.timeline.map((t) => (
            <li key={t.uid} className="grid grid-cols-[150px_14px_1fr] items-start gap-2 px-4 py-1 text-[12px] hover:bg-ink-850">
              <span className="mono text-ink-400">{fmtTime(t.timestamp)}</span>
              <span className={`mt-1 h-2.5 w-2.5 rounded-full ${t.category === "alert" ? "bg-crit" : t.seed ? "bg-high" : t.severity > 0 ? "bg-mod" : "bg-ink-500"}`} title={t.seed ? "seed signal" : "supporting record"} />
              <div className="min-w-0">
                <span className={t.category === "alert" ? "font-medium text-ink-100" : "text-ink-200"}>{t.description}</span>
                <span className="ml-2 text-[10px] text-ink-400">{t.source_system} · <EventLink uid={t.uid} /></span>
              </div>
            </li>
          ))}
        </ol>
      </Panel>
    </div>
  );
}
