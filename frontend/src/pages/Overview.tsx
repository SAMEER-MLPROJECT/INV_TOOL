import { FileWarning, GitBranch, Radar, Siren } from "lucide-react";
import { ActivityTimeline } from "../components/Charts";
import { EntityLink } from "../components/Inspector";
import { PathChain } from "../components/PathChain";
import { Button, CritDots, ErrorBox, Loading, Panel, PriorityPill, Stat } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime, go, useAsync } from "../lib/hooks";

export function Overview() {
  const { data: s, error, loading } = useAsync(() => api.summary(), []);
  const { data: incidents } = useAsync(() => api.incidents(), []);
  if (loading && !s) return <Loading label="Building graph" />;
  if (error) return <ErrorBox msg={error} />;
  if (!s) return null;
  const top = s.top_incident;
  const ing = s.ingestion;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Events ingested" value={s.events.toLocaleString()} sub={`${s.files} files · ${s.source_systems} source systems`} onClick={() => go("evidence")} />
        <Stat label="Unique entities" value={s.entities.toLocaleString()} sub={`${s.entity_types.host ?? 0} hosts · ${s.entity_types.user ?? 0} identities`} onClick={() => go("graph")} />
        <Stat label="Relationships" value={s.relationships.toLocaleString()} sub={`${s.occurrences.toLocaleString()} supporting occurrences`} onClick={() => go("graph")} />
        <Stat
          label="Potential incidents"
          value={s.incidents}
          sub={["Critical", "High", "Moderate", "Low"].filter((p) => s.incidents_by_priority[p]).map((p) => `${s.incidents_by_priority[p]} ${p.toLowerCase()}`).join(" · ") || "none"}
          onClick={() => go("incidents")}
        />
        <Stat label="Critical assets" value={s.critical_assets.length} sub="criticality ≥ 4 in inventory" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.35fr_1fr]">
        <Panel
          title={<span className="flex items-center gap-2"><Siren size={14} className="text-crit" /> Highest-priority investigation</span>}
          actions={top && <PriorityPill priority={top.priority} score={top.score} />}
        >
          {!top ? (
            <p className="text-sm text-ink-400">No suspicious signals in the loaded data.</p>
          ) : (
            <div className="space-y-3">
              <div>
                <div className="mono text-xs text-ink-400">{top.id}</div>
                <div className="text-lg font-semibold leading-snug">{top.title}</div>
                <div className="mono mt-0.5 text-xs text-ink-400">{fmtTime(top.start)} → {fmtTime(top.end)} · {top.independent_sources} independent sources</div>
              </div>
              <div className="grid gap-3 text-sm sm:grid-cols-2">
                <div>
                  <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-400">Identities</div>
                  <div className="flex flex-wrap gap-1">{top.identities.map((i) => <EntityLink key={i} id={i} className="border border-ink-600 bg-ink-850 py-0.5" />)}</div>
                </div>
                <div>
                  <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-400">Affected assets</div>
                  <div className="flex flex-wrap gap-1">{top.affected_assets.slice(0, 8).map((i) => <EntityLink key={i} id={i} className="border border-ink-600 bg-ink-850 py-0.5" />)}</div>
                </div>
              </div>
              {top.hypothesis_nodes && (
                <div>
                  <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-400">Attack-path hypothesis</div>
                  <PathChain nodes={top.hypothesis_nodes} />
                </div>
              )}
              <div className="flex flex-wrap gap-2 pt-1">
                <Button variant="primary" onClick={() => go("incidents", { id: top.id })}><Siren size={14} /> Open investigation</Button>
                {top.hypothesis_nodes && (
                  <Button onClick={() => go("paths", { source: top.hypothesis_nodes![0], target: top.hypothesis_nodes![top.hypothesis_nodes!.length - 1] })}>
                    <GitBranch size={14} /> Explore attack paths
                  </Button>
                )}
                {top.identities[0] && <Button onClick={() => go("blast", { entity: top.identities[0] })}><Radar size={14} /> Blast radius of {top.identities[0].split(":")[1]}</Button>}
              </div>
            </div>
          )}
        </Panel>

        <Panel title="Investigation queue" bodyClass="p-0">
          <ul className="divide-y divide-ink-700">
            {(incidents || []).map((i) => (
              <li key={i.id}>
                <button onClick={() => go("incidents", { id: i.id })} className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-ink-850">
                  <PriorityPill priority={i.priority} score={i.score} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13px]">{i.title}</div>
                    <div className="mono text-[11px] text-ink-400">{i.id} · {fmtTime(i.start)} · {i.alerts} alerts · {i.independent_sources} sources{i.dismissed_by_source ? " · dismissed by source" : ""}</div>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <Panel title="Activity over time" actions={<span className="mono text-[11px] text-ink-400">{fmtTime(s.time_range.start)} → {fmtTime(s.time_range.end)}</span>}>
        <ActivityTimeline data={s.histogram} />
      </Panel>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Critical assets" bodyClass="p-0">
          <ul className="max-h-72 divide-y divide-ink-700 overflow-y-auto">
            {s.critical_assets.map((a) => (
              <li key={a.id} className="flex items-center gap-2 px-4 py-1.5 text-[13px]">
                <EntityLink id={a.id} className="flex-1" />
                <span className="text-[11px] text-ink-400">{a.category}</span>
                <CritDots n={a.criticality} />
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Events by source system">
          <div className="space-y-2">
            {Object.entries(s.events_by_source).sort((a, b) => b[1] - a[1]).map(([k, v]) => (
              <div key={k} className="grid grid-cols-[110px_1fr_48px] items-center gap-2 text-xs">
                <span className="mono text-ink-300">{k}</span>
                <div className="h-2 rounded-full bg-ink-800"><div className="h-2 rounded-full bg-ink-400" style={{ width: `${(100 * v) / Math.max(...Object.values(s.events_by_source))}%` }} /></div>
                <span className="tabular text-right text-ink-200">{v}</span>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title={<span className="flex items-center gap-2"><FileWarning size={14} /> Ingestion quality</span>} actions={<Button variant="ghost" onClick={() => go("settings")}>Details</Button>}>
          <dl className="grid grid-cols-2 gap-y-1.5 text-[13px]">
            {[["Records read", ing.records_read], ["Accepted", ing.accepted], ["Rejected (invalid)", ing.rejected], ["Duplicates ignored", ing.duplicates], ["ID conflicts", ing.conflicts], ["Normalization notes", ing.warnings]].map(([k, v]) => (
              <div key={k as string} className="contents">
                <dt className="text-ink-400">{k}</dt>
                <dd className={`tabular text-right ${(k === "Rejected (invalid)" || k === "ID conflicts") && (v as number) > 0 ? "text-mod" : ""}`}>{(v ?? 0).toLocaleString()}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-[11px] leading-snug text-ink-400">Invalid records are rejected with a reason; nothing is silently repaired. Open Settings &amp; Data for row-level detail.</p>
        </Panel>
      </div>
    </div>
  );
}
