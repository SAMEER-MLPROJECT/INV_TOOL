import { useEffect, useMemo, useState } from "react";
import { Radar } from "lucide-react";
import { GrowthChart } from "../components/Charts";
import { EntityPicker } from "../components/EntityPicker";
import { GraphCanvas, GraphLegend, type CanvasEdge } from "../components/GraphCanvas";
import { EntityLink, useInspector } from "../components/Inspector";
import { CLASS_META, ClassPill, CritDots, Empty, ErrorBox, Field, Loading, Panel, Segmented, inputCls } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime, setParams, useAsync, useDataVersion, type Route } from "../lib/hooks";
import type { BlastClass, BlastResult } from "../lib/types";
import { toCanvasNodes } from "./PathsPage";

const CLASSES: BlastClass[] = ["CONFIRMED_COMPROMISE", "SUSPECTED_LATERAL_MOVEMENT", "OBSERVED_CONNECTION", "POTENTIAL_EXPOSURE"];
const TONE: Record<BlastClass, "crit" | "high" | "signal" | "muted"> = {
  CONFIRMED_COMPROMISE: "crit", SUSPECTED_LATERAL_MOVEMENT: "high", OBSERVED_CONNECTION: "signal", POTENTIAL_EXPOSURE: "muted",
};

export function BlastPage({ route }: { route: Route }) {
  const P = route.params;
  const { open } = useInspector();
  const { version } = useDataVersion();
  const { data: entList } = useAsync(() => api.entities(), []);
  const ents = useMemo(() => new Map((entList || []).map((e) => [e.id, e])), [entList]);
  const [entity, setEntity] = useState(P.get("entity") || "");
  const [hops, setHops] = useState(Number(P.get("hops") || 3));
  const [mode, setMode] = useState<"temporal" | "structural">((P.get("mode") as "temporal") || "temporal");
  const [since, setSince] = useState("");
  const [procs, setProcs] = useState<"show" | "hide">("hide");
  const [filter, setFilter] = useState<BlastClass | "">("");
  const [res, setRes] = useState<BlastResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!entity) return;
    setParams("blast", { entity, hops, mode });
    const t = setTimeout(() => {
      setBusy(true);
      setErr(null);
      api.blast(entity, hops, mode === "temporal", true, since ? `${since}:00Z` : undefined)
        .then(setRes)
        .catch((e) => { setErr(e.message); setRes(null); })
        .finally(() => setBusy(false));
    }, 120);
    return () => clearTimeout(t);
  }, [entity, hops, mode, since, version]);

  const hideProcs = procs === "hide";
  const shown = useMemo(
    () => (res?.nodes || []).filter((n) => (!filter || n.classification === filter) && !(hideProcs && n.type === "process")),
    [res, filter, hideProcs],
  );
  const canvas = useMemo(() => {
    if (!res) return null;
    const keep = new Set([res.source, ...shown.map((n) => n.id)]);
    const suspicious = new Set(res.nodes.flatMap((n) => n.suspicious_relationships));
    const parse = (id: string) => { const [s, t, d] = id.split("|"); return { id, source: s, target: d, type: t }; };
    let edges: CanvasEdge[];
    if (hideProcs) {
      edges = shown.filter((n) => n.via.length > 0).map((n) => {
        const chain = n.via.map(parse);
        let k = chain.length - 1;
        while (k > 0 && chain[k].source.startsWith("process:")) k--;
        const seg = chain.slice(k);
        return {
          id: n.via[n.via.length - 1], source: seg[0].source, target: n.id, type: seg.map((c) => c.type).join(" › "),
          max_suspicion: seg.some((c) => suspicious.has(c.id)) ? 1 : 0, basis: "observed" as const,
        };
      }).filter((e) => keep.has(e.source));
    } else {
      edges = res.edges.map(parse).filter((e) => keep.has(e.source) && keep.has(e.target));
      edges.forEach((e) => (e.max_suspicion = suspicious.has(e.id) ? 1 : 0));
    }
    const cls = new Map(res.nodes.map((n) => [n.id, n.classification]));
    const nodes = toCanvasNodes(keep, ents).map((n) => {
      const c = cls.get(n.id);
      return c ? { ...n, badge: CLASS_META[c].short, badgeTone: TONE[c] } : n;
    });
    return { nodes, edges, suspicious };
  }, [res, shown, ents, hideProcs]);

  return (
    <div className="space-y-4">
      <Panel>
        <div className="grid items-end gap-3 lg:grid-cols-[1.4fr_1.4fr_auto_1fr_auto]">
          <Field label="Compromised (or suspected) entity"><EntityPicker id="blast-entity" value={entity} onChange={setEntity} placeholder="e.g. user:sameer" /></Field>
          <Field label={`Hop limit: ${hops}`}>
            <input aria-label="Hop limit" type="range" min={1} max={8} value={hops} onChange={(e) => setHops(Number(e.target.value))} className="mt-2 w-full" />
          </Field>
          <Field label="Time model">
            <Segmented value={mode} onChange={setMode} options={[{ value: "temporal", label: "Respect time" }, { value: "structural", label: "Structural" }]} />
          </Field>
          <Field label="Compromise time (UTC, optional)">
            <input type="datetime-local" className={inputCls} disabled={mode !== "temporal"} value={since} onChange={(e) => setSince(e.target.value)} />
          </Field>
          <Field label="Processes">
            <Segmented value={procs} onChange={setProcs} options={[{ value: "hide", label: "Collapse" }, { value: "show", label: "Show" }]} />
          </Field>
        </div>
        {res && (
          <p className="mt-2 text-[12px] text-ink-400">
            {mode === "temporal" ? (
              <>Reachability counted only along time-respecting routes starting <b className="text-ink-200">{res.start_time ? fmtTime(res.start_time) : "at the beginning of the data"}</b> ({res.start_time_basis}).</>
            ) : (
              <>Structural reachability: every route in the graph is counted regardless of when it was observed.</>
            )}
          </p>
        )}
      </Panel>
      {err && <ErrorBox msg={err} />}
      {!entity && <Empty>Select an entity to calculate its blast radius.</Empty>}
      {busy && !res && <Loading label="Calculating blast radius" />}
      {res && (
        <>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[repeat(4,1fr)_1.3fr]">
            {CLASSES.map((c) => (
              <button key={c} onClick={() => setFilter(filter === c ? "" : c)} title={res.class_definitions[c]}
                className={`rounded-lg border bg-ink-900 px-4 py-3 text-left transition ${filter === c ? "border-signal" : "border-ink-700 hover:border-ink-500"}`}>
                <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-ink-400">
                  <span className={`h-2 w-2 rounded-full ${CLASS_META[c].dot}`} /> {CLASS_META[c].label}
                </div>
                <div className="tabular mt-1 text-2xl font-semibold">{res.summary.by_classification[c] ?? 0}</div>
                <div className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-ink-400">{res.class_definitions[c]}</div>
              </button>
            ))}
            <div className="rounded-lg border border-ink-700 bg-ink-900 px-3 pt-2">
              <div className="text-[11px] font-medium uppercase tracking-wider text-ink-400">Reach by hop limit (click to set)</div>
              <GrowthChart data={res.growth} current={hops} onPick={setHops} />
            </div>
          </div>

          <div className="grid gap-4 xl:grid-cols-[1fr_440px]">
            <div className="space-y-2">
              <div className="h-[460px] overflow-hidden rounded-lg border border-ink-700 bg-ink-900">
                {canvas && canvas.nodes.length > 1 ? (
                  <GraphCanvas nodes={canvas.nodes} edges={canvas.edges} rootId={res.source} highlightEdges={canvas.suspicious} showEdgeLabels={canvas.nodes.length < 45} />
                ) : (
                  <Empty>Nothing reachable under these settings.</Empty>
                )}
              </div>
              <GraphLegend />
            </div>
            <Panel title={<span className="flex items-center gap-2"><Radar size={14} /> Critical exposure</span>} bodyClass="p-0">
              {res.summary.critical_assets.length === 0 ? (
                <Empty>No asset with criticality ≥ 4 is reachable within {hops} hop(s).</Empty>
              ) : (
                <ul className="divide-y divide-ink-700">
                  {res.summary.critical_assets.map((a) => (
                    <li key={a.id} className="flex items-center gap-2 px-4 py-2 text-[13px]">
                      <EntityLink id={a.id} className="flex-1" />
                      <span className="text-[11px] text-ink-400">hop {a.hop}</span>
                      <CritDots n={a.criticality} />
                      <ClassPill c={a.classification} />
                    </li>
                  ))}
                </ul>
              )}
              <div className="border-t border-ink-700 px-4 py-2.5 text-[12px] text-ink-400">
                {res.summary.accounts.length} account(s) reachable: {res.summary.accounts.slice(0, 8).map((a) => a.split(":")[1]).join(", ") || "none"}
              </div>
            </Panel>
          </div>

          <Panel title={`Reachable entities (${shown.length}${filter ? ` · ${CLASS_META[filter].label}` : ""})`} bodyClass="p-0">
            <div className="max-h-[520px] overflow-auto">
              <table className="w-full text-[12px]">
                <thead className="sticky top-0 bg-ink-900 text-left text-[10px] uppercase tracking-wider text-ink-400">
                  <tr><th className="px-4 py-2">Entity</th><th>Type</th><th>Hop</th><th>Evidence tier</th><th>Criticality</th><th>Earliest arrival</th><th className="text-right">Impact</th><th className="px-4">Route (click for evidence)</th></tr>
                </thead>
                <tbody className="divide-y divide-ink-700">
                  {shown.map((n) => (
                    <tr key={n.id} className="hover:bg-ink-850">
                      <td className="max-w-[220px] px-4 py-1.5"><EntityLink id={n.id} /></td>
                      <td className="text-ink-300">{n.type === "host" ? n.category : n.type}</td>
                      <td className="tabular">{n.hop}</td>
                      <td><ClassPill c={n.classification} /></td>
                      <td><CritDots n={n.criticality} /></td>
                      <td className="mono text-ink-400">{n.earliest_arrival ? fmtTime(n.earliest_arrival) : "—"}</td>
                      <td className="tabular text-right">{n.impact.toFixed(0)}</td>
                      <td className="px-4">
                        <div className="flex flex-wrap gap-1">
                          {n.via.map((r) => (
                            <button key={r} onClick={() => open({ kind: "relationship", id: r })} className={`mono rounded px-1 text-[10px] hover:bg-ink-700 ${n.suspicious_relationships.includes(r) ? "text-high" : "text-ink-400"}`}>
                              {r.split("|")[1]}
                            </button>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
          <p className="text-[11px] text-ink-400">Reachability shows where an adversary <i>could</i> go from this entity using interactions that actually occurred. It is not proof that any reached entity was exploited. Only an analyst can mark a confirmed compromise (open an entity and use “Mark confirmed compromise”).</p>
        </>
      )}
    </div>
  );
}
