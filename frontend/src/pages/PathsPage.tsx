import { useEffect, useMemo, useState } from "react";
import { Ban, CheckCircle2, GitBranch, Search, XCircle } from "lucide-react";
import { EntityPicker } from "../components/EntityPicker";
import { GraphCanvas, GraphLegend, type CanvasEdge, type CanvasNode } from "../components/GraphCanvas";
import { EntityLink, EventLink, useInspector } from "../components/Inspector";
import { PathChannelMatrix } from "../components/ChannelMatrix";
import { PathChain } from "../components/PathChain";
import { BasisTag, Button, Empty, ErrorBox, Field, Loading, Panel, PriorityPill, ScoreBreakdown, inputCls } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime, setParams, useAsync, type Route } from "../lib/hooks";
import type { EntitySummary, PathResult } from "../lib/types";

const REL_TYPES = ["AUTHENTICATED_TO", "EXECUTED", "SPAWNED", "CONNECTED_TO", "COMMUNICATED_WITH", "ACCESSED", "QUERIED", "RESOLVED_TO", "MODIFIED", "PRIVILEGE_ESCALATED"];

export function toCanvasNodes(ids: Iterable<string>, ents: Map<string, EntitySummary>): CanvasNode[] {
  return [...new Set(ids)].map((id) => {
    const e = ents.get(id);
    return { id, type: e?.type || id.split(":")[0], name: e?.name || id.split(":").slice(1).join(":"), category: e?.category, criticality: e?.criticality || 1, status: e?.status };
  });
}

export function PathsPage({ route }: { route: Route }) {
  const P = route.params;
  const { open } = useInspector();
  const { data: entList } = useAsync(() => api.entities(), []);
  const ents = useMemo(() => new Map((entList || []).map((e) => [e.id, e])), [entList]);
  const [source, setSource] = useState(P.get("source") || "");
  const [target, setTarget] = useState(P.get("target") || "");
  const [hops, setHops] = useState(Number(P.get("hops") || 5));
  const [since, setSince] = useState("");
  const [rels, setRels] = useState<Set<string>>(new Set(REL_TYPES));
  const [res, setRes] = useState<PathResult | null>(null);
  const [sel, setSel] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (src = source, tgt = target) => {
    if (!src) return;
    setBusy(true);
    setErr(null);
    setParams("paths", { source: src, target: tgt || undefined, hops });
    try {
      const r = await api.paths({
        source: src, targets: tgt ? [tgt] : null, max_hops: hops, max_paths: 15,
        rel_types: rels.size === REL_TYPES.length ? null : [...rels], since: since ? `${since}:00Z` : null,
      });
      setRes(r);
      setSel(0);
    } catch (e) {
      setErr((e as Error).message);
      setRes(null);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (P.get("source")) run(P.get("source")!, P.get("target") || "");
  }, []);

  const path = res?.paths[sel];
  const canvas = useMemo(() => {
    if (!res) return null;
    const ids: string[] = [];
    const edges = new Map<string, CanvasEdge>();
    res.paths.forEach((p) => {
      ids.push(...p.nodes);
      p.steps.forEach((s) => edges.set(s.relationship_id, { id: s.relationship_id, source: s.from, target: s.to, type: s.relationship, basis: s.basis, max_suspicion: s.suspicion }));
    });
    return { nodes: toCanvasNodes(ids, ents), edges: [...edges.values()] };
  }, [res, ents]);

  return (
    <div className="space-y-4">
      <Panel>
        <form className="grid items-end gap-3 lg:grid-cols-[1.3fr_1.3fr_100px_1fr_auto]" onSubmit={(e) => { e.preventDefault(); run(); }}>
          <Field label="Suspected compromised entity (start)"><EntityPicker id="path-source" value={source} onChange={setSource} placeholder="e.g. user:sameer" /></Field>
          <Field label="Target"><EntityPicker id="path-target" value={target} onChange={setTarget} allowEmpty emptyLabel="Auto: every critical asset (criticality ≥ 4)" placeholder="Auto: critical assets" /></Field>
          <Field label="Max hops">
            <select className={inputCls} value={hops} onChange={(e) => setHops(Number(e.target.value))}>
              {[1, 2, 3, 4, 5, 6, 7, 8].map((h) => <option key={h}>{h}</option>)}
            </select>
          </Field>
          <Field label="Not before (UTC, optional)"><input type="datetime-local" className={inputCls} value={since} onChange={(e) => setSince(e.target.value)} /></Field>
          <Button type="submit" variant="primary" disabled={!source || busy}><Search size={14} /> {busy ? "Searching…" : "Find paths"}</Button>
          <div className="flex flex-wrap items-center gap-1.5 lg:col-span-5">
            <span className="mr-1 text-[11px] uppercase tracking-wider text-ink-400">Allowed relationships</span>
            {REL_TYPES.map((t) => (
              <button type="button" key={t} onClick={() => { const n = new Set(rels); if (n.has(t)) n.delete(t); else n.add(t); setRels(n); }}
                className={`mono rounded-full border px-2 py-0.5 text-[10px] ${rels.has(t) ? "border-ink-400 bg-ink-700 text-ink-100" : "border-ink-700 text-ink-400"}`}>{t}</button>
            ))}
          </div>
        </form>
      </Panel>

      {err && <ErrorBox msg={err} />}
      {busy && !res && <Loading label="Searching temporal paths" />}
      {!res && !busy && !err && <Empty>Choose a starting entity (for example <span className="mono">user:sameer</span>) and run the search.</Empty>}

      {res && (
        <>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-400">
            <span><b className="text-ink-200">{res.total_valid_paths}</b> temporally consistent path(s) to {res.targets.length} target(s)</span>
            <span><b className="text-ink-200">{res.rejected_temporally_impossible.length}</b> structural path(s) rejected as temporally impossible</span>
            <span>engine: {res.search.engine} · {res.search.expansions.toLocaleString()} expansions{res.search.truncated ? " · search budget reached (results partial)" : ""}</span>
            <span>window: clock skew {res.window.clock_skew_seconds}s · max gap between steps {res.window.max_hop_gap_hours || "∞"} h</span>
          </div>

          {res.paths.length === 0 ? (
            <Empty>No temporally consistent path from this entity reaches the selected target(s) within {res.max_hops} hops.</Empty>
          ) : (
            <div className="grid gap-4 xl:grid-cols-[400px_1fr]">
              <Panel title={<span className="flex items-center gap-2"><GitBranch size={14} /> Ranked hypotheses</span>} bodyClass="p-0">
                <ol className="max-h-[640px] divide-y divide-ink-700 overflow-y-auto">
                  {res.paths.map((p, i) => (
                    <li key={i}>
                      <button onClick={() => setSel(i)} className={`w-full px-3 py-2.5 text-left ${i === sel ? "bg-ink-800" : "hover:bg-ink-850"}`}>
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[11px] text-ink-400">#{i + 1} · {p.hops} hops · {p.suspicious_hops} suspicious</span>
                          <PriorityPill priority={p.priority} score={p.score} />
                        </div>
                        <div className="mt-1 text-[12px] leading-snug text-ink-200">
                          {p.nodes.map((n) => n.split(":").slice(1).join(":").split("/").pop()).join(" → ")}
                        </div>
                        <div className="mono mt-0.5 text-[10px] text-ink-400">{fmtTime(p.start)} → {fmtTime(p.end, false)} · {p.sources.length} sources</div>
                      </button>
                    </li>
                  ))}
                </ol>
              </Panel>
              <div className="min-w-0 space-y-4">
                {canvas && (
                  <div className="h-[340px] overflow-hidden rounded-lg border border-ink-700 bg-ink-900">
                    <GraphCanvas
                      nodes={canvas.nodes}
                      edges={canvas.edges}
                      rootId={res.source}
                      highlightNodes={new Set(path?.nodes)}
                      highlightEdges={new Set(path?.steps.map((s) => s.relationship_id))}
                      showEdgeLabels
                      onEdgeSelect={(id) => open({ kind: "relationship", id })}
                    />
                  </div>
                )}
                <GraphLegend />
                {path && (
                  <>
                    <Panel title={`Hypothesis #${sel + 1}: chronological evidence`} actions={<PriorityPill priority={path.priority} score={path.score} />}>
                      <PathChain nodes={path.nodes} rels={path.steps.map((s) => s.relationship)} />
                      <div className="mt-3 overflow-x-auto">
                        <table className="w-full text-[12px]">
                          <thead className="text-left text-[10px] uppercase tracking-wider text-ink-400">
                            <tr><th className="py-1 pr-2">#</th><th className="pr-2">Time (UTC)</th><th className="pr-2">Step</th><th className="pr-2">Supporting record</th><th className="pr-2">Basis</th><th className="pr-2 text-right">Suspicion</th></tr>
                          </thead>
                          <tbody className="divide-y divide-ink-700">
                            {path.steps.map((s, i) => (
                              <tr key={i} className="align-top">
                                <td className="py-1.5 pr-2 text-ink-400">{i + 1}</td>
                                <td className="mono whitespace-nowrap pr-2 text-ink-300">{fmtTime(s.timestamp)}</td>
                                <td className="pr-2">
                                  <div className="flex flex-wrap items-center gap-1"><EntityLink id={s.from} /><button className="mono text-[10px] text-signal hover:underline" onClick={() => open({ kind: "relationship", id: s.relationship_id })}>—{s.relationship}→</button><EntityLink id={s.to} /></div>
                                </td>
                                <td className="pr-2">
                                  <div className="text-ink-200">{s.description}</div>
                                  <div className="text-[10px] text-ink-400"><EventLink uid={s.event_uid} /> · {s.source_file}#{s.source_row} · {s.rule}{s.alert ? ` · alert ${s.alert}` : ""}{s.total_occurrences > 1 ? ` · 1 of ${s.total_occurrences} occurrences` : ""}</div>
                                </td>
                                <td className="pr-2"><BasisTag basis={s.basis} /></td>
                                <td className={`tabular pr-2 text-right ${s.suspicion >= 0.5 ? "text-high" : "text-ink-400"}`}>{s.suspicion.toFixed(2)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </Panel>
                    {path.channels && (
                      <Panel title="Multichannel corroboration (which observation channels saw each step)">
                        <PathChannelMatrix data={path.channels} />
                      </Panel>
                    )}
                    <div className="grid gap-4 lg:grid-cols-2">
                      <Panel title="Why this path is ranked here">
                        <ul className="list-disc space-y-1 pl-4 text-[13px] text-ink-200">{path.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
                      </Panel>
                      <Panel title="Score breakdown"><ScoreBreakdown breakdown={path.breakdown} disclaimer={path.disclaimer} /></Panel>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title={<span className="flex items-center gap-2"><Ban size={14} className="text-mod" /> Rejected: temporally impossible</span>}>
              {res.rejected_temporally_impossible.length === 0 ? (
                <p className="text-sm text-ink-400">No structural path to a target was rejected for time ordering.</p>
              ) : (
                <ul className="space-y-3">
                  {res.rejected_temporally_impossible.map((r, i) => (
                    <li key={i} className="rounded border border-ink-700 bg-ink-850 p-2.5">
                      <PathChain nodes={r.nodes} />
                      <p className="mt-1.5 text-[12px] text-mod">{r.reason}</p>
                    </li>
                  ))}
                </ul>
              )}
              <p className="mt-3 text-[11px] text-ink-400">These routes exist in the graph, but the evidence shows the later step happened before the earlier one could have enabled it, so they are not reported as attack sequences.</p>
            </Panel>
            <Panel title="Connectivity-only shortest path (time ignored)">
              {!res.structural_shortest_path ? (
                <p className="text-sm text-ink-400">Shown when a single target is selected.</p>
              ) : (
                <div className="space-y-2">
                  <PathChain nodes={res.structural_shortest_path.nodes} />
                  <p className="flex items-center gap-1.5 text-[13px]">
                    {res.structural_shortest_path.temporally_consistent ? (
                      <><CheckCircle2 size={14} className="text-ok" /> Also temporally consistent ({res.structural_shortest_path.hops} hops).</>
                    ) : (
                      <><XCircle size={14} className="text-mod" /> Not a valid sequence: {res.structural_shortest_path.reason}</>
                    )}
                  </p>
                  <p className="text-[11px] text-ink-400">A plain shortest-path query would return this route. Compare it with the ranked hypotheses: the shortest connection is often ordinary business activity, not the attack.</p>
                </div>
              )}
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
