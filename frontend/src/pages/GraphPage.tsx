import { useEffect, useMemo, useState } from "react";
import { Expand, RotateCcw, Target } from "lucide-react";
import { EntityPicker } from "../components/EntityPicker";
import { GraphCanvas, GraphLegend, type CanvasEdge, type CanvasNode } from "../components/GraphCanvas";
import { useInspector } from "../components/Inspector";
import { Button, ErrorBox, Field, Loading, Segmented, inputCls } from "../components/ui";
import { api } from "../lib/api";
import { setParams, shortName, useDataVersion, type Route } from "../lib/hooks";
import type { GraphData } from "../lib/types";

const ENTITY_TYPES = ["user", "host", "process", "database", "service", "ip", "domain", "alert"];
const REL_TYPES = ["AUTHENTICATED_TO", "EXECUTED", "SPAWNED", "CONNECTED_TO", "COMMUNICATED_WITH", "ACCESSED", "QUERIED", "RESOLVED_TO", "MODIFIED", "PRIVILEGE_ESCALATED", "ALERTED_ON"];

const toUtcInput = (iso?: string | null) => (iso ? iso.slice(0, 16) : "");

export function GraphPage({ route }: { route: Route }) {
  const P = route.params;
  const { open } = useInspector();
  const { version } = useDataVersion();
  const [focus, setFocus] = useState(P.get("focus") || "");
  const [depth, setDepth] = useState(Number(P.get("depth") || 2));
  const [minSusp, setMinSusp] = useState(Number(P.get("min_suspicion") ?? (P.get("focus") ? 0 : 0.5)));
  const [types, setTypes] = useState<Set<string>>(new Set(ENTITY_TYPES.filter((t) => t !== "alert")));
  const [rels, setRels] = useState<Set<string>>(new Set(REL_TYPES.filter((r) => r !== "ALERTED_ON")));
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [labels, setLabels] = useState<"on" | "off">("on");
  const [dir, setDir] = useState<"LR" | "TB">("LR");
  const [base, setBase] = useState<GraphData | null>(null);
  const [extra, setExtra] = useState<GraphData>({ nodes: [], edges: [], truncated: false, limit: 0 });
  const [selected, setSelected] = useState<string>("");
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const query = useMemo(
    () => ({
      focus: focus || undefined,
      depth: focus ? depth : undefined,
      min_suspicion: minSusp,
      types: types.size === ENTITY_TYPES.length ? undefined : [...types].join(","),
      rels: [...rels].join(","),
      include_context: rels.has("ALERTED_ON"),
      since: since ? `${since}:00Z` : undefined,
      until: until ? `${until}:00Z` : undefined,
      limit: 350,
    }),
    [focus, depth, minSusp, types, rels, since, until],
  );

  useEffect(() => {
    setLoading(true);
    setErr(null);
    setExtra({ nodes: [], edges: [], truncated: false, limit: 0 });
    setParams("graph", { focus: focus || undefined, depth: focus ? depth : undefined, min_suspicion: minSusp });
    api.graph(query).then(setBase).catch((e) => setErr(e.message)).finally(() => setLoading(false));
  }, [query, focus, depth, minSusp, version]);

  const merged = useMemo(() => {
    const nodes = new Map<string, CanvasNode>();
    const edges = new Map<string, CanvasEdge>();
    [...(base?.nodes || []), ...extra.nodes].forEach((n) => nodes.set(n.id, n));
    [...(base?.edges || []), ...extra.edges].forEach((e) => nodes.has(e.source) && nodes.has(e.target) && edges.set(e.id, e));
    return { nodes: [...nodes.values()], edges: [...edges.values()] };
  }, [base, extra]);

  const expand = async () => {
    if (!selected) return;
    try {
      const g = await api.graph({ ...query, focus: selected, depth: 1, min_suspicion: 0 });
      setExtra((x) => ({ ...x, nodes: [...x.nodes, ...g.nodes], edges: [...x.edges, ...g.edges] }));
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const toggle = (set: Set<string>, v: string, fn: (s: Set<string>) => void) => {
    const n = new Set(set);
    if (n.has(v)) n.delete(v);
    else n.add(v);
    fn(n);
  };

  return (
    <div className="flex h-[calc(100vh-88px)] flex-col gap-3">
      <div className="grid gap-3 rounded-lg border border-ink-700 bg-ink-900 p-3 lg:grid-cols-[1.2fr_90px_1.3fr_1fr]">
        <Field label="Focus entity (blank = whole graph)">
          <EntityPicker value={focus} onChange={setFocus} allowEmpty emptyLabel="Whole graph (no focus)" />
        </Field>
        <Field label="Depth">
          <select className={inputCls} value={depth} disabled={!focus} onChange={(e) => setDepth(Number(e.target.value))}>
            {[1, 2, 3, 4].map((d) => <option key={d} value={d}>{d} hop{d > 1 ? "s" : ""}</option>)}
          </select>
        </Field>
        <Field label="Time window (UTC)">
          <div className="flex gap-1.5">
            <input aria-label="From (UTC)" type="datetime-local" className={inputCls} value={since} onChange={(e) => setSince(e.target.value)} max={toUtcInput(until) || undefined} />
            <input aria-label="To (UTC)" type="datetime-local" className={inputCls} value={until} onChange={(e) => setUntil(e.target.value)} />
          </div>
        </Field>
        <Field label={`Minimum suspicion: ${minSusp.toFixed(2)}${minSusp > 0 ? " (suspicious only)" : " (everything)"}`}>
          <input aria-label="Minimum suspicion" type="range" min={0} max={1} step={0.05} value={minSusp} onChange={(e) => setMinSusp(Number(e.target.value))} className="mt-2 w-full" />
        </Field>
        <div className="lg:col-span-4">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[11px] uppercase tracking-wider text-ink-400">Entities</span>
            {ENTITY_TYPES.map((t) => (
              <button key={t} onClick={() => toggle(types, t, setTypes)} className={`rounded-full border px-2 py-0.5 text-[11px] ${types.has(t) ? "border-ink-400 bg-ink-700 text-ink-100" : "border-ink-700 text-ink-400"}`}>{t}</button>
            ))}
            <span className="ml-3 mr-1 text-[11px] uppercase tracking-wider text-ink-400">Relationships</span>
            {REL_TYPES.map((t) => (
              <button key={t} onClick={() => toggle(rels, t, setRels)} className={`mono rounded-full border px-2 py-0.5 text-[10px] ${rels.has(t) ? "border-ink-400 bg-ink-700 text-ink-100" : "border-ink-700 text-ink-400"}`}>{t}</button>
            ))}
          </div>
        </div>
      </div>

      <div className="relative min-h-0 flex-1 overflow-hidden rounded-lg border border-ink-700 bg-ink-900">
        {loading && !base && <Loading label="Loading graph" />}
        {err && <div className="p-3"><ErrorBox msg={err} /></div>}
        {base && merged.nodes.length === 0 && <div className="p-6 text-sm text-ink-400">No relationships match these filters. Lower the minimum suspicion or widen the time window.</div>}
        {base && merged.nodes.length > 0 && (
          <GraphCanvas
            nodes={merged.nodes}
            edges={merged.edges}
            rootId={focus || undefined}
            highlightNodes={selected ? new Set([selected]) : undefined}
            direction={dir}
            showEdgeLabels={labels === "on"}
            onNodeSelect={(id) => { setSelected(id); open({ kind: "entity", id }); }}
          />
        )}
        <div className="absolute left-3 top-3 flex flex-wrap items-center gap-2">
          <Segmented value={dir} onChange={setDir} options={[{ value: "LR", label: "Left → right" }, { value: "TB", label: "Top → bottom" }]} />
          <Segmented value={labels} onChange={setLabels} options={[{ value: "on", label: "Edge labels" }, { value: "off", label: "No labels" }]} />
          <span className="rounded bg-ink-850/90 px-2 py-1 text-[11px] text-ink-300">
            {merged.nodes.length} nodes · {merged.edges.length} edges{base?.truncated ? ` · truncated to ${base.limit}` : ""}
          </span>
        </div>
        {selected && (
          <div className="absolute bottom-3 right-3 flex items-center gap-2 rounded-lg border border-ink-600 bg-ink-850/95 px-3 py-2 text-xs shadow-lg">
            <span className="text-ink-400">Selected</span>
            <span className="mono max-w-[220px] truncate">{shortName(selected)}</span>
            <Button onClick={expand} title="Add this entity's direct neighbours (all suspicion levels) to the view"><Expand size={13} /> Expand neighbours</Button>
            <Button onClick={() => { setFocus(selected); setMinSusp(0); }}><Target size={13} /> Focus here</Button>
            <Button variant="ghost" onClick={() => { setSelected(""); setExtra({ nodes: [], edges: [], truncated: false, limit: 0 }); }}><RotateCcw size={13} /> Reset</Button>
          </div>
        )}
      </div>
      <GraphLegend />
    </div>
  );
}
