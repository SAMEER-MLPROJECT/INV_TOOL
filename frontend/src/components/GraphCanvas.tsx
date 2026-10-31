import { memo, useEffect, useMemo } from "react";
import dagre from "@dagrejs/dagre";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { useInspector } from "./Inspector";
import { CritDots, TypeIcon } from "./ui";

export interface CanvasNode {
  id: string;
  type: string;
  name: string;
  category?: string;
  criticality: number;
  status?: string | null;
  badge?: string;
  badgeTone?: "crit" | "high" | "signal" | "muted";
}

export interface CanvasEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  count?: number;
  basis?: "observed" | "inferred";
  max_suspicion?: number;
  label?: string;
}

type NodeData = CanvasNode & { dim: boolean; hl: boolean; root: boolean } & Record<string, unknown>;

const NODE_W = 188;
const NODE_H = 46;

const TONE: Record<string, string> = {
  crit: "bg-crit/20 text-crit",
  high: "bg-high/20 text-high",
  signal: "bg-signal/15 text-signal",
  muted: "bg-ink-700 text-ink-300",
};

const EntityNode = memo(({ data, selected }: NodeProps<Node<NodeData>>) => {
  const border = data.status === "confirmed"
    ? "border-crit"
    : data.root
      ? "border-signal"
      : data.hl
        ? "border-high"
        : data.criticality >= 5
          ? "border-crit/60"
          : data.criticality >= 4
            ? "border-high/50"
            : "border-ink-600";
  const label = data.type === "process" ? data.name.split("/").slice(1).join("/") || data.name : data.name;
  return (
    <div
      className={`flex h-[46px] w-[188px] items-center gap-2 rounded-md border bg-ink-850 px-2 shadow-sm transition-opacity ${border} ${
        selected ? "ring-2 ring-signal" : ""
      } ${data.dim ? "opacity-30" : ""}`}
      title={data.id}
    >
      <Handle type="target" position={Position.Left} />
      <div className={`rounded p-1 ${data.hl || data.root ? "bg-ink-700 text-ink-100" : "bg-ink-800 text-ink-300"}`}>
        <TypeIcon type={data.type} category={data.category} size={15} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="truncate text-[12px] font-medium leading-tight text-ink-100">{label}</div>
        <div className="mt-0.5 flex items-center gap-1.5 text-[10px] leading-tight text-ink-400">
          <span className="truncate">{data.type === "host" ? data.category || "host" : data.type}</span>
          {data.criticality > 1 && <CritDots n={data.criticality} />}
        </div>
      </div>
      {data.badge && <span className={`rounded px-1 py-0.5 text-[9px] font-semibold uppercase ${TONE[data.badgeTone || "muted"]}`}>{data.badge}</span>}
      <Handle type="source" position={Position.Right} />
    </div>
  );
});

const nodeTypes = { entity: EntityNode };

function layout(nodes: CanvasNode[], edges: CanvasEdge[], direction: "LR" | "TB") {
  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setGraph({ rankdir: direction, nodesep: 16, ranksep: 56, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((n) => g.setNode(n.id, { width: NODE_W, height: NODE_H }));
  edges.forEach((e) => {
    if (g.hasNode(e.source) && g.hasNode(e.target)) g.setEdge(e.source, e.target, {}, e.id);
  });
  dagre.layout(g);
  const pos: Record<string, { x: number; y: number }> = {};
  nodes.forEach((n) => {
    const p = g.node(n.id);
    pos[n.id] = { x: (p?.x ?? 0) - NODE_W / 2, y: (p?.y ?? 0) - NODE_H / 2 };
  });
  return pos;
}

function Inner({ nodes, edges, highlightNodes, highlightEdges, rootId, direction, showEdgeLabels, onNodeSelect, onEdgeSelect, suspicionThreshold }: Props) {
  const { open } = useInspector();
  const rf = useReactFlow();
  const pos = useMemo(() => layout(nodes, edges, direction), [nodes, edges, direction]);
  const hasHl = !!highlightNodes && highlightNodes.size > 0;
  const rfNodes: Node<NodeData>[] = useMemo(
    () =>
      nodes.map((n) => ({
        id: n.id,
        type: "entity",
        position: pos[n.id],
        data: { ...n, dim: hasHl && !highlightNodes!.has(n.id), hl: !!highlightNodes?.has(n.id), root: n.id === rootId },
        sourcePosition: direction === "LR" ? Position.Right : Position.Bottom,
        targetPosition: direction === "LR" ? Position.Left : Position.Top,
      })),
    [nodes, pos, hasHl, highlightNodes, rootId, direction],
  );
  const rfEdges: Edge[] = useMemo(
    () =>
      edges.map((e) => {
        const susp = (e.max_suspicion ?? 0) >= suspicionThreshold;
        const hl = highlightEdges?.has(e.id);
        const dim = !!highlightEdges && highlightEdges.size > 0 && !hl;
        const color = hl ? "#f08c3a" : susp ? "#c4753a" : "#4a5361";
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: showEdgeLabels ? e.label ?? `${e.type}${e.count && e.count > 1 ? ` ×${e.count}` : ""}` : undefined,
          style: {
            stroke: color,
            strokeWidth: hl ? 2.4 : Math.min(1 + Math.log10(e.count || 1), 2.2),
            strokeDasharray: e.basis === "inferred" ? "5 4" : undefined,
            opacity: dim ? 0.18 : 1,
          },
          markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
          animated: !!hl,
          zIndex: hl ? 10 : 0,
        } satisfies Edge;
      }),
    [edges, highlightEdges, showEdgeLabels, suspicionThreshold],
  );
  useEffect(() => {
    const t = setTimeout(() => rf.fitView({ padding: 0.15, duration: 250 }), 30);
    return () => clearTimeout(t);
  }, [rf, pos]);
  return (
    <ReactFlow
      nodes={rfNodes}
      edges={rfEdges}
      nodeTypes={nodeTypes}
      minZoom={0.1}
      maxZoom={2}
      nodesConnectable={false}
      proOptions={{ hideAttribution: true }}
      onNodeClick={(_, n) => (onNodeSelect ? onNodeSelect(n.id) : open({ kind: "entity", id: n.id }))}
      onEdgeClick={(_, e) => (onEdgeSelect ? onEdgeSelect(e.id) : open({ kind: "relationship", id: e.id }))}
    >
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#252b35" />
      <Controls showInteractive={false} position="bottom-left" />
      {nodes.length > 40 && (
        <MiniMap pannable zoomable nodeColor={(n) => ((n.data as unknown as NodeData).hl ? "#f08c3a" : "#4a5361")} maskColor="rgba(12,14,18,0.7)" />
      )}
    </ReactFlow>
  );
}

interface Props {
  nodes: CanvasNode[];
  edges: CanvasEdge[];
  highlightNodes?: Set<string>;
  highlightEdges?: Set<string>;
  rootId?: string;
  direction: "LR" | "TB";
  showEdgeLabels: boolean;
  onNodeSelect?: (id: string) => void;
  onEdgeSelect?: (id: string) => void;
  suspicionThreshold: number;
}

export function GraphCanvas(p: Partial<Props> & Pick<Props, "nodes" | "edges">) {
  return (
    <ReactFlowProvider>
      <Inner direction="LR" showEdgeLabels suspicionThreshold={0.5} {...p} />
    </ReactFlowProvider>
  );
}

export function GraphLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-ink-400">
      <span className="flex items-center gap-1.5"><span className="inline-block h-0.5 w-6 bg-ink-500" /> observed</span>
      <span className="flex items-center gap-1.5"><span className="inline-block w-6 border-t-2 border-dashed border-ink-500" /> inferred (IP→host)</span>
      <span className="flex items-center gap-1.5"><span className="inline-block h-0.5 w-6 bg-[#c4753a]" /> suspicious evidence</span>
      <span className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded-sm border border-crit/60" /> criticality 5</span>
      <span className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded-sm border border-high/50" /> criticality 4</span>
      <span>Click any node or edge for its evidence.</span>
    </div>
  );
}
