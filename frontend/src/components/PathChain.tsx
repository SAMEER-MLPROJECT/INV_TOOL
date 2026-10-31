import { ArrowRight } from "lucide-react";
import { EntityLink } from "./Inspector";

/** Inline chain of entity chips: a -> b -> c, each opening its evidence. */
export function PathChain({ nodes, rels }: { nodes: string[]; rels?: string[] }) {
  return (
    <div className="flex flex-wrap items-center gap-1">
      {nodes.map((n, i) => (
        <span key={`${n}-${i}`} className="flex items-center gap-1">
          {i > 0 && (
            <span className="flex items-center gap-0.5 text-ink-500">
              {rels && rels[i - 1] && <span className="mono text-[9px] text-ink-400">{rels[i - 1]}</span>}
              <ArrowRight size={12} />
            </span>
          )}
          <span className="rounded border border-ink-600 bg-ink-850 py-0.5 text-[12px]">
            <EntityLink id={n} />
          </span>
        </span>
      ))}
    </div>
  );
}
