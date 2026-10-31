import { useInspector } from "./Inspector";
import { shortName } from "../lib/hooks";
import type { IncidentChannels, PathChannels } from "../lib/types";

const STEP_STYLE: Record<string, { cls: string; label: string; glyph: string }> = {
  primary: { cls: "bg-signal/25 text-signal ring-1 ring-signal/50", label: "primary record", glyph: "●" },
  corroborating: { cls: "bg-ok/20 text-ok ring-1 ring-ok/40", label: "corroborating record(s) within ±15 min", glyph: "◆" },
  silent: { cls: "bg-mod/15 text-mod ring-1 ring-dashed ring-mod/50", label: "expected and covered, but silent", glyph: "?" },
  blind: { cls: "bg-ink-800 text-ink-500 ring-1 ring-ink-600", label: "expected, but this channel has no coverage (blind spot)", glyph: "⊘" },
  none: { cls: "text-ink-600", label: "not expected for this step, nothing recorded", glyph: "·" },
};

export function ChannelLegend() {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-400">
      {Object.entries(STEP_STYLE).map(([k, v]) => (
        <span key={k} className="flex items-center gap-1.5">
          <span className={`inline-flex h-4 w-4 items-center justify-center rounded text-[9px] ${v.cls}`}>{v.glyph}</span> {v.label}
        </span>
      ))}
    </div>
  );
}

export function AgreementGauge({ value, label }: { value: number; label: string }) {
  const pct = Math.round(value * 100);
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 w-28 rounded-full bg-ink-800">
        <div className={`h-2 rounded-full ${pct >= 75 ? "bg-ok" : pct >= 50 ? "bg-mod" : "bg-high"}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="tabular text-[12px] text-ink-200">{pct}%</span>
      <span className="text-[11px] text-ink-400">{label}</span>
    </div>
  );
}

export function PathChannelMatrix({ data }: { data: PathChannels }) {
  const { open } = useInspector();
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <AgreementGauge value={data.agreement} label="channel agreement" />
        <span className="text-[12px] text-ink-300">{data.summary}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[12px]">
          <thead className="text-left text-[10px] uppercase tracking-wider text-ink-400">
            <tr>
              <th className="py-1 pr-2">Step</th>
              {data.channels.map((c) => <th key={c} className="px-1 text-center">{data.labels[c]}</th>)}
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-700">
            {data.steps.map((s) => (
              <tr key={s.step}>
                <td className="py-1.5 pr-2">
                  <span className="text-ink-500">{s.step}.</span>{" "}
                  <span className="text-ink-200">{shortName(s.from)}</span>{" "}
                  <span className="mono text-[10px] text-signal">{s.relationship}</span>{" "}
                  <span className="text-ink-200">{shortName(s.to)}</span>
                </td>
                {data.channels.map((c) => {
                  const cell = s.cells[c];
                  const st = STEP_STYLE[cell.state];
                  const first = cell.records[0];
                  return (
                    <td key={c} className="px-1 text-center">
                      <button
                        disabled={!first}
                        onClick={() => first && open({ kind: "event", id: first })}
                        title={`${data.labels[c]}: ${st.label}${cell.count ? ` (${cell.count})` : ""}`}
                        className={`inline-flex h-6 min-w-6 items-center justify-center rounded px-1 text-[10px] font-semibold ${st.cls} ${first ? "cursor-pointer hover:brightness-125" : "cursor-default"}`}
                      >
                        {cell.state === "corroborating" ? cell.count : st.glyph}
                      </button>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ChannelLegend />
      {data.silent_gaps.length > 0 && (
        <ul className="list-disc space-y-0.5 pl-5 text-[12px] text-mod">{data.silent_gaps.map((g) => <li key={g}>{g}</li>)}</ul>
      )}
      <p className="text-[11px] text-ink-400">
        Corroboration means an independent channel recorded activity on the same entities within ±15 minutes. It strengthens a
        hypothesis; it is not proof that the same action was seen twice. Silent channels may indicate a logging gap, tampering, or
        simply benign absence.
      </p>
    </div>
  );
}

export function IncidentChannelMatrix({ data }: { data: IncidentChannels }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <AgreementGauge value={data.agreement} label="of covering channels produced evidence" />
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[12px]">
          <thead className="text-left text-[10px] uppercase tracking-wider text-ink-400">
            <tr><th className="py-1 pr-2">Entity</th>{data.channels.map((c) => <th key={c} className="px-1 text-center">{data.labels[c]}</th>)}</tr>
          </thead>
          <tbody className="divide-y divide-ink-700">
            {data.rows.map((r) => (
              <tr key={r.entity}>
                <td className="max-w-[220px] truncate py-1.5 pr-2 text-ink-200" title={r.entity}>{shortName(r.entity)}</td>
                {data.channels.map((c) => {
                  const cell = r.cells[c];
                  const cls = cell.state === "evidence"
                    ? (cell.count >= 5 ? "bg-signal/35 text-ink-100" : "bg-signal/15 text-signal")
                    : cell.state === "silent" ? "text-mod" : "text-ink-600";
                  return (
                    <td key={c} className="px-1 text-center">
                      <span title={`${data.labels[c]}: ${cell.state === "evidence" ? `${cell.count} record(s)` : cell.state === "silent" ? "covers this entity but silent in window" : "no coverage"}`}
                        className={`tabular inline-flex h-6 min-w-8 items-center justify-center rounded px-1 text-[11px] ${cls}`}>
                        {cell.state === "evidence" ? cell.count : cell.state === "silent" ? "?" : "⊘"}
                      </span>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {(data.silent_observations.length > 0 || data.single_channel_entities.length > 0) && (
        <ul className="list-disc space-y-0.5 pl-5 text-[12px] text-mod">
          {[...data.silent_observations, ...data.single_channel_entities].map((g) => <li key={g}>{g}</li>)}
        </ul>
      )}
      <p className="text-[11px] text-ink-400">Numbers are records per channel touching the entity in the incident window. “?” = the channel normally observes this entity but recorded nothing; “⊘” = never observes it.</p>
    </div>
  );
}
