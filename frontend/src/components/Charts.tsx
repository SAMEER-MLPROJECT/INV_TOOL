import { fmtTime } from "../lib/hooks";

export function ActivityTimeline({ data }: { data: { hour: string; events: number; suspicious: number }[] }) {
  if (!data.length) return null;
  const start = new Date(data[0].hour).getTime();
  const end = new Date(data[data.length - 1].hour).getTime();
  const hours = Math.round((end - start) / 3_600_000) + 1;
  const byHour = new Map(data.map((d) => [Math.round((new Date(d.hour).getTime() - start) / 3_600_000), d]));
  const max = Math.max(...data.map((d) => d.events), 1);
  const W = 1000, H = 160, PB = 20, PL = 28, PT = 10;
  const bw = (W - PL) / hours;
  const ticks = [];
  for (let h = 0; h < hours; h++) {
    const t = new Date(start + h * 3_600_000);
    if (t.getUTCHours() % 12 === 0) ticks.push({ h, label: `${t.getUTCMonth() + 1}/${t.getUTCDate()} ${String(t.getUTCHours()).padStart(2, "0")}:00` });
  }
  return (
    <figure>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-[160px] w-full" role="img" aria-label="Events per hour">
        {[0.5, 1].map((f) => (
          <g key={f}>
            <line x1={PL} x2={W} y1={(PT + (H - PB - PT) * (1 - f))} y2={(PT + (H - PB - PT) * (1 - f))} stroke="#252b35" />
            <text x={PL - 4} y={(PT + (H - PB - PT) * (1 - f)) + 3} textAnchor="end" fontSize="9" fill="#6c7685">{Math.round(max * f)}</text>
          </g>
        ))}
        {Array.from({ length: hours }, (_, h) => {
          const d = byHour.get(h);
          if (!d) return null;
          const hAll = ((H - PB - PT) * d.events) / max;
          const hS = ((H - PB - PT) * d.suspicious) / max;
          return (
            <g key={h}>
              <title>{`${fmtTime(d.hour)}: ${d.events} events, ${d.suspicious} suspicious`}</title>
              <rect x={PL + h * bw + 0.5} y={H - PB - hAll} width={Math.max(bw - 1.5, 1)} height={hAll} fill="#323a46" rx={1} />
              {d.suspicious > 0 && <rect x={PL + h * bw + 0.5} y={H - PB - Math.max(hS, 3)} width={Math.max(bw - 1.5, 1)} height={Math.max(hS, 3)} fill="#f08c3a" rx={1} />}
            </g>
          );
        })}
        {ticks.map((t) => (
          <text key={t.h} x={PL + t.h * bw} y={H - 5} fontSize="9" fill="#6c7685">{t.label}</text>
        ))}
      </svg>
      <figcaption className="mt-1 flex gap-4 text-[11px] text-ink-400">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-ink-600" /> events per hour (UTC)</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-high" /> alerts and high-severity records</span>
      </figcaption>
    </figure>
  );
}

export function GrowthChart({ data, current, onPick }: { data: { hops: number; reachable: number }[]; current: number; onPick: (h: number) => void }) {
  const max = Math.max(...data.map((d) => d.reachable), 1);
  const W = 320, H = 120, PB = 18, PL = 26;
  const bw = (W - PL) / data.length;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Reachable entities by hop limit">
      {data.map((d, i) => {
        const h = ((H - PB - 12) * d.reachable) / max;
        const on = d.hops <= current;
        return (
          <g key={d.hops} className="cursor-pointer" onClick={() => onPick(d.hops)}>
            <title>{`≤ ${d.hops} hops: ${d.reachable} reachable`}</title>
            <rect x={PL + i * bw + 3} y={0} width={bw - 6} height={H - PB} fill="transparent" />
            <rect x={PL + i * bw + 3} y={H - PB - h} width={bw - 6} height={h} rx={2} fill={on ? "#7cc4ff" : "#323a46"} opacity={d.hops === current ? 1 : on ? 0.55 : 1} />
            <text x={PL + i * bw + bw / 2} y={H - PB - h - 3} textAnchor="middle" fontSize="9" fill="#949dab">{d.reachable}</text>
            <text x={PL + i * bw + bw / 2} y={H - 5} textAnchor="middle" fontSize="9" fill={d.hops === current ? "#e2e6eb" : "#6c7685"}>{d.hops}</text>
          </g>
        );
      })}
      <text x={2} y={H - 5} fontSize="9" fill="#6c7685">hops</text>
    </svg>
  );
}
