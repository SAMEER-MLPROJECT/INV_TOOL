import { useEffect, useState } from "react";
import { Bell, Play, Radio, Square } from "lucide-react";
import { EntityPicker } from "../components/EntityPicker";
import { EntityLink, EventLink } from "../components/Inspector";
import { Button, CLASS_META, ClassPill, CritDots, ErrorBox, Field, Panel, PriorityPill, Stat, inputCls } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime, go, useAsync, useDataVersion } from "../lib/hooks";
import type { BlastClass, LiveStatus } from "../lib/types";

const PRESETS = [
  { label: "Attack window 20:25 to 22:15 UTC at 60×", start: "2026-10-27T20:25:00Z", end: "2026-10-27T22:15:00Z", speed: 60 },
  { label: "Attack window at 240× (fast)", start: "2026-10-27T20:25:00Z", end: "2026-10-27T22:15:00Z", speed: 240 },
  { label: "Whole dataset at 3600× (≈ 1 min)", start: "", end: "", speed: 3600 },
];
const TIERS: BlastClass[] = ["CONFIRMED_COMPROMISE", "SUSPECTED_LATERAL_MOVEMENT", "OBSERVED_CONNECTION", "POTENTIAL_EXPOSURE"];

export function LivePage() {
  const { version } = useDataVersion();
  const [status, setStatus] = useState<LiveStatus | null>(null);
  const [preset, setPreset] = useState(0);
  const [speed, setSpeed] = useState(PRESETS[0].speed);
  const [watch, setWatch] = useState("user:sameer");
  const [err, setErr] = useState<string | null>(null);
  const blast = useAsync(() => api.blast(watch, 4, true, false), [watch]);

  useEffect(() => {
    let alive = true;
    const tick = () => api.liveStatus().then((s) => alive && setStatus(s)).catch(() => {});
    tick();
    const id = setInterval(tick, 700);
    return () => { alive = false; clearInterval(id); };
  }, [version]);

  const start = async () => {
    setErr(null);
    const p = PRESETS[preset];
    try {
      await api.startReplay(p.start || null, p.end || null, speed);
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const r = status?.replay;
  const u = status?.last_update && "events" in status.last_update ? status.last_update : null;
  const pct = r && r.total ? Math.round((100 * r.sent) / r.total) : 0;
  const counts = blast.data?.summary.by_classification || {};

  return (
    <div className="space-y-4">
      <Panel title={<span className="flex items-center gap-2"><Radio size={14} className={r?.running ? "animate-pulse text-crit" : "text-signal"} /> Live stream &amp; attack replay</span>}>
        <div className="grid items-end gap-3 lg:grid-cols-[1.6fr_140px_auto_1fr]">
          <Field label="Replay the synthetic incident as a live feed">
            <select className={inputCls} value={preset} onChange={(e) => { const i = Number(e.target.value); setPreset(i); setSpeed(PRESETS[i].speed); }}>
              {PRESETS.map((p, i) => <option key={p.label} value={i}>{p.label}</option>)}
            </select>
          </Field>
          <Field label="Speed (× real time)">
            <input type="number" min={1} max={100000} className={inputCls} value={speed} onChange={(e) => setSpeed(Number(e.target.value))} />
          </Field>
          <div className="flex gap-2">
            <Button variant="primary" disabled={r?.running} onClick={start}><Play size={14} /> Start replay</Button>
            <Button variant="danger" disabled={!r?.running} onClick={() => api.stopReplay()}><Square size={14} /> Stop</Button>
          </div>
          <div className="text-[12px] text-ink-300">
            {r?.running ? (
              <>Streaming… data clock <b className="mono text-ink-100">{fmtTime(r.data_time)}</b></>
            ) : r?.finished ? <>Replay finished at <span className="mono">{fmtTime(r.data_time)}</span>.</> : r?.stopped ? "Replay stopped." : "Idle. Events can also be pushed by any source (see below)."}
          </div>
        </div>
        {r && r.total > 0 && (
          <div className="mt-3">
            <div className="h-1.5 rounded-full bg-ink-800"><div className="h-1.5 rounded-full bg-signal transition-all" style={{ width: `${pct}%` }} /></div>
            <div className="mt-1 text-[11px] text-ink-400">
              {r.preloaded.toLocaleString()} earlier events preloaded · {r.sent} / {r.total} window events streamed · speed {r.speed}× ·
              graph rebuilt in {status?.last_rebuild_ms} ms per micro-batch
            </div>
          </div>
        )}
        {err && <div className="mt-3"><ErrorBox msg={err} /></div>}
        <p className="mt-3 text-[11px] text-ink-400">
          The replay re-sends the sample records through the same push API, normaliser and graph engine an external log shipper would use.
          Every open screen (overview, graph, blast radius, incidents) refreshes itself as the graph changes. Use Settings &amp; Data → Reset to
          restore the full dataset afterwards.
        </p>
      </Panel>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Events in graph" value={(u?.events ?? 0).toLocaleString()} sub={`${(u?.streamed ?? 0).toLocaleString()} via stream`} />
        <Stat label="Entities" value={(u?.entities ?? 0).toLocaleString()} />
        <Stat label="Relationships" value={(u?.relationships ?? 0).toLocaleString()} />
        <Stat label="Incidents" value={u?.incidents ?? 0} onClick={() => go("incidents")} />
        <Stat label="Data clock" value={<span className="mono text-[15px]">{fmtTime(u?.data_time, false)}</span>} sub={u?.data_time ? fmtTime(u.data_time).slice(0, 10) : ""} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        <Panel title="Live blast radius (time-respecting, 4 hops)" actions={<Button variant="ghost" onClick={() => go("blast", { entity: watch, hops: 4 })}>Open full view</Button>}>
          <div className="mb-3 max-w-md"><EntityPicker value={watch} onChange={(v) => v && setWatch(v)} /></div>
          {u?.top_incident && (
            <div className="mb-3 flex items-center gap-2 text-[13px]">
              <span className="text-ink-400">Top incident</span> <PriorityPill priority={u.top_incident.priority} score={u.top_incident.score} />
              <button className="truncate text-ink-100 hover:underline" onClick={() => go("incidents", { id: u.top_incident!.id })}>{u.top_incident.id} · {u.top_incident.title}</button>
            </div>
          )}
          {blast.error ? <p className="text-sm text-ink-400">Waiting for {watch} to appear in the stream…</p> : (
            <>
              <div className="mb-3 grid grid-cols-4 gap-2">
                {TIERS.map((t) => (
                  <div key={t} className="rounded border border-ink-700 bg-ink-850 px-3 py-2">
                    <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-ink-400"><span className={`h-1.5 w-1.5 rounded-full ${CLASS_META[t].dot}`} />{CLASS_META[t].short}</div>
                    <div className="tabular text-xl font-semibold">{counts[t] ?? 0}</div>
                  </div>
                ))}
              </div>
              <ul className="divide-y divide-ink-700 rounded border border-ink-700">
                {(blast.data?.summary.critical_assets || []).map((a) => (
                  <li key={a.id} className="flex items-center gap-2 px-3 py-1.5 text-[13px]">
                    <EntityLink id={a.id} className="flex-1" /><span className="text-[11px] text-ink-400">hop {a.hop}</span><CritDots n={a.criticality} /><ClassPill c={a.classification} />
                  </li>
                ))}
                {!blast.data?.summary.critical_assets.length && <li className="px-3 py-2 text-[12px] text-ink-400">No critical asset reachable yet.</li>}
              </ul>
            </>
          )}
        </Panel>
        <Panel title={<span className="flex items-center gap-2"><Bell size={14} /> Live alert feed</span>} bodyClass="p-0">
          <ul className="max-h-[420px] divide-y divide-ink-700 overflow-y-auto">
            {(status?.feed || []).map((f) => (
              <li key={f.uid} className="px-4 py-2 text-[12px]">
                <div className="flex justify-between gap-2"><span className="mono text-ink-400">{fmtTime(f.at)}</span><EventLink uid={f.uid} /></div>
                <div className="text-ink-100">{f.text}</div>
              </li>
            ))}
            {!status?.feed.length && <li className="px-4 py-3 text-[12px] text-ink-400">No streamed alerts yet.</li>}
          </ul>
        </Panel>
      </div>

      <Panel title="Push API (for SIEM forwarders and log shippers)">
        <pre className="mono overflow-x-auto rounded bg-ink-950 p-3 text-[11px] text-ink-200">{`curl -X POST http://127.0.0.1:8000/api/stream/events \\
  -H "Content-Type: application/json" \\
  -d '{"source_type": "idp_auth", "records": [{"event_id": "A-1", "time": "2026-10-28T13:00:00Z",
       "user": "k.rao", "src_host": "WS-020", "dst_host": "SRV-APP-02", "logon_type": "network", "result": "success"}]}'

# change notifications (Server-Sent Events):  GET /api/stream/updates
# status / replay:  GET /api/stream/status · POST /api/stream/replay {"start","end","speed"} · POST /api/stream/replay/stop`}</pre>
        <p className="mt-2 text-[11px] text-ink-400">Batches of up to 5,000 records in any supported source schema (auto-detected or set with source_type). Records are validated and normalised exactly like uploaded files; the graph is recomputed in micro-batches (at most every 0.4 s).</p>
      </Panel>
    </div>
  );
}
