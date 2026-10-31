import { useEffect, useState } from "react";
import { FlaskConical, ShieldCheck, ShieldX } from "lucide-react";
import { EntityLink } from "./Inspector";
import { Button, ErrorBox, Loading, inputCls } from "./ui";
import { api } from "../lib/api";
import { fmtTime, shortName } from "../lib/hooks";
import type { ContainmentPlan, SpreadMetrics, WhatIfResult } from "../lib/types";

function Metric({ label, before, after }: { label: string; before: number; after: number }) {
  const max = Math.max(before, after, 1);
  return (
    <div className="grid grid-cols-[150px_1fr_70px] items-center gap-2 text-[12px]">
      <span className="text-ink-300">{label}</span>
      <div className="space-y-0.5">
        <div className="h-1.5 rounded-full bg-high/70" style={{ width: `${(100 * before) / max}%` }} />
        <div className="h-1.5 rounded-full bg-ok" style={{ width: `${Math.max((100 * after) / max, after ? 2 : 0)}%` }} />
      </div>
      <span className="tabular text-right"><span className="text-high">{before}</span> → <span className="text-ok">{after}</span></span>
    </div>
  );
}

export function BeforeAfter({ before, after }: { before: SpreadMetrics; after: SpreadMetrics }) {
  return (
    <div className="space-y-1.5">
      <Metric label="Crown jewels suspected" before={before.crown_jewels_suspected.length} after={after.crown_jewels_suspected.length} />
      <Metric label="Critical / high paths" before={before.critical_paths} after={after.critical_paths} />
      <Metric label="Suspected entities" before={before.suspected} after={after.suspected} />
      <Metric label="Reachable entities" before={before.reachable} after={after.reachable} />
      <div className="flex gap-4 pt-1 text-[10px] text-ink-400">
        <span className="flex items-center gap-1"><span className="h-1.5 w-4 rounded bg-high/70" /> without action</span>
        <span className="flex items-center gap-1"><span className="h-1.5 w-4 rounded bg-ok" /> with action(s)</span>
      </div>
    </div>
  );
}

/** Containment planner + what-if simulator for an incident. */
export function ContainmentPanel({ incidentId, defaultAt }: { incidentId: string; defaultAt: string }) {
  const [at, setAt] = useState(defaultAt.slice(0, 16));
  const [plan, setPlan] = useState<ContainmentPlan | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);
  const [sim, setSim] = useState<WhatIfResult | null>(null);

  const run = async (t = at) => {
    setBusy(true);
    setErr(null);
    setSim(null);
    try {
      const p = await api.containment(incidentId, `${t}:00Z`);
      setPlan(p);
      setPicked(p.plan.map((r) => r.action.target));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => { run(defaultAt.slice(0, 16)); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [incidentId]);

  const simulate = async () => {
    if (!plan || picked.length === 0) return;
    setBusy(true);
    try {
      setSim(await api.whatIf(plan.source, picked, `${at}:00Z`));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <label className="block">
          <span className="mb-1 block text-[11px] font-medium uppercase tracking-wider text-ink-400">Actions take effect at (UTC)</span>
          <input type="datetime-local" className={inputCls} value={at} onChange={(e) => setAt(e.target.value)} />
        </label>
        <Button variant="primary" disabled={busy} onClick={() => run()}><ShieldCheck size={14} /> Plan containment</Button>
        <span className="text-[11px] text-ink-400">Try the first alert time, then a later time: the plan changes as the attacker gains footholds.</span>
      </div>
      {err && <ErrorBox msg={err} />}
      {busy && !plan && <Loading label="Simulating containment options" />}
      {plan && (
        <div className="grid gap-4 xl:grid-cols-2">
          <div className="space-y-3">
            <div className="text-[12px] text-ink-300">
              At {fmtTime(plan.effective_at)} the adversary already holds{" "}
              <b className="text-ink-100">{plan.footholds.length}</b> foothold(s):{" "}
              {plan.footholds.filter((f) => !f.id.startsWith("process:")).map((f) => shortName(f.id)).join(", ")}
              {plan.footholds.some((f) => f.id.startsWith("process:")) && ` + ${plan.footholds.filter((f) => f.id.startsWith("process:")).length} process(es)`}.
            </div>
            <div className={`flex items-center gap-2 rounded-md border px-3 py-2 text-[13px] ${plan.contained ? "border-ok/40 bg-ok/10 text-ok" : "border-high/40 bg-high/10 text-high"}`}>
              {plan.contained ? <ShieldCheck size={16} /> : <ShieldX size={16} />}
              {plan.contained
                ? `Contained with ${plan.plan.length} action(s): no critical/high path and no crown jewel suspected after T.`
                : plan.plan.length ? `Not fully contained after ${plan.plan.length} action(s).` : "No further spread found from the footholds after this time."}
            </div>
            <ol className="space-y-2">
              {plan.plan.map((r, i) => (
                <li key={r.action.target} className="rounded border border-ink-700 bg-ink-850 px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[13px] font-medium"><span className="text-ink-500">{i + 1}.</span> {r.action.label}</span>
                    <span className="text-[11px] text-ink-400">disruption cost {r.action.cost}</span>
                  </div>
                  <div className="mt-0.5 text-[11px] text-ink-400">
                    residual path risk −{r.risk_reduction_pct}% · crown jewels still suspected: {r.after.crown_jewels_suspected.map(shortName).join(", ") || "none"}
                  </div>
                </li>
              ))}
            </ol>
            <BeforeAfter before={plan.before} after={plan.after} />
            {plan.pruned_as_redundant.length > 0 && (
              <p className="text-[11px] text-ink-400">Removed as redundant after verification: {plan.pruned_as_redundant.join("; ")}.</p>
            )}
            <p className="text-[11px] text-ink-400">{plan.method}. {plan.caveat}</p>
          </div>
          <div className="space-y-3">
            <div className="text-[11px] font-medium uppercase tracking-wider text-ink-400">What-if: choose actions and simulate</div>
            <ul className="max-h-72 space-y-1 overflow-y-auto">
              {plan.candidates.map((c) => (
                <li key={c.target}>
                  <label className="flex cursor-pointer items-start gap-2 rounded px-2 py-1.5 text-[12px] hover:bg-ink-850">
                    <input type="checkbox" className="mt-0.5 accent-[#7cc4ff]" checked={picked.includes(c.target)}
                      onChange={(e) => setPicked(e.target.checked ? [...picked, c.target] : picked.filter((x) => x !== c.target))} />
                    <span className="flex-1">
                      <span className="text-ink-100">{c.label}</span>
                      <span className="block text-[11px] text-ink-400">
                        alone: −{c.risk_reduction_pct}% path risk · cost {c.cost}
                        {c.crown_jewels_protected.length > 0 && <> · protects {c.crown_jewels_protected.map(shortName).join(", ")}</>}
                      </span>
                    </span>
                  </label>
                </li>
              ))}
            </ul>
            <Button disabled={busy || picked.length === 0} onClick={simulate}><FlaskConical size={14} /> Simulate {picked.length} action(s)</Button>
            {sim && (
              <div className="space-y-2 rounded-md border border-ink-700 bg-ink-850 p-3">
                <div className="text-[12px] text-ink-200">
                  {sim.prevented.length ? <>Prevents reach to: {sim.prevented.map((p) => <EntityLink key={p} id={p} />)}</> : "Prevents no additional critical asset."}
                </div>
                <BeforeAfter before={sim.before} after={sim.after} />
                {sim.remaining_paths.length > 0 && (
                  <div className="text-[11px] text-mod">Remaining route example: {sim.remaining_paths[0].map(shortName).join(" → ")}</div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
