import type { ReactNode } from "react";
import {
  AlertTriangle,
  Bell,
  Cog,
  Cpu,
  Database,
  Globe,
  Link2,
  Loader2,
  Monitor,
  Network,
  Server,
  ShieldAlert,
  User,
  UserCog,
} from "lucide-react";
import type { BlastClass, Breakdown, Priority } from "../lib/types";

export function Panel({ title, actions, children, className = "", bodyClass = "p-4" }: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClass?: string;
}) {
  return (
    <section className={`rounded-lg border border-ink-700 bg-ink-900 ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-ink-700 px-4 py-2.5">
          <h2 className="text-[13px] font-semibold tracking-wide text-ink-200">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, sub, onClick }: { label: string; value: ReactNode; sub?: ReactNode; onClick?: () => void }) {
  const C = onClick ? "button" : "div";
  return (
    <C
      onClick={onClick}
      className={`rounded-lg border border-ink-700 bg-ink-900 px-4 py-3 text-left ${onClick ? "transition hover:border-ink-500" : ""}`}
    >
      <div className="text-[11px] font-medium uppercase tracking-wider text-ink-400">{label}</div>
      <div className="tabular mt-1 text-2xl font-semibold text-ink-100">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-ink-400">{sub}</div>}
    </C>
  );
}

const PRIORITY_STYLE: Record<Priority, string> = {
  Critical: "bg-crit/15 text-crit ring-crit/40",
  High: "bg-high/15 text-high ring-high/40",
  Moderate: "bg-mod/15 text-mod ring-mod/40",
  Low: "bg-low/15 text-ink-300 ring-low/40",
};

export function PriorityPill({ priority, score }: { priority: Priority; score?: number }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[11px] font-semibold ring-1 ring-inset ${PRIORITY_STYLE[priority]}`}>
      {priority}
      {score !== undefined && <span className="tabular font-normal opacity-80">{score.toFixed(1)}</span>}
    </span>
  );
}

export const CLASS_META: Record<BlastClass, { label: string; short: string; cls: string; dot: string }> = {
  CONFIRMED_COMPROMISE: { label: "Confirmed compromise", short: "Confirmed", cls: "bg-crit/15 text-crit ring-crit/40", dot: "bg-crit" },
  SUSPECTED_LATERAL_MOVEMENT: { label: "Suspected lateral movement", short: "Suspected", cls: "bg-high/15 text-high ring-high/40", dot: "bg-high" },
  OBSERVED_CONNECTION: { label: "Observed connection", short: "Observed", cls: "bg-signal/10 text-signal ring-signal/30", dot: "bg-signal" },
  POTENTIAL_EXPOSURE: { label: "Potential exposure", short: "Potential", cls: "bg-ink-700/60 text-ink-300 ring-ink-600", dot: "bg-ink-400" },
};

export function ClassPill({ c }: { c: BlastClass }) {
  const m = CLASS_META[c];
  return <span className={`inline-flex whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset ${m.cls}`}>{m.short}</span>;
}

export function BasisTag({ basis }: { basis: "observed" | "inferred" }) {
  return basis === "observed" ? (
    <span className="rounded bg-ink-700 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-ink-200">observed</span>
  ) : (
    <span className="rounded border border-dashed border-ink-500 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-ink-300">inferred</span>
  );
}

export function TypeIcon({ type, category, size = 14, className = "" }: { type: string; category?: string; size?: number; className?: string }) {
  const p = { size, className, strokeWidth: 1.8 };
  switch (type) {
    case "user":
      return category === "admin_account" || category === "service_account" ? <UserCog {...p} /> : <User {...p} />;
    case "host":
      return category === "workstation" ? <Monitor {...p} /> : category === "network_device" ? <Network {...p} /> : <Server {...p} />;
    case "database":
      return <Database {...p} />;
    case "process":
      return <Cpu {...p} />;
    case "service":
      return <Cog {...p} />;
    case "domain":
      return <Link2 {...p} />;
    case "ip":
      return <Globe {...p} />;
    case "alert":
      return <Bell {...p} />;
    default:
      return <ShieldAlert {...p} />;
  }
}

export function CritDots({ n }: { n: number }) {
  return (
    <span className="inline-flex gap-0.5" title={`Criticality ${n}/5`} aria-label={`Criticality ${n} of 5`}>
      {[1, 2, 3, 4, 5].map((i) => (
        <span key={i} className={`h-1.5 w-1.5 rounded-full ${i <= n ? (n >= 5 ? "bg-crit" : n >= 4 ? "bg-high" : "bg-ink-300") : "bg-ink-700"}`} />
      ))}
    </span>
  );
}

export function Button({ children, onClick, variant = "default", disabled, type = "button", title, className = "" }: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "default" | "primary" | "ghost" | "danger";
  disabled?: boolean;
  type?: "button" | "submit";
  title?: string;
  className?: string;
}) {
  const v = {
    default: "border border-ink-600 bg-ink-800 text-ink-100 hover:bg-ink-700",
    primary: "bg-signal text-ink-950 hover:bg-signal/90 font-semibold",
    ghost: "text-ink-300 hover:bg-ink-800 hover:text-ink-100",
    danger: "border border-crit/50 text-crit hover:bg-crit/10",
  }[variant];
  return (
    <button
      type={type}
      title={title}
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[13px] transition disabled:cursor-not-allowed disabled:opacity-40 ${v} ${className}`}
    >
      {children}
    </button>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] font-medium uppercase tracking-wider text-ink-400">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-[11px] text-ink-400">{hint}</span>}
    </label>
  );
}

export const inputCls =
  "w-full rounded-md border border-ink-600 bg-ink-850 px-2.5 py-1.5 text-[13px] text-ink-100 placeholder:text-ink-500 focus:border-signal focus:outline-none";

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-6 text-sm text-ink-400">
      <Loader2 size={16} className="animate-spin" /> {label}…
    </div>
  );
}

export function ErrorBox({ msg }: { msg: string }) {
  return (
    <div role="alert" className="flex items-start gap-2 rounded-md border border-crit/40 bg-crit/10 p-3 text-sm text-crit">
      <AlertTriangle size={16} className="mt-0.5 shrink-0" /> {msg}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="p-6 text-center text-sm text-ink-400">{children}</div>;
}

export function ScoreBreakdown({ breakdown, disclaimer }: { breakdown: Breakdown[]; disclaimer?: string }) {
  return (
    <div className="space-y-1.5">
      {breakdown.map((b) => (
        <div key={b.component} className="grid grid-cols-[150px_1fr_52px] items-center gap-3 text-xs" title={b.explanation}>
          <span className="text-ink-300">{b.label}</span>
          <div className="relative h-2 rounded-full bg-ink-800">
            <div className="absolute inset-y-0 left-0 rounded-full bg-ink-400/50" style={{ width: `${b.weight * 100}%` }} />
            <div className="absolute inset-y-0 left-0 rounded-full bg-signal" style={{ width: `${b.weight * b.value * 100}%` }} />
          </div>
          <span className="tabular text-right text-ink-200">+{b.contribution.toFixed(1)}</span>
          <span className="col-span-3 -mt-1 pl-[162px] text-[11px] leading-snug text-ink-400">{b.explanation}</span>
        </div>
      ))}
      {disclaimer && <p className="pt-1 text-[11px] italic text-ink-400">{disclaimer}</p>}
    </div>
  );
}

export function Segmented<T extends string>({ value, options, onChange }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex rounded-md border border-ink-600 bg-ink-850 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={`rounded px-2.5 py-1 text-xs transition ${value === o.value ? "bg-ink-600 text-ink-100" : "text-ink-300 hover:text-ink-100"}`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
