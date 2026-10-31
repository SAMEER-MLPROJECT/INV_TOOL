import { useMemo, useState } from "react";
import { FolderSearch, GitBranch, LayoutDashboard, Radar, Radio, Settings2, Share2, Siren } from "lucide-react";
import { InspectorProvider } from "./components/Inspector";
import { api } from "./lib/api";
import { DataVersion, fmtTime, useAsync, useRoute } from "./lib/hooks";
import { useLiveUpdates } from "./lib/live";
import type { LiveUpdate } from "./lib/types";
import { LivePage } from "./pages/LivePage";
import { BlastPage } from "./pages/BlastPage";
import { EvidencePage } from "./pages/EvidencePage";
import { GraphPage } from "./pages/GraphPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { Overview } from "./pages/Overview";
import { PathsPage } from "./pages/PathsPage";
import { SettingsPage } from "./pages/SettingsPage";

const NAV = [
  { id: "overview", label: "Overview", icon: LayoutDashboard, title: "Overview" },
  { id: "live", label: "Live Monitor", icon: Radio, title: "Live stream monitor" },
  { id: "graph", label: "Attack Graph", icon: Share2, title: "Attack graph" },
  { id: "paths", label: "Attack Paths", icon: GitBranch, title: "Attack path explorer" },
  { id: "blast", label: "Blast Radius", icon: Radar, title: "Blast radius explorer" },
  { id: "incidents", label: "Incidents", icon: Siren, title: "Incident investigation" },
  { id: "evidence", label: "Evidence", icon: FolderSearch, title: "Evidence centre" },
  { id: "settings", label: "Settings & Data", icon: Settings2, title: "Settings and data management" },
];

function TopBar({ title, live, connected }: { title: string; live: LiveUpdate | null; connected: boolean }) {
  const { data } = useAsync(() => api.summary(), []);
  return (
    <header className="flex h-12 items-center justify-between border-b border-ink-700 bg-ink-900/80 px-5 backdrop-blur">
      <h1 className="text-[15px] font-semibold">{title}</h1>
      {data && (
        <div className="flex items-center gap-4 text-[11px] text-ink-400">
          <span className="mono">{fmtTime(data.time_range.start)} → {fmtTime(data.time_range.end)}</span>
          <span>{data.events.toLocaleString()} events · {data.source_systems} sources</span>
          <button onClick={() => (window.location.hash = "/live")} title="Live updates (Server-Sent Events)"
            className="flex items-center gap-1.5 rounded border border-ink-700 px-2 py-0.5 hover:border-ink-500">
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? (live?.reason === "stream" ? "animate-pulse bg-crit" : "bg-ok") : "bg-ink-500"}`} />
            {connected ? (live?.reason === "stream" ? `LIVE · ${live.streamed.toLocaleString()} streamed` : "Live updates on") : "Live updates off"}
          </button>
          <span className="flex items-center gap-1.5 rounded border border-ink-700 px-2 py-0.5">
            <span className={`h-1.5 w-1.5 rounded-full ${data.backend.neo4j.synced ? "bg-ok" : "bg-signal"}`} />
            {data.backend.mode === "neo4j" && data.backend.neo4j.synced ? "Neo4j + local engine" : "Local graph engine"}
          </span>
        </div>
      )}
    </header>
  );
}

export default function App() {
  const route = useRoute();
  const [version, setVersion] = useState(0);
  const dv = useMemo(() => ({ version, bump: () => setVersion((v) => v + 1) }), [version]);
  const { last, connected } = useLiveUpdates(() => setVersion((v) => v + 1));
  const page = NAV.find((n) => n.id === route.page) || NAV[0];
  return (
    <DataVersion.Provider value={dv}>
      <InspectorProvider>
        <div className="flex h-full">
          <nav aria-label="Main" className="flex w-[208px] shrink-0 flex-col border-r border-ink-700 bg-ink-900">
            <div className="flex h-12 items-center gap-2 border-b border-ink-700 px-4">
              <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden><g stroke="#7cc4ff" strokeWidth="2.2" fill="none"><path d="M8 22 L16 10 L24 20" /><circle cx="8" cy="22" r="3" fill="#111419" /><circle cx="16" cy="10" r="3" fill="#111419" /><circle cx="24" cy="20" r="3.5" fill="#f08c3a" stroke="#f08c3a" /></g></svg>
              <div className="leading-tight">
                <div className="text-[13px] font-semibold tracking-wide">AttackGraph Lens</div>
                <div className="text-[10px] text-ink-400">GraphOps investigation</div>
              </div>
            </div>
            <ul className="flex-1 space-y-0.5 p-2">
              {NAV.map((n) => {
                const Icon = n.icon;
                const active = n.id === page.id;
                return (
                  <li key={n.id}>
                    <a href={`#/${n.id}`} aria-current={active ? "page" : undefined}
                      className={`flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] transition ${active ? "bg-ink-800 text-ink-100" : "text-ink-300 hover:bg-ink-850 hover:text-ink-100"}`}>
                      <Icon size={16} strokeWidth={1.8} className={active ? "text-signal" : ""} /> {n.label}
                    </a>
                  </li>
                );
              })}
            </ul>
            <p className="border-t border-ink-700 p-3 text-[10px] leading-snug text-ink-500">
              Relationships show observed interactions, not proof of compromise. All times UTC.
            </p>
          </nav>
          <div className="flex min-w-0 flex-1 flex-col">
            <TopBar title={page.title} live={last} connected={connected} />
            <main className="min-h-0 flex-1 overflow-y-auto p-5">
              {page.id === "overview" && <Overview />}
              {page.id === "live" && <LivePage />}
              {page.id === "graph" && <GraphPage key={route.params.get("focus") || "all"} route={route} />}
              {page.id === "paths" && <PathsPage key={route.params.get("source") || "none"} route={route} />}
              {page.id === "blast" && <BlastPage key={route.params.get("entity") || "none"} route={route} />}
              {page.id === "incidents" && <IncidentsPage route={route} />}
              {page.id === "evidence" && <EvidencePage />}
              {page.id === "settings" && <SettingsPage />}
            </main>
          </div>
        </div>
      </InspectorProvider>
    </DataVersion.Provider>
  );
}
