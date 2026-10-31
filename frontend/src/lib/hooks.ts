import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

export const DataVersion = createContext<{ version: number; bump: () => void }>({ version: 0, bump: () => {} });
export const useDataVersion = () => useContext(DataVersion);

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const { version } = useDataVersion();
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const run = useCallback(() => {
    const id = ++seq.current;
    setLoading(true);
    setError(null);
    fn()
      .then((d) => id === seq.current && setData(d))
      .catch((e: Error) => id === seq.current && setError(e.message))
      .finally(() => id === seq.current && setLoading(false));
  }, [...deps, version]);
  useEffect(run, [run]);
  return { data, error, loading, reload: run, setData };
}

export interface Route {
  page: string;
  params: URLSearchParams;
}

function parse(): Route {
  const h = window.location.hash.replace(/^#\/?/, "");
  const [page, qs] = h.split("?");
  return { page: page || "overview", params: new URLSearchParams(qs || "") };
}

export function useRoute(): Route {
  const [r, setR] = useState(parse);
  useEffect(() => {
    const on = () => setR(parse());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return r;
}

export function go(page: string, params?: Record<string, string | number | undefined>) {
  const p = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => v !== undefined && v !== "" && p.set(k, String(v)));
  const qs = p.toString();
  window.location.hash = `/${page}${qs ? `?${qs}` : ""}`;
}

export function setParams(page: string, params: Record<string, string | number | undefined>) {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => v !== undefined && v !== "" && p.set(k, String(v)));
  const qs = p.toString();
  history.replaceState(null, "", `#/${page}${qs ? `?${qs}` : ""}`);
}

export const fmtTime = (iso: string | null | undefined, withDate = true) => {
  if (!iso) return "-";
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, "0");
  const t = `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  return withDate ? `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${t}Z` : `${t}Z`;
};

export const shortName = (id: string) => {
  const i = id.indexOf(":");
  const name = i >= 0 ? id.slice(i + 1) : id;
  if (id.startsWith("process:")) {
    const [, rest] = name.split("/");
    return rest || name;
  }
  return name;
};

export const entityType = (id: string) => id.split(":")[0];

export const fmtBytes = (n: number) =>
  n > 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : n > 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;
