import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown } from "lucide-react";
import { api } from "../lib/api";
import { useAsync } from "../lib/hooks";
import type { EntitySummary } from "../lib/types";
import { CritDots, TypeIcon, inputCls } from "./ui";

export function EntityPicker({ value, onChange, placeholder = "Search entity…", types, allowEmpty, emptyLabel = "Any", id }: {
  value: string;
  onChange: (id: string) => void;
  placeholder?: string;
  types?: string[];
  allowEmpty?: boolean;
  emptyLabel?: string;
  id?: string;
}) {
  const { data } = useAsync(() => api.entities(), []);
  const [q, setQ] = useState("");
  const [openList, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const list: EntitySummary[] = useMemo(() => {
    const all = (data || []).filter((e) => e.type !== "alert" && (!types || types.includes(e.type)));
    const needle = q.trim().toLowerCase();
    return (needle ? all.filter((e) => e.id.toLowerCase().includes(needle)) : all).slice(0, 60);
  }, [data, q, types]);
  useEffect(() => {
    const h = (ev: MouseEvent) => ref.current && !ref.current.contains(ev.target as Node) && setOpen(false);
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);
  const choose = (v: string) => {
    onChange(v);
    setQ("");
    setOpen(false);
  };
  return (
    <div ref={ref} className="relative">
      <div className="relative">
        <input
          id={id}
          role="combobox"
          aria-expanded={openList}
          className={`${inputCls} pr-7`}
          placeholder={value ? value : placeholder}
          value={openList ? q : value || ""}
          onFocus={() => { setOpen(true); setActive(0); }}
          onChange={(e) => { setQ(e.target.value); setOpen(true); setActive(0); }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, list.length - 1)); }
            else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
            else if (e.key === "Enter" && list[active]) { e.preventDefault(); choose(list[active].id); }
            else if (e.key === "Escape") setOpen(false);
          }}
        />
        <ChevronDown size={14} className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-ink-400" />
      </div>
      {openList && (
        <ul role="listbox" className="absolute z-30 mt-1 max-h-72 w-full min-w-[280px] overflow-y-auto rounded-md border border-ink-600 bg-ink-850 py-1 shadow-xl shadow-black/50">
          {allowEmpty && (
            <li>
              <button className="w-full px-2.5 py-1.5 text-left text-xs text-ink-300 hover:bg-ink-700" onMouseDown={(e) => { e.preventDefault(); choose(""); }}>
                {emptyLabel}
              </button>
            </li>
          )}
          {list.map((e, i) => (
            <li key={e.id} role="option" aria-selected={i === active}>
              <button
                onMouseDown={(ev) => { ev.preventDefault(); choose(e.id); }}
                onMouseEnter={() => setActive(i)}
                className={`flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-[13px] ${i === active ? "bg-ink-700" : ""}`}
              >
                <TypeIcon type={e.type} category={e.category} size={13} className="shrink-0 text-ink-400" />
                <span className="min-w-0 flex-1 truncate">{e.id}</span>
                {e.criticality > 1 && <CritDots n={e.criticality} />}
              </button>
            </li>
          ))}
          {list.length === 0 && <li className="px-2.5 py-2 text-xs text-ink-400">No matching entities</li>}
        </ul>
      )}
    </div>
  );
}
