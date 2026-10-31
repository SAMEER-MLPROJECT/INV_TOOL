import { useEffect, useRef, useState } from "react";
import type { LiveUpdate } from "./types";

/** Subscribes to /api/stream/updates (Server-Sent Events). Calls onChange at most once per `throttleMs`. */
export function useLiveUpdates(onChange: () => void, throttleMs = 1000) {
  const [last, setLast] = useState<LiveUpdate | null>(null);
  const [connected, setConnected] = useState(false);
  const cb = useRef(onChange);
  cb.current = onChange;
  useEffect(() => {
    let lastFire = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let first = true;
    const es = new EventSource("/api/stream/updates");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.addEventListener("update", (ev) => {
      try {
        setLast(JSON.parse((ev as MessageEvent).data));
      } catch {
        /* ignore malformed message */
      }
      if (first) {
        first = false; // the first message only reports the current state
        return;
      }
      const now = Date.now();
      const fire = () => {
        lastFire = Date.now();
        timer = null;
        cb.current();
      };
      if (now - lastFire >= throttleMs) fire();
      else if (!timer) timer = setTimeout(fire, throttleMs - (now - lastFire));
    });
    return () => {
      es.close();
      if (timer) clearTimeout(timer);
    };
  }, [throttleMs]);
  return { last, connected };
}
