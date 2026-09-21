import { createContext, useContext, useEffect, useState } from "react";
import type { OutboundMessage } from "@/lib/embed";

export interface HostLink {
  post: (message: OutboundMessage) => void;
  /** Called when the host page says re-authentication finished. Returns an unsubscribe. */
  onReauthDone: (listener: () => void) => () => void;
}

export const HostLinkContext = createContext<HostLink>({
  post: () => {},
  onReauthDone: () => () => {},
});

export const useHostLink = () => useContext(HostLinkContext);

/** The current time, re-read on an interval. For countdowns; never sent to the server. */
export function useNow(intervalMs: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}
