import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@/App";
import "@/styles.css";

/**
 * All server state goes through TanStack Query; no component hand-rolls fetch state.
 * A signing session is short and the document must never be stale, so nothing is cached for long.
 */
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 0,
      gcTime: 60_000,
      refetchOnWindowFocus: true,
      retry: 1,
    },
    mutations: { retry: 0 },
  },
});

const container = document.getElementById("root");
if (container === null) {
  throw new Error("#root is missing from index.html");
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
