import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";
import { isSessionGone, shouldRetryQuery } from "@/lib/signing-api";

/**
 * One client per signing session. A 401 from anywhere (any query, any mutation) means the token
 * is no longer good, and is reported once, centrally, so no screen can forget to handle it.
 */
export function createSigningQueryClient(onSessionGone: () => void): QueryClient {
  const report = (error: unknown) => {
    if (isSessionGone(error)) {
      onSessionGone();
    }
  };
  return new QueryClient({
    queryCache: new QueryCache({ onError: report }),
    mutationCache: new MutationCache({ onError: report }),
    defaultOptions: {
      queries: {
        staleTime: 0,
        gcTime: 60_000,
        refetchOnWindowFocus: true,
        retry: shouldRetryQuery,
        retryDelay: (attempt) => Math.min(4_000, 600 * 2 ** attempt),
      },
      mutations: { retry: 0 },
    },
  });
}
