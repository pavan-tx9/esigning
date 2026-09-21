import { QueryClientProvider } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { AnnouncerProvider } from "@/components/ui";
import { SigningFlow } from "@/flow/SigningFlow";
import { ParentChannel, resolveAllowedOrigins } from "@/lib/embed";
import { createSigningQueryClient } from "@/lib/query-client";

interface AppProps {
  /** Tests inject a channel with a stand-in parent window; production builds the real one. */
  channel?: ParentChannel;
}

/**
 * The embeddable signing UI (SPEC section 11). Everything it knows arrives after load: the token
 * by postMessage from the host page, and the rest from the Signer API using that token.
 */
export function App({ channel }: AppProps) {
  const sessionGone = useRef<() => void>(() => {});
  const [queryClient] = useState(() => createSigningQueryClient(() => sessionGone.current()));
  const [link] = useState(() => channel ?? new ParentChannel(resolveAllowedOrigins()));
  return (
    <QueryClientProvider client={queryClient}>
      <AnnouncerProvider>
        <SigningFlow channel={link} sessionGone={sessionGone} />
      </AnnouncerProvider>
    </QueryClientProvider>
  );
}
