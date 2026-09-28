import { QueryClientProvider } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { AnnouncerProvider } from "@/components/ui";
import { SigningFlow } from "@/flow/SigningFlow";
import { configureApi, setSessionToken } from "@/lib/api";
import { createSigningQueryClient } from "@/lib/query-client";
import { CallbackChannel, type SigningCallbacks } from "@/sdk/channel";
import { SDK_CLIENT } from "@/sdk/version";

export interface EsignSignerProps extends SigningCallbacks {
  token: string;
  baseUrl: string;
  locale?: string;
}

/**
 * The signing UI, mounted in the host's page rather than an iframe. Page-seen gating, consent,
 * one act per field and "Sign as" are the same code the framed UI runs.
 */
export function EsignSigner({
  token,
  baseUrl,
  locale,
  onSigned,
  onSealed,
  onDeclined,
  onExpired,
  onReauthRequired,
  onResize,
  onNext,
}: EsignSignerProps) {
  // Before children render: the session query must hit the signing origin and name this library,
  // not `/v1` on the host page. An effect would run too late (child effects fire first).
  configureApi({ baseUrl, client: SDK_CLIENT });
  const sessionGone = useRef<() => void>(() => {});
  const [queryClient] = useState(() => createSigningQueryClient(() => sessionGone.current()));
  const channel = useMemo(() => {
    const handlers: SigningCallbacks = {};
    if (onSigned !== undefined) handlers.onSigned = onSigned;
    if (onSealed !== undefined) handlers.onSealed = onSealed;
    if (onDeclined !== undefined) handlers.onDeclined = onDeclined;
    if (onExpired !== undefined) handlers.onExpired = onExpired;
    if (onReauthRequired !== undefined) handlers.onReauthRequired = onReauthRequired;
    if (onResize !== undefined) handlers.onResize = onResize;
    if (onNext !== undefined) handlers.onNext = onNext;
    return new CallbackChannel(handlers);
  }, [onSigned, onSealed, onDeclined, onExpired, onReauthRequired, onResize, onNext]);

  useEffect(() => {
    return () => setSessionToken(null);
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <AnnouncerProvider>
        <SigningFlow
          channel={channel}
          sessionGone={sessionGone}
          token={token}
          {...(locale === undefined ? {} : { locale })}
        />
      </AnnouncerProvider>
    </QueryClientProvider>
  );
}
