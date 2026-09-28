import type { HostChannel, InboundMessage, OutboundMessage } from "@/lib/embed";

export interface SigningCallbacks {
  onSigned?: () => void;
  onSealed?: () => void;
  onDeclined?: () => void;
  onExpired?: () => void;
  onReauthRequired?: (sessionId: string) => void;
  onResize?: (height: number) => void;
  onNext?: (envelopeId: string) => void;
}

/**
 * Delivers `esign:*` events as callbacks instead of postMessage. The flow posts the same
 * messages it always did; this is the host side of that conversation for SDK mode.
 */
export class CallbackChannel implements HostChannel {
  constructor(private readonly handlers: SigningCallbacks) {}

  accept(_event: MessageEvent): InboundMessage | null {
    return null;
  }

  post(message: OutboundMessage): void {
    switch (message.type) {
      case "esign:signed":
        this.handlers.onSigned?.();
        return;
      case "esign:sealed":
        this.handlers.onSealed?.();
        return;
      case "esign:declined":
        this.handlers.onDeclined?.();
        return;
      case "esign:expired":
        this.handlers.onExpired?.();
        return;
      case "esign:reauth_required":
        this.handlers.onReauthRequired?.(message.session_id);
        return;
      case "esign:resize":
        this.handlers.onResize?.(message.height);
        return;
      case "esign:next":
        this.handlers.onNext?.(message.envelope_id);
        return;
      default:
        return;
    }
  }
}
