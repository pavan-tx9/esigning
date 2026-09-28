import "@/styles.css";
import { createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { EsignSigner, type EsignSignerProps } from "@/sdk/EsignSigner";

export { createSigningClient } from "@/sdk/client";
export type { EsignSignerProps } from "@/sdk/EsignSigner";
export { SDK_CLIENT, SDK_VERSION } from "@/sdk/version";

/**
 * Mount the signing UI into a host page element. Used by the demo host and by pages that do not
 * have their own React tree.
 */
export function mount(element: HTMLElement, props: EsignSignerProps): () => void {
  const root: Root = createRoot(element);
  root.render(createElement(EsignSigner, props));
  return () => root.unmount();
}
