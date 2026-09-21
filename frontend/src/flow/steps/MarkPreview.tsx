import type { AdoptedSignature } from "@/flow/draft";

interface MarkPreviewProps {
  adopted: AdoptedSignature;
  kind: "signature" | "initials";
  initials: string;
  displayName: string;
  /** "page" sizes the text to the field box on the PDF; "card" is for the review list. */
  context: "page" | "card";
}

/**
 * How the adopted signature will look in a field. A preview only: the server stamps the real
 * mark (and the caption with name, capacity, time and signer id) when the document is signed.
 */
export function MarkPreview({ adopted, kind, initials, displayName, context }: MarkPreviewProps) {
  const ink = context === "page" ? "text-page-ink" : "text-pen";
  const fit = context === "page" ? "size-full" : "h-12 max-w-[14rem]";
  if (kind === "initials") {
    return (
      <span
        className={`${adopted.kind === "click" ? "font-sans font-semibold" : "font-script"} ${ink} ${context === "page" ? "text-base" : "text-2xl"}`}
      >
        {initials}
      </span>
    );
  }
  if (adopted.kind === "click") {
    return (
      <span
        className={`truncate px-1 font-sans font-semibold ${ink} ${context === "page" ? "text-[0.8rem]" : "text-lg"}`}
      >
        {displayName}
      </span>
    );
  }
  if (adopted.kind === "typed") {
    return (
      <span
        className={`truncate px-1 font-script ${ink} ${context === "page" ? "text-xl" : "text-3xl"}`}
      >
        {adopted.text}
      </span>
    );
  }
  return (
    <img
      src={adopted.dataUrl}
      alt=""
      className={`${fit} object-contain p-0.5 ${context === "card" ? "dark:invert dark:hue-rotate-180" : ""}`}
    />
  );
}
