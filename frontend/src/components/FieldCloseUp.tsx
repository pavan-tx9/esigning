import type { ReactNode } from "react";
import { PdfPage } from "@/components/PdfPage";
import { fieldWindow, rectToPercentBox } from "@/lib/geometry";
import type { LoadedPdf } from "@/lib/pdf";
import type { SigningField } from "@/lib/signing-api";
import { useMeasuredWidth } from "@/lib/use-pdf";

interface FieldCloseUpProps {
  pdf: LoadedPdf;
  field: SigningField;
  done: boolean;
  /** How tall the window may be. Smaller in a list of fields than on a screen of its own. */
  maxHeight?: number;
  /** What currently sits in the field: the applied signature, a tick, the typed text. */
  children?: ReactNode;
}

/**
 * The part of the page around one field, enlarged so the field is easy to see on a phone. The
 * signer sees exactly where on the real document their mark will go.
 */
export function FieldCloseUp({ pdf, field, done, maxHeight = 220, children }: FieldCloseUpProps) {
  const [measure, width] = useMeasuredWidth<HTMLDivElement>();
  const size = pdf.pages[field.page - 1];
  if (size === undefined) {
    return null;
  }
  const view = width > 0 ? fieldWindow(field.rect, size, width, maxHeight) : null;
  const box = rectToPercentBox(field.rect, size);
  return (
    <div ref={measure} aria-hidden="true" className="w-full" data-testid="field-closeup">
      {view ? (
        <div
          className="relative mx-auto overflow-hidden rounded-md ring-1 ring-edge"
          style={{ width: `${view.width}px`, height: `${view.height}px` }}
        >
          <div
            className="absolute top-0 left-0"
            style={{ transform: `translate(${view.offsetX}px, ${view.offsetY}px)` }}
          >
            <PdfPage
              doc={pdf.doc}
              pageNumber={field.page}
              size={size}
              width={size.width * view.scale}
              active
              queueKey={`closeup:${field.id}`}
            >
              <div
                data-field-box={field.id}
                className={`absolute flex items-center justify-center rounded-sm border-2 ${
                  done
                    ? "border-page-done-edge bg-page-done"
                    : "border-page-mark-edge border-dashed bg-page-mark"
                }`}
                style={{
                  left: `${box.left}%`,
                  top: `${box.top}%`,
                  width: `${box.width}%`,
                  height: `${box.height}%`,
                }}
              >
                {children}
              </div>
            </PdfPage>
          </div>
        </div>
      ) : (
        <div style={{ height: `${maxHeight}px` }} />
      )}
    </div>
  );
}
