/**
 * What the signer has prepared but not yet submitted: the signature they adopted and what they
 * have put in each field. Client state only; it never leaves memory and is dropped on hand-back.
 */

import { byReadingOrder } from "@/lib/geometry";
import type { Capture, SigningField } from "@/lib/signing-api";

export type AdoptedSignature =
  | { kind: "drawn"; dataUrl: string; base64: string }
  | { kind: "typed"; text: string }
  | { kind: "click" };

export type FieldValue =
  | { type: "mark" }
  | { type: "checkbox"; checked: boolean }
  | { type: "text"; text: string };

export interface Draft {
  adopted: AdoptedSignature | null;
  initials: string;
  values: Record<string, FieldValue>;
}

export const emptyDraft: Draft = { adopted: null, initials: "", values: {} };

/**
 * `Settings.max_text_field_chars` (SPEC section 9): what the server will actually accept in a
 * text field. It was 200 here -- the *typed signature* bound -- so a long answer stopped dead
 * with no counter and no message.
 */
export const TEXT_FIELD_MAX = 2000;

/** Past this much of the limit the field starts saying how much room is left. */
export const TEXT_FIELD_HINT_AT = Math.floor(TEXT_FIELD_MAX * 0.8);

export const isMarkField = (field: SigningField) =>
  field.type === "signature" || field.type === "initials";

/** The fields the signer acts on, in reading order. `date_signed` is filled by the server. */
export function actionableFields(fields: SigningField[]): SigningField[] {
  return fields.filter((field) => field.type !== "date_signed").sort(byReadingOrder);
}

export function serverFilledFields(fields: SigningField[]): SigningField[] {
  return fields.filter((field) => field.type === "date_signed").sort(byReadingOrder);
}

export function initialsFrom(displayName: string): string {
  return displayName
    .split(/\s+/)
    .filter((part) => /^\p{L}/u.test(part) && !/\.$/.test(part))
    .map((part) => part.charAt(0).toUpperCase())
    .join("")
    .slice(0, 4);
}

export function isFieldComplete(field: SigningField, value: FieldValue | undefined): boolean {
  switch (field.type) {
    case "signature":
    case "initials":
      return value?.type === "mark" || !field.required;
    case "checkbox":
      return !field.required || (value?.type === "checkbox" && value.checked);
    case "text":
      return !field.required || (value?.type === "text" && value.text.trim() !== "");
    case "date_signed":
      return true;
  }
}

export function remainingRequired(fields: SigningField[], draft: Draft): SigningField[] {
  return actionableFields(fields).filter(
    (field) => field.required && !isFieldComplete(field, draft.values[field.id]),
  );
}

/** Adopting a different signature un-applies the old one everywhere: applying is per field. */
export function withAdopted(draft: Draft, adopted: AdoptedSignature, initials: string): Draft {
  const values = Object.fromEntries(
    Object.entries(draft.values).filter(([, value]) => value.type !== "mark"),
  );
  return { adopted, initials, values };
}

export function withValue(draft: Draft, fieldId: string, value: FieldValue | null): Draft {
  const values = { ...draft.values };
  if (value === null) {
    delete values[fieldId];
  } else {
    values[fieldId] = value;
  }
  return { ...draft, values };
}

/** Signature inputs only. No dates, no identity, no hashes: the server supplies those. */
export function buildCaptures(fields: SigningField[], draft: Draft): Capture[] {
  const captures: Capture[] = [];
  for (const field of actionableFields(fields)) {
    const value = draft.values[field.id];
    if (value === undefined) {
      continue;
    }
    if (value.type === "checkbox" && field.type === "checkbox") {
      captures.push({ field_id: field.id, checked: value.checked });
    } else if (value.type === "text" && field.type === "text") {
      const text = value.text.trim();
      if (text !== "") {
        captures.push({ field_id: field.id, text_value: text.slice(0, TEXT_FIELD_MAX) });
      }
    } else if (value.type === "mark" && isMarkField(field) && draft.adopted !== null) {
      const adopted = draft.adopted;
      if (field.type === "initials") {
        // Initials are always the signer's typed initials: a full printed name or a full
        // signature image does not belong in an initials box.
        captures.push({ field_id: field.id, kind: "typed", typed_text: draft.initials });
      } else if (adopted.kind === "click") {
        captures.push({ field_id: field.id, kind: "click" });
      } else if (adopted.kind === "typed") {
        captures.push({ field_id: field.id, kind: "typed", typed_text: adopted.text });
      } else {
        captures.push({ field_id: field.id, kind: "drawn", image_png_base64: adopted.base64 });
      }
    }
  }
  return captures;
}
