import { describe, expect, it } from "vitest";
import {
  type AdoptedSignature,
  actionableFields,
  buildCaptures,
  buildSignRequest,
  type Draft,
  emptyDraft,
  initialsFrom,
  isFieldComplete,
  remainingRequired,
  savedLook,
  TEXT_FIELD_MAX,
  withAdopted,
  withoutAdopted,
  withoutInitialsMarks,
  withValue,
} from "@/flow/draft";
import type { SigningField } from "@/lib/signing-api";

const field = (patch: Partial<SigningField> & Pick<SigningField, "id" | "type">): SigningField => ({
  page: 1,
  rect: { x: 72, y: 100, w: 200, h: 40 },
  required: true,
  label: patch.id,
  ...patch,
});

const fields: SigningField[] = [
  field({ id: "sig", type: "signature", page: 3 }),
  field({ id: "date", type: "date_signed", page: 3, rect: { x: 330, y: 100, w: 100, h: 20 } }),
  field({ id: "init", type: "initials" }),
  field({ id: "ack", type: "checkbox", page: 2 }),
  field({
    id: "note",
    type: "text",
    page: 2,
    required: false,
    rect: { x: 72, y: 50, w: 200, h: 40 },
  }),
];

describe("the signing draft", () => {
  it("guides through the signer's fields in reading order and leaves dates to the server", () => {
    expect(actionableFields(fields).map((f) => f.id)).toEqual(["init", "ack", "note", "sig"]);
  });

  it("counts what is still needed", () => {
    let draft: Draft = withAdopted(emptyDraft, { kind: "click" }, "MA");
    expect(remainingRequired(fields, draft).map((f) => f.id)).toEqual(["init", "ack", "sig"]);
    draft = withValue(draft, "init", { type: "mark" });
    draft = withValue(draft, "ack", { type: "checkbox", checked: false });
    expect(remainingRequired(fields, draft).map((f) => f.id)).toEqual(["ack", "sig"]);
    draft = withValue(draft, "ack", { type: "checkbox", checked: true });
    draft = withValue(draft, "sig", { type: "mark" });
    expect(remainingRequired(fields, draft)).toEqual([]);
  });

  it("an optional field is never in the way; a required text needs real text", () => {
    expect(
      isFieldComplete(field({ id: "n", type: "text", required: false }), undefined, emptyDraft),
    ).toBe(true);
    expect(
      isFieldComplete(field({ id: "n", type: "text" }), { type: "text", text: "   " }, emptyDraft),
    ).toBe(false);
    expect(
      isFieldComplete(field({ id: "n", type: "text" }), { type: "text", text: "Yes" }, emptyDraft),
    ).toBe(true);
  });

  /**
   * An initials mark stands for the typed initials and nothing else (`buildCaptures` sends them
   * as the capture's `typed_text`), so an emptied box leaves the mark standing for nothing. It
   * used to count as done: the button signed, and the server refused the empty text with a 422
   * whose advice -- choose your signature again -- named the wrong box.
   */
  it("initials are not in place when the initials box is empty", () => {
    const initials = field({ id: "init", type: "initials" });
    let draft = withAdopted(emptyDraft, { kind: "click" }, "MA");
    draft = withValue(draft, "init", { type: "mark" });
    expect(isFieldComplete(initials, draft.values.init, draft)).toBe(true);

    const cleared = { ...draft, initials: "  " };
    expect(isFieldComplete(initials, cleared.values.init, cleared)).toBe(false);
    expect(remainingRequired([initials], cleared).map((f) => f.id)).toEqual(["init"]);
    // ...and nothing empty goes over the wire even if a mark survives somewhere.
    expect(buildCaptures([initials], cleared)).toEqual([]);
  });

  it("clearing the initials box un-places the marks that stood for them", () => {
    let draft = withAdopted(emptyDraft, { kind: "click" }, "MA");
    draft = withValue(draft, "init", { type: "mark" });
    draft = withValue(draft, "sig", { type: "mark" });
    draft = withValue(draft, "ack", { type: "checkbox", checked: true });
    expect(withoutInitialsMarks(draft, fields).values).toEqual({
      sig: { type: "mark" },
      ack: { type: "checkbox", checked: true },
    });
  });

  it("builds exactly the SPEC 9 capture shapes and nothing else", () => {
    let draft = withAdopted(
      emptyDraft,
      { kind: "drawn", dataUrl: "data:image/png;base64,AAAA", base64: "AAAA" },
      "MA",
    );
    for (const id of ["sig", "init"]) {
      draft = withValue(draft, id, { type: "mark" });
    }
    draft = withValue(draft, "ack", { type: "checkbox", checked: true });
    draft = withValue(draft, "note", { type: "text", text: "  Will it hurt?  " });
    expect(buildCaptures(fields, draft)).toEqual([
      { field_id: "init", kind: "typed", typed_text: "MA" },
      { field_id: "ack", checked: true },
      { field_id: "note", text_value: "Will it hurt?" },
      { field_id: "sig", kind: "drawn", image_png_base64: "AAAA" },
    ]);
  });

  it("typed and click signatures are first-class capture kinds", () => {
    const typed = withValue(
      withAdopted(emptyDraft, { kind: "typed", text: "Maria Alvarez" }, ""),
      "sig",
      { type: "mark" },
    );
    expect(buildCaptures(fields, typed)).toEqual([
      { field_id: "sig", kind: "typed", typed_text: "Maria Alvarez" },
    ]);
    const click = withValue(withAdopted(emptyDraft, { kind: "click" }, ""), "sig", {
      type: "mark",
    });
    expect(buildCaptures(fields, click)).toEqual([{ field_id: "sig", kind: "click" }]);
  });

  it("never sends a date, an unapplied signature, or an empty optional answer", () => {
    let draft = withAdopted(emptyDraft, { kind: "click" }, "MA");
    draft = withValue(draft, "note", { type: "text", text: " " });
    expect(buildCaptures(fields, draft)).toEqual([]);
    expect(
      JSON.stringify(buildCaptures(fields, withValue(draft, "date", { type: "mark" }))),
    ).not.toContain("date");
  });

  it("choosing a different signature un-applies the old one from every field", () => {
    let draft = withAdopted(emptyDraft, { kind: "click" }, "MA");
    draft = withValue(draft, "sig", { type: "mark" });
    draft = withValue(draft, "ack", { type: "checkbox", checked: true });
    const changed = withAdopted(draft, { kind: "typed", text: "Maria" }, "MA");
    expect(changed.values).toEqual({ ack: { type: "checkbox", checked: true } });
  });

  /**
   * SPEC section 9 bounds a text field at `MAX_TEXT_FIELD_CHARS` (2000). The UI used to cut it at
   * 200 -- the typed-signature bound -- so a long answer was silently truncated on its way to the
   * server, and the textarea simply stopped accepting keystrokes at a tenth of the real limit.
   */
  it("carries a text answer up to the limit the server accepts, and no further", () => {
    expect(TEXT_FIELD_MAX).toBe(2000);
    const long = "a".repeat(TEXT_FIELD_MAX);
    const draft = withValue(emptyDraft, "note", { type: "text", text: long });
    expect(buildCaptures(fields, draft)).toEqual([{ field_id: "note", text_value: long }]);

    const tooLong = withValue(emptyDraft, "note", { type: "text", text: "b".repeat(2500) });
    const capture = buildCaptures(fields, tooLong)[0] as { text_value: string };
    expect(capture.text_value).toHaveLength(TEXT_FIELD_MAX);
  });

  it("derives initials from a name, skipping titles", () => {
    expect(initialsFrom("Maria Alvarez")).toBe("MA");
    expect(initialsFrom("Dr. Priya Raman")).toBe("PR");
    expect(initialsFrom("  anne-marie   o'neil ")).toBe("AO");
  });
});

/**
 * SPEC section 14 B. A saved signature goes over the wire as its id and nothing else -- the
 * server holds the image or text and the trail must say a *saved* signature was applied -- and
 * the request to save one is made only when it can possibly be honoured.
 */
describe("saved signatures in the draft", () => {
  const saved = savedLook({
    id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
    kind: "drawn",
    image_png_base64: "iVBORw0KGgo=",
    created_at: "2026-09-16T09:00:00Z",
  });
  const adopted: AdoptedSignature = {
    kind: "adopted",
    id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
    look: saved,
  };

  it("turns the payload into something the previews can draw", () => {
    expect(saved).toEqual({ kind: "drawn", dataUrl: "data:image/png;base64,iVBORw0KGgo=" });
    expect(
      savedLook({
        id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
        kind: "typed",
        typed_text: "Priya Raman",
        created_at: "2026-09-16T09:00:00Z",
      }),
    ).toEqual({ kind: "typed", text: "Priya Raman" });
  });

  it("sends an adopted capture as the id alone; initials stay typed", () => {
    let draft = withAdopted(emptyDraft, adopted, "PR");
    draft = withValue(draft, "sig", { type: "mark" });
    draft = withValue(draft, "init", { type: "mark" });
    expect(buildCaptures(fields, draft)).toEqual([
      { field_id: "init", kind: "typed", typed_text: "PR" },
      { field_id: "sig", kind: "adopted", adopted_signature_id: adopted.id },
    ]);
    expect(JSON.stringify(buildCaptures(fields, draft))).not.toMatch(/image_png|dataUrl|base64/);
  });

  /**
   * The server can refuse the saved signature after it was chosen and placed -- the host revoked
   * it, or another session replaced it -- and then the signer has to choose again. What they
   * typed and ticked is theirs and stays; the marks cannot, because a mark stands for a signature
   * applied on purpose, field by field, and the signature behind these is gone.
   */
  it("un-choosing a signature drops its marks and keeps every other answer", () => {
    let draft = withAdopted(emptyDraft, adopted, "PR", true);
    draft = withValue(draft, "sig", { type: "mark" });
    draft = withValue(draft, "init", { type: "mark" });
    draft = withValue(draft, "ack", { type: "checkbox", checked: true });
    draft = withValue(draft, "note", { type: "text", text: "A question" });

    const gone = withoutAdopted(draft);
    expect(gone.adopted).toBeNull();
    expect(gone.save).toBe(false);
    expect(gone.initials).toBe("PR");
    expect(gone.values).toEqual({
      ack: { type: "checkbox", checked: true },
      note: { type: "text", text: "A question" },
    });
    expect(buildCaptures(fields, gone)).toEqual([
      { field_id: "ack", checked: true },
      { field_id: "note", text_value: "A question" },
    ]);
  });

  it("asks to save only a drawn or typed signature that was actually placed", () => {
    const placed = (draft: Draft) => withValue(draft, "sig", { type: "mark" });
    const typed: AdoptedSignature = { kind: "typed", text: "Maria Alvarez" };

    // Off unless asked, and the flag is absent from the body rather than false.
    const quiet = buildSignRequest(fields, placed(withAdopted(emptyDraft, typed, "MA")), {
      kiosk: false,
    });
    expect(quiet).not.toHaveProperty("save_adopted_signature");

    const asked = buildSignRequest(fields, placed(withAdopted(emptyDraft, typed, "MA", true)), {
      kiosk: false,
    });
    expect(asked.save_adopted_signature).toBe(true);
    expect(asked.captures).toEqual([
      { field_id: "sig", kind: "typed", typed_text: "Maria Alvarez" },
    ]);

    // A printed name and a saved signature are not things to save.
    for (const notSaveable of [{ kind: "click" } as const, adopted]) {
      const draft = placed(withAdopted(emptyDraft, notSaveable, "MA", true));
      expect(draft.save).toBe(false);
      expect(buildSignRequest(fields, draft, { kiosk: false })).not.toHaveProperty(
        "save_adopted_signature",
      );
    }

    // Nor one that was adopted but never placed in a signature field.
    let initialsOnly = withAdopted(emptyDraft, typed, "MA", true);
    initialsOnly = withValue(initialsOnly, "init", { type: "mark" });
    expect(buildSignRequest(fields, initialsOnly, { kiosk: false })).not.toHaveProperty(
      "save_adopted_signature",
    );
  });

  it("never asks a kiosk to save one, whatever the draft says", () => {
    let draft = withAdopted(emptyDraft, { kind: "typed", text: "Maria Alvarez" }, "MA", true);
    draft = withValue(draft, "sig", { type: "mark" });
    expect(draft.save).toBe(true);
    const request = buildSignRequest(fields, draft, { kiosk: true });
    expect(request).not.toHaveProperty("save_adopted_signature");
    expect(request.captures).toEqual([
      { field_id: "sig", kind: "typed", typed_text: "Maria Alvarez" },
    ]);
  });

  it("choosing a new signature drops the request to save the old one", () => {
    const draft = withAdopted(emptyDraft, { kind: "typed", text: "Maria" }, "MA", true);
    expect(withAdopted(draft, adopted, "MA").save).toBe(false);
    expect(withAdopted(draft, { kind: "drawn", dataUrl: "d", base64: "b" }, "MA").save).toBe(false);
  });
});
