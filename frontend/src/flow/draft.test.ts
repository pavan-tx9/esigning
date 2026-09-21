import { describe, expect, it } from "vitest";
import {
  actionableFields,
  buildCaptures,
  type Draft,
  emptyDraft,
  initialsFrom,
  isFieldComplete,
  remainingRequired,
  withAdopted,
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
    expect(isFieldComplete(field({ id: "n", type: "text", required: false }), undefined)).toBe(
      true,
    );
    expect(isFieldComplete(field({ id: "n", type: "text" }), { type: "text", text: "   " })).toBe(
      false,
    );
    expect(isFieldComplete(field({ id: "n", type: "text" }), { type: "text", text: "Yes" })).toBe(
      true,
    );
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

  it("derives initials from a name, skipping titles", () => {
    expect(initialsFrom("Maria Alvarez")).toBe("MA");
    expect(initialsFrom("Dr. Priya Raman")).toBe("PR");
    expect(initialsFrom("  anne-marie   o'neil ")).toBe("AO");
  });
});
