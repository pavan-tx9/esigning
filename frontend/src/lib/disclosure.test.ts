import { describe, expect, it } from "vitest";
import { type DisclosureBlock, parseDisclosure } from "@/lib/disclosure";
import { CONSENT } from "@/mocks/db";

const text = (blocks: DisclosureBlock[]) =>
  blocks
    .map((block) => (block.kind === "list" ? block.items.join(" ") : block.text))
    .join(" ")
    .replace(/\s+/g, " ");

describe("parseDisclosure", () => {
  it("makes headings out of heading lines, and keeps their words", () => {
    const blocks = parseDisclosure(
      "# Agreement\n\nSome words.\n\n## Getting a copy\n\nMore words.",
    );
    expect(blocks).toEqual([
      { kind: "heading", level: 2, text: "Agreement" },
      { kind: "paragraph", text: "Some words." },
      { kind: "heading", level: 3, text: "Getting a copy" },
      { kind: "paragraph", text: "More words." },
    ]);
  });

  it("joins the lines of a wrapped paragraph back into a sentence", () => {
    const blocks = parseDisclosure("You do not have to sign\nelectronically. Ask staff.");
    expect(blocks).toEqual([
      { kind: "paragraph", text: "You do not have to sign electronically. Ask staff." },
    ]);
  });

  it("gathers bullets into one list, continuation lines included", () => {
    const blocks = parseDisclosure(
      "You need:\n\n- a browser,\n- a screen, so you can\n  sign, and\n- a printer.",
    );
    expect(blocks).toEqual([
      { kind: "paragraph", text: "You need:" },
      { kind: "list", items: ["a browser,", "a screen, so you can sign, and", "a printer."] },
    ]);
  });

  it("shows plain text as plain paragraphs", () => {
    expect(parseDisclosure("One.\n\nTwo.")).toEqual([
      { kind: "paragraph", text: "One." },
      { kind: "paragraph", text: "Two." },
    ]);
  });

  /**
   * The disclosure's hash is evidence: the signer agreed to these words. Layout may consume the
   * marker that said "heading" or "bullet" and nothing else.
   */
  it("loses not one word of the real disclosure", () => {
    const rendered = text(parseDisclosure(CONSENT.body));
    const original = CONSENT.body
      .replace(/^#{1,6}\s+/gm, "")
      .replace(/^[-*]\s+/gm, "")
      .replace(/\s+/g, " ")
      .trim();
    expect(rendered).toBe(original);
    expect(rendered).not.toContain("##");
  });
});
