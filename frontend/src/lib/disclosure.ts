/**
 * Laying out the ESIGN disclosure.
 *
 * The disclosure is stored text, and its hash is part of the evidence: whatever the signer agreed
 * to is exactly the bytes the server holds, so nothing here may rewrite, summarise or reorder a
 * word of it. The shipped US English text is written with Markdown-ish headings and bullets
 * (`## Getting a copy`, `- a device with a browser`), and a version rendered as flat paragraphs
 * shows those markers to the patient as literal `##` and `-`.
 *
 * So this splits the text into blocks and says what each one *is*. The component renders them as
 * headings, lists and paragraphs. It is not a Markdown parser and must never become one: there is
 * no inline formatting, no links, no HTML, and every character of the body still reaches the
 * screen -- only the marker that said "this line is a heading" is consumed.
 */

export type DisclosureBlock =
  | { kind: "heading"; level: 2 | 3; text: string }
  | { kind: "list"; items: string[] }
  | { kind: "paragraph"; text: string };

const HEADING = /^(#{1,6})\s+(.*)$/;
const BULLET = /^[-*]\s+(.*)$/;

/** Join the wrapped lines of one paragraph back into a sentence. */
const unwrap = (lines: string[]) => lines.join(" ").replace(/\s+/g, " ").trim();

export function parseDisclosure(body: string): DisclosureBlock[] {
  const blocks: DisclosureBlock[] = [];
  let paragraph: string[] = [];
  let list: string[] | null = null;
  let item: string[] = [];

  const endParagraph = () => {
    const text = unwrap(paragraph);
    paragraph = [];
    if (text !== "") {
      blocks.push({ kind: "paragraph", text });
    }
  };
  const endItem = () => {
    const text = unwrap(item);
    item = [];
    if (text !== "" && list !== null) {
      list.push(text);
    }
  };
  const endList = () => {
    endItem();
    if (list !== null && list.length > 0) {
      blocks.push({ kind: "list", items: list });
    }
    list = null;
  };

  for (const raw of body.split("\n")) {
    const line = raw.trimEnd();
    const heading = HEADING.exec(line.trim());
    const bullet = BULLET.exec(line.trim());

    if (line.trim() === "") {
      endParagraph();
      endList();
      continue;
    }
    if (heading !== null) {
      endParagraph();
      endList();
      // A single `#` is the document's own title; everything under it is a section of this sheet,
      // so the top level renders as an h2 and anything deeper as an h3.
      blocks.push({
        kind: "heading",
        level: heading[1]?.length === 1 ? 2 : 3,
        text: heading[2]?.trim() ?? "",
      });
      continue;
    }
    if (bullet !== null) {
      endParagraph();
      if (list === null) {
        list = [];
      } else {
        endItem();
      }
      item = [bullet[1]?.trim() ?? ""];
      continue;
    }
    if (list !== null) {
      // An indented continuation line belongs to the bullet above it.
      item.push(line.trim());
      continue;
    }
    paragraph.push(line.trim());
  }
  endParagraph();
  endList();
  return blocks;
}
