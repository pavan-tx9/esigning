/**
 * A tiny PDF writer for the mock API, so dev and tests have a real, multi-page, US Letter
 * document to render without shipping binary fixtures. Mock only: the real documents are
 * rendered by the backend. Fictional content; no real person appears in it.
 */

export const LETTER = { width: 612, height: 792 };

type Font = "regular" | "bold";

export class PageWriter {
  private readonly ops: string[] = [];

  text(x: number, y: number, size: number, value: string, font: Font = "regular"): this {
    const safe = value.replace(/([\\()])/g, "\\$1");
    this.ops.push(`BT /${font === "bold" ? "F2" : "F1"} ${size} Tf ${x} ${y} Td (${safe}) Tj ET`);
    return this;
  }

  paragraph(x: number, y: number, size: number, lines: string[], leading = size * 1.5): number {
    let cursor = y;
    for (const line of lines) {
      this.text(x, cursor, size, line);
      cursor -= leading;
    }
    return cursor;
  }

  line(x1: number, y1: number, x2: number, y2: number): this {
    this.ops.push(`0.6 w ${x1} ${y1} m ${x2} ${y2} l S`);
    return this;
  }

  box(x: number, y: number, w: number, h: number): this {
    this.ops.push(`0.6 w ${x} ${y} ${w} ${h} re S`);
    return this;
  }

  content(): string {
    return this.ops.join("\n");
  }
}

export function buildPdf(pages: PageWriter[]): Uint8Array {
  const objects: string[] = [];
  const pageIds = pages.map((_, i) => 5 + i * 2);
  objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`;
  objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
  objects[4] =
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>";
  pages.forEach((page, i) => {
    const id = 5 + i * 2;
    const stream = page.content();
    objects[id] =
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${LETTER.width} ${LETTER.height}] ` +
      `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${id + 1} 0 R >>`;
    objects[id + 1] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`;
  });

  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  for (let id = 1; id < objects.length; id += 1) {
    offsets[id] = out.length;
    out += `${id} 0 obj\n${objects[id]}\nendobj\n`;
  }
  const xref = out.length;
  out += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let id = 1; id < objects.length; id += 1) {
    out += `${String(offsets[id]).padStart(10, "0")} 00000 n \n`;
  }
  out += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  // ASCII only, so string offsets are byte offsets.
  return new TextEncoder().encode(out);
}
