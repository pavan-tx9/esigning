/**
 * The two mock documents and their field definitions. Rects are PDF points, origin bottom-left,
 * exactly as the real API sends them, and they line up with the rules drawn in the PDF so a
 * misplaced highlight is visible at a glance.
 */

import { buildPdf, PageWriter } from "@/mocks/pdf";

export interface MockField {
  id: string;
  type: "signature" | "initials" | "date_signed" | "text" | "checkbox";
  page: number;
  rect: { x: number; y: number; w: number; h: number };
  required: boolean;
  label: string;
  role: "patient" | "witness" | "clinician";
}

const FILLER = [
  "This section explains, in plain language, what you are agreeing to. Please read it",
  "carefully and ask a member of staff about anything that is unclear. You can take as",
  "much time as you need, and you may ask for a printed copy at any point.",
];

function header(page: PageWriter, title: string, n: number, total: number) {
  page.text(72, 730, 10, "Harbourview Family Clinic (sample document)");
  page.text(470, 730, 10, `Page ${n} of ${total}`);
  page.line(72, 722, 540, 722);
  page.text(72, 690, 18, title, "bold");
}

function signatureBlock(page: PageWriter, y: number, who: string, signedName?: string) {
  page.line(72, y, 292, y);
  page.text(72, y - 14, 9, `${who} signature`);
  page.line(330, y, 450, y);
  page.text(330, y - 14, 9, "Date");
  if (signedName !== undefined) {
    page.text(80, y + 14, 16, signedName);
    page.text(334, y + 6, 10, "2026-09-21");
  }
}

// --------------------------------------------------------------------------- HIPAA acknowledgement

export const hipaaFields: MockField[] = [
  {
    id: "ack_received",
    type: "checkbox",
    page: 2,
    rect: { x: 72, y: 520, w: 16, h: 16 },
    required: true,
    label: "I have received the Notice of Privacy Practices",
    role: "patient",
  },
  {
    id: "patient_sig",
    type: "signature",
    page: 2,
    rect: { x: 72, y: 400, w: 220, h: 48 },
    required: true,
    label: "Patient signature",
    role: "patient",
  },
  {
    id: "patient_date",
    type: "date_signed",
    page: 2,
    rect: { x: 330, y: 400, w: 120, h: 24 },
    required: true,
    label: "Date signed",
    role: "patient",
  },
];

export function hipaaPdf(sealed = false): Uint8Array {
  const p1 = new PageWriter();
  header(p1, "Notice of Privacy Practices: Acknowledgement", 1, 2);
  let y = p1.paragraph(72, 650, 11, FILLER);
  p1.text(72, y - 12, 13, "How we use your information", "bold");
  y = p1.paragraph(72, y - 36, 11, [
    "We use your health information to treat you, to bill for your care, and to run the",
    "clinic. We share it only as the law allows, and you can ask us who has seen it.",
    ...FILLER,
  ]);
  p1.text(72, y - 12, 13, "Your rights", "bold");
  p1.paragraph(72, y - 36, 11, [
    "You can ask for a copy of your record, ask us to correct it, and ask us to limit",
    "what we share. The full notice is available at the front desk.",
  ]);

  const p2 = new PageWriter();
  header(p2, "Acknowledgement", 2, 2);
  p2.paragraph(72, 650, 11, [
    "By signing below you confirm that you were offered a copy of the clinic's Notice of",
    "Privacy Practices. Signing does not mean you agree with everything in the notice.",
  ]);
  p2.box(72, 520, 16, 16);
  p2.text(98, 524, 11, "I have received the Notice of Privacy Practices.");
  signatureBlock(p2, 400, "Patient");
  if (sealed) {
    p2.text(80, 414, 16, "Maria Alvarez");
    p2.text(76, 523, 12, "X", "bold");
    p2.text(
      72,
      80,
      9,
      "Sealed copy (mock). Certificate of completion follows in the real service.",
    );
  }
  return buildPdf([p1, p2]);
}

// --------------------------------------------------------------------------- procedure consent

export const procedureFields: MockField[] = [
  {
    id: "patient_initials_risks",
    type: "initials",
    page: 1,
    rect: { x: 470, y: 300, w: 70, h: 30 },
    required: true,
    label: "Initials: the risks were explained to me",
    role: "patient",
  },
  {
    id: "patient_questions",
    type: "text",
    page: 2,
    rect: { x: 72, y: 380, w: 468, h: 60 },
    required: false,
    label: "Anything you would like to ask before the procedure",
    role: "patient",
  },
  {
    id: "patient_sig",
    type: "signature",
    page: 3,
    rect: { x: 72, y: 560, w: 220, h: 48 },
    required: true,
    label: "Patient signature",
    role: "patient",
  },
  {
    id: "patient_date",
    type: "date_signed",
    page: 3,
    rect: { x: 330, y: 560, w: 120, h: 24 },
    required: true,
    label: "Date signed",
    role: "patient",
  },
  {
    id: "witness_sig",
    type: "signature",
    page: 3,
    rect: { x: 72, y: 440, w: 220, h: 48 },
    required: true,
    label: "Witness signature",
    role: "witness",
  },
  {
    id: "clinician_sig",
    type: "signature",
    page: 3,
    rect: { x: 72, y: 320, w: 220, h: 48 },
    required: true,
    label: "Clinician signature",
    role: "clinician",
  },
  {
    id: "clinician_date",
    type: "date_signed",
    page: 3,
    rect: { x: 330, y: 320, w: 120, h: 24 },
    required: true,
    label: "Date signed",
    role: "clinician",
  },
];

// --------------------------------------------------------------------------- one-page order

/**
 * The shape of document a signing queue is made of (addendum 3 B): one page, one signature, and
 * the clinician has twenty of them. Everything this addendum saves is saved here -- a queue of
 * thirty-page reports was never the case it was written for.
 */
export const orderFields: MockField[] = [
  {
    id: "clinician_sig",
    type: "signature",
    page: 1,
    rect: { x: 72, y: 300, w: 220, h: 48 },
    required: true,
    label: "Clinician signature",
    role: "clinician",
  },
  {
    id: "clinician_date",
    type: "date_signed",
    page: 1,
    rect: { x: 330, y: 300, w: 120, h: 24 },
    required: true,
    label: "Date signed",
    role: "clinician",
  },
];

export function orderPdf(sealed = false): Uint8Array {
  const page = new PageWriter();
  header(page, "Order for imaging", 1, 1);
  // Plain ASCII only: this stand-in writes bytes straight into the PDF, so a typographic dash or
  // a middot would reach the page as mojibake and make the sample look broken.
  let y = page.paragraph(72, 650, 11, [
    "Patient: R. P. (sample) - MRN 00-114-2 (sample) - ordered by the attending clinician.",
    "",
    "Chest radiograph, two views, to be performed before discharge. Clinical question: rule out",
    "consolidation. No contrast. Standing precautions apply.",
  ]);
  y = page.paragraph(72, y - 24, 11, [
    "By signing this order you confirm that it reflects your clinical decision for this patient",
    "and that you have reviewed the details above.",
  ]);
  signatureBlock(page, 300, "Clinician", sealed ? "Dr. Priya Raman" : undefined);
  if (sealed) {
    page.text(
      72,
      80,
      9,
      "Sealed copy (mock). Certificate of completion follows in the real service.",
    );
  }
  return buildPdf([page]);
}

export function procedurePdf(options: { earlierSigned: boolean; sealed?: boolean }): Uint8Array {
  const p1 = new PageWriter();
  header(p1, "Consent to procedure", 1, 3);
  let y = p1.paragraph(72, 650, 11, FILLER);
  p1.text(72, y - 12, 13, "What will happen", "bold");
  y = p1.paragraph(72, y - 36, 11, [...FILLER, ...FILLER]);
  p1.text(72, 310, 11, "The risks of this procedure have been explained to me.");
  p1.box(470, 300, 70, 30);
  p1.text(470, 288, 9, "Initials");
  if (options.earlierSigned) {
    p1.text(488, 309, 14, "MA");
  }

  const p2 = new PageWriter();
  header(p2, "Risks and alternatives", 2, 3);
  y = p2.paragraph(72, 650, 11, [...FILLER, ...FILLER]);
  p2.text(72, 452, 11, "Anything you would like to ask before the procedure:");
  p2.box(72, 380, 468, 60);

  const p3 = new PageWriter();
  header(p3, "Signatures", 3, 3);
  p3.paragraph(72, 650, 11, ["Sign below only when your questions have been answered."]);
  signatureBlock(p3, 560, "Patient", options.earlierSigned ? "Maria Alvarez" : undefined);
  signatureBlock(p3, 440, "Witness", options.earlierSigned ? "Tom Okafor" : undefined);
  signatureBlock(p3, 320, "Clinician", options.sealed ? "Dr. Priya Raman" : undefined);
  if (options.sealed) {
    p3.text(
      72,
      80,
      9,
      "Sealed copy (mock). Certificate of completion follows in the real service.",
    );
  }
  return buildPdf([p1, p2, p3]);
}

// --------------------------------------------------------------------------- long generated report

/** How many pages the report has: the shape of the packets a full-screen host signs one after another. */
export const REPORT_PAGES = 22;

export const reportFields: MockField[] = [
  {
    id: "clinician_sig",
    type: "signature",
    page: REPORT_PAGES,
    rect: { x: 72, y: 300, w: 220, h: 48 },
    required: true,
    label: "Attending clinician signature",
    role: "clinician",
  },
  {
    id: "clinician_date",
    type: "date_signed",
    page: REPORT_PAGES,
    rect: { x: 330, y: 300, w: 120, h: 24 },
    required: true,
    label: "Date signed",
    role: "clinician",
  },
];

/**
 * A long report of the kind an EHR generates for one patient and asks a clinician to sign at the
 * end: many pages, dense text, tables drawn as rules, and the signature on the last page. This is
 * what the reading progress and the render budget were built against.
 */
export function reportPdf(sealed = false): Uint8Array {
  const pages: PageWriter[] = [];
  for (let n = 1; n <= REPORT_PAGES; n += 1) {
    const page = new PageWriter();
    header(page, n === 1 ? "Discharge summary (sample)" : `Section ${n - 1}`, n, REPORT_PAGES);
    let y = 650;
    for (let block = 0; block < 4 && y > 200; block += 1) {
      page.text(72, y, 12, `${n}.${block + 1}  Findings and course`, "bold");
      y = page.paragraph(72, y - 20, 10, [...FILLER, ...FILLER], 14);
      // A ruled table, so the page is not only text.
      for (let row = 0; row < 4; row += 1) {
        page.line(72, y - row * 16, 540, y - row * 16);
        page.text(78, y - row * 16 + 4, 9, `Observation ${row + 1}`);
        page.text(300, y - row * 16 + 4, 9, "within expected range (sample)");
      }
      page.line(72, y - 64, 540, y - 64);
      y -= 92;
    }
    if (n === REPORT_PAGES) {
      page.paragraph(72, 360, 11, [
        "By signing this report you confirm that it reflects your clinical assessment of this",
        "patient and that you have reviewed every section above.",
      ]);
      signatureBlock(page, 300, "Attending clinician", sealed ? "Dr. Priya Raman" : undefined);
      if (sealed) {
        page.text(
          72,
          80,
          9,
          "Sealed copy (mock). Certificate of completion follows in the real service.",
        );
      }
    }
    pages.push(page);
  }
  return buildPdf(pages);
}
