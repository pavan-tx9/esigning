import { useId, useState } from "react";
import { SignaturePad } from "@/components/SignaturePad";
import { Button } from "@/components/ui";
import type { AdoptedSignature } from "@/flow/draft";
import { exportSignaturePng, inkProblem, type Stroke } from "@/lib/strokes";

type Method = AdoptedSignature["kind"];

const METHODS: { kind: Method; title: string; detail: string }[] = [
  { kind: "drawn", title: "Draw it", detail: "With your finger, a stylus or a mouse." },
  { kind: "typed", title: "Type it", detail: "Type your name and we'll set it in handwriting." },
  { kind: "click", title: "Use my printed name", detail: "No drawing or typing needed." },
];

interface AdoptSignatureProps {
  displayName: string;
  needsInitials: boolean;
  defaultInitials: string;
  current: AdoptedSignature | null;
  currentInitials: string;
  onAdopt: (adopted: AdoptedSignature, initials: string) => void;
}

export function AdoptSignature({
  displayName,
  needsInitials,
  defaultInitials,
  current,
  currentInitials,
  onAdopt,
}: AdoptSignatureProps) {
  const [method, setMethod] = useState<Method>(current?.kind ?? "drawn");
  const [strokes, setStrokes] = useState<Stroke[]>([]);
  const [typed, setTyped] = useState(current?.kind === "typed" ? current.text : "");
  const [initials, setInitials] = useState(currentInitials || defaultInitials);
  const [problem, setProblem] = useState<string | null>(null);
  const ids = { error: useId(), typed: useId(), initials: useId(), padHelp: useId() };

  const choose = (next: Method) => {
    setMethod(next);
    setProblem(null);
  };

  const adopt = () => {
    if (needsInitials && initials.trim() === "") {
      setProblem("Please enter your initials.");
      return;
    }
    if (method === "drawn") {
      const issue = inkProblem(strokes);
      if (issue === "empty") {
        setProblem(
          "The box is empty. Draw your signature in it, or choose to type it or use your printed name.",
        );
        return;
      }
      if (issue === "too_small") {
        setProblem("That's too small to read as a signature. Please draw it a little larger.");
        return;
      }
      try {
        const png = exportSignaturePng(strokes);
        onAdopt({ kind: "drawn", dataUrl: png.dataUrl, base64: png.base64 }, initials.trim());
      } catch {
        setProblem(
          "We couldn't save the drawing on this device. Please type your name or use your printed name instead.",
        );
      }
      return;
    }
    if (method === "typed") {
      const text = typed.trim().replace(/\s+/g, " ");
      if (text.length < 2) {
        setProblem("Please type your full name.");
        return;
      }
      onAdopt({ kind: "typed", text }, initials.trim());
      return;
    }
    onAdopt({ kind: "click" }, initials.trim());
  };

  return (
    <div>
      <fieldset className="m-0 border-0 p-0">
        <legend className="mb-3 font-semibold text-ink-900 text-lg">
          How would you like to sign?
        </legend>
        <div className="grid gap-3 sm:grid-cols-3">
          {METHODS.map((option) => {
            const selected = method === option.kind;
            return (
              <label
                key={option.kind}
                className={`flex min-h-14 cursor-pointer items-start gap-3 rounded-lg bg-sheet p-4 ring-[1.5px] ring-inset transition-colors ${
                  selected ? "bg-accent-wash ring-accent-600" : "ring-edge-strong hover:bg-sunk"
                }`}
              >
                <input
                  type="radio"
                  name="signature-method"
                  value={option.kind}
                  checked={selected}
                  onChange={() => choose(option.kind)}
                  className="mt-1 size-5 shrink-0 accent-accent-600"
                />
                <span>
                  <span className="block font-semibold text-ink-900">{option.title}</span>
                  <span className="block text-ink-700 text-sm leading-snug">{option.detail}</span>
                </span>
              </label>
            );
          })}
        </div>
      </fieldset>

      <div className="mt-5">
        {method === "drawn" ? (
          <>
            <p id={ids.padHelp} className="mb-2 text-ink-700">
              Draw your signature in the box. If drawing is awkward, typing your name or using your
              printed name counts exactly the same.
            </p>
            <SignaturePad
              strokes={strokes}
              onChange={(next) => {
                setStrokes(next);
                setProblem(null);
              }}
              describedBy={ids.padHelp}
            />
          </>
        ) : null}

        {method === "typed" ? (
          <div>
            <label htmlFor={ids.typed} className="mb-2 block font-semibold text-ink-900">
              Type your full name
            </label>
            <input
              id={ids.typed}
              type="text"
              value={typed}
              maxLength={80}
              autoComplete="off"
              autoCapitalize="words"
              spellCheck={false}
              aria-describedby={problem ? ids.error : undefined}
              onChange={(event) => {
                setTyped(event.target.value);
                setProblem(null);
              }}
              className="block min-h-12 w-full rounded-lg bg-sheet px-4 py-2.5 text-ink-900 text-lg ring-[1.5px] ring-edge-strong ring-inset"
            />
            <div
              aria-hidden="true"
              className="signature-line mt-3 flex h-28 items-center justify-center overflow-hidden rounded-lg bg-sheet px-4 ring-1 ring-edge"
            >
              <span className="truncate pb-4 font-script text-4xl text-pen">
                {typed.trim() || " "}
              </span>
            </div>
          </div>
        ) : null}

        {method === "click" ? (
          <div className="rounded-lg bg-sheet p-5 ring-1 ring-edge">
            <p className="text-ink-700">
              Each signature box will show your name, printed like this:
            </p>
            <p className="signature-line mt-2 flex h-24 items-center justify-center pb-4 font-semibold text-2xl text-pen">
              {displayName}
            </p>
          </div>
        ) : null}

        {needsInitials ? (
          <div className="mt-5">
            <label htmlFor={ids.initials} className="mb-2 block font-semibold text-ink-900">
              Your initials
            </label>
            <input
              id={ids.initials}
              type="text"
              value={initials}
              maxLength={4}
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              onChange={(event) => {
                setInitials(event.target.value);
                setProblem(null);
              }}
              className="block min-h-12 w-28 rounded-lg bg-sheet px-4 py-2.5 text-ink-900 text-lg ring-[1.5px] ring-edge-strong ring-inset"
            />
            <p className="mt-1 text-ink-700 text-sm">Used where the document asks for initials.</p>
          </div>
        ) : null}
      </div>

      {problem ? (
        <p id={ids.error} role="alert" className="mt-4 font-medium text-danger-600">
          {problem}
        </p>
      ) : null}

      <p className="mt-5 text-ink-700">
        Whichever you choose counts the same as signing by hand. Nothing is added to the document
        until you place it yourself in the next step.
      </p>
      <Button className="mt-4 w-full sm:w-auto" onClick={adopt}>
        Use this signature
      </Button>
    </div>
  );
}
