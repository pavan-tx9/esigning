import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { SignaturePad } from "@/components/SignaturePad";
import { Button, CheckRow, Notice, useAnnounce } from "@/components/ui";
import { type AdoptedSignature, type SavedLook, savedLook } from "@/flow/draft";
import {
  isNetworkError,
  postRevokeAdoptedSignature,
  type SavedSignature,
  signingKeys,
} from "@/lib/signing-api";
import { exportSignaturePng, inkProblem, type Stroke } from "@/lib/strokes";

/** The ways to make a signature here and now. A saved one is chosen above these, not among them. */
type Method = "drawn" | "typed" | "click";

const METHODS: { kind: Method; title: string; detail: string }[] = [
  { kind: "drawn", title: "Draw it", detail: "With your finger, a stylus or a mouse." },
  { kind: "typed", title: "Type it", detail: "Type your name and we'll set it in handwriting." },
  { kind: "click", title: "Use my printed name", detail: "No drawing or typing needed." },
];

/** With a signature on file: use it, make another, or take it off the file. Equal choices. */
type Route = "saved" | "new";

const cardClass = (selected: boolean) =>
  `flex min-h-14 cursor-pointer items-start gap-3 rounded-lg bg-sheet p-4 text-left ring-[1.5px] ring-inset transition-colors ${
    selected ? "bg-accent-wash ring-accent-600" : "ring-edge-strong hover:bg-sunk"
  }`;

function savedOn(iso: string, locale: string): string {
  const options: Intl.DateTimeFormatOptions = { day: "numeric", month: "long", year: "numeric" };
  try {
    return new Intl.DateTimeFormat(locale, options).format(new Date(iso));
  } catch {
    return new Intl.DateTimeFormat(undefined, options).format(new Date(iso));
  }
}

interface AdoptSignatureProps {
  displayName: string;
  needsInitials: boolean;
  /**
   * Whether this signer has a signature field at all. A signer asked only for initials has
   * nothing to save: initials go over as their own typed text, so the server would refuse
   * `save_adopted_signature` with `no_signature_to_save` -- and a box promising to keep a
   * signature that will never be kept is worse than no box.
   */
  hasSignatureField: boolean;
  defaultInitials: string;
  current: AdoptedSignature | null;
  currentInitials: string;
  currentSave: boolean;
  /**
   * The signature this person saved in an earlier session, as the server offers it (SPEC
   * section 14 B). `null` when there is none -- and always `null` on a kiosk, where nothing
   * about a saved signature is shown or sent either way.
   */
  saved: SavedSignature | null;
  kiosk: boolean;
  /** The language the page is in, for the date the signature was saved on. */
  locale: string;
  onAdopt: (adopted: AdoptedSignature, initials: string, save: boolean) => void;
}

export function AdoptSignature({
  displayName,
  needsInitials,
  hasSignatureField,
  defaultInitials,
  current,
  currentInitials,
  currentSave,
  saved: savedFromServer,
  kiosk,
  locale,
  onAdopt,
}: AdoptSignatureProps) {
  // A shared tablet is never offered a saved signature, whatever the payload says.
  const saved = kiosk ? null : savedFromServer;
  const [route, setRoute] = useState<Route>(
    current !== null && current.kind !== "adopted" ? "new" : "saved",
  );
  const [method, setMethod] = useState<Method>(
    current !== null && current.kind !== "adopted" ? current.kind : "drawn",
  );
  const [strokes, setStrokes] = useState<Stroke[]>([]);
  const [typed, setTyped] = useState(current?.kind === "typed" ? current.text : "");
  const [initials, setInitials] = useState(currentInitials || defaultInitials);
  const [save, setSave] = useState(currentSave);
  const [removing, setRemoving] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const ids = {
    error: useId(),
    typed: useId(),
    initials: useId(),
    padHelp: useId(),
    save: useId(),
  };
  const queryClient = useQueryClient();
  const announce = useAnnounce();

  const revoke = useMutation({
    mutationFn: postRevokeAdoptedSignature,
    onSuccess: async () => {
      // The server's word for it: the refetched session no longer offers one.
      await queryClient.invalidateQueries({ queryKey: signingKeys.session });
      setRemoving(false);
      setRoute("new");
      announce("Your saved signature has been removed.");
    },
  });

  const usingSaved = saved !== null && route === "saved";
  // Offered whenever a signature is being *made* here by drawing or typing -- a first-time signer
  // as much as one replacing what they saved -- never on a shared tablet, and never where this
  // document has no signature field for it to land in.
  const canSave =
    !kiosk && hasSignatureField && !usingSaved && (method === "drawn" || method === "typed");

  const choose = (next: Method) => {
    setMethod(next);
    setProblem(null);
  };

  const adopt = () => {
    if (needsInitials && initials.trim() === "") {
      setProblem("Please enter your initials.");
      return;
    }
    if (usingSaved) {
      onAdopt({ kind: "adopted", id: saved.id, look: savedLook(saved) }, initials.trim(), false);
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
        onAdopt(
          { kind: "drawn", dataUrl: png.dataUrl, base64: png.base64 },
          initials.trim(),
          canSave && save,
        );
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
      onAdopt({ kind: "typed", text }, initials.trim(), canSave && save);
      return;
    }
    onAdopt({ kind: "click" }, initials.trim(), false);
  };

  return (
    <div>
      {saved !== null ? (
        <SavedChoice
          saved={saved}
          locale={locale}
          route={route}
          removing={removing}
          busy={revoke.isPending}
          failed={revoke.isError ? (isNetworkError(revoke.error) ? "network" : "server") : null}
          onRoute={(next) => {
            setRoute(next);
            setRemoving(false);
            revoke.reset();
            setProblem(null);
          }}
          onRemove={() => {
            setRemoving(true);
            revoke.reset();
          }}
          onKeep={() => {
            setRemoving(false);
            revoke.reset();
          }}
          onConfirmRemove={() => revoke.mutate()}
        />
      ) : null}

      {usingSaved ? null : (
        <fieldset className={`m-0 border-0 p-0 ${saved !== null ? "mt-8" : ""}`}>
          <legend className="mb-3 font-semibold text-ink-900 text-lg">
            {saved !== null
              ? "How would you like to make the new one?"
              : "How would you like to sign?"}
          </legend>
          <div className="grid gap-3 sm:grid-cols-3">
            {METHODS.map((option) => {
              const selected = method === option.kind;
              return (
                <label key={option.kind} className={cardClass(selected)}>
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
      )}

      <div className="mt-5">
        {!usingSaved && method === "drawn" ? (
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

        {!usingSaved && method === "typed" ? (
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

        {!usingSaved && method === "click" ? (
          <div className="rounded-lg bg-sheet p-5 ring-1 ring-edge">
            <p className="text-ink-700">
              Each signature box will show your name, printed like this:
            </p>
            <p className="signature-line mt-2 flex h-24 items-center justify-center pb-4 font-semibold text-2xl text-pen">
              {displayName}
            </p>
          </div>
        ) : null}

        {/* Only a signature made here can be kept, and never from a shared tablet: a patient on
            a clinic kiosk must not leave their signature behind. Off by default, always. */}
        {canSave ? (
          <div className="mt-5" data-testid="save-signature">
            <CheckRow checked={save} onChange={setSave} describedBy={ids.save}>
              Save this signature for next time
            </CheckRow>
            <p id={ids.save} className="mt-2 text-ink-700 text-sm">
              It will be offered the next time you sign with this clinic. Only you can use it, and
              you can remove it whenever you like.
              {saved !== null ? " It replaces the one you saved before." : ""}
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
      <Button className="mt-4 w-full sm:w-auto" onClick={adopt} inert={revoke.isPending}>
        Use this signature
      </Button>
    </div>
  );
}

// --------------------------------------------------------------------------- the saved signature

interface SavedChoiceProps {
  saved: SavedSignature;
  locale: string;
  route: Route;
  removing: boolean;
  busy: boolean;
  failed: "network" | "server" | null;
  onRoute: (route: Route) => void;
  onRemove: () => void;
  onKeep: () => void;
  onConfirmRemove: () => void;
}

/**
 * The signature on file, shown before anything else, with the three things that can be done
 * about it given equal weight (SPEC section 14 B). Using it is still one explicit action per
 * field in the next step, exactly as for a signature made here.
 */
function SavedChoice({
  saved,
  locale,
  route,
  removing,
  busy,
  failed,
  onRoute,
  onRemove,
  onKeep,
  onConfirmRemove,
}: SavedChoiceProps) {
  const look = savedLook(saved);
  const removeHint = useId();
  return (
    <fieldset className="m-0 border-0 p-0" data-testid="saved-signature">
      <legend className="mb-3 font-semibold text-ink-900 text-lg">Your saved signature</legend>
      <SavedPreview look={look} />
      <p className="mt-2 text-ink-700 text-sm">
        {saved.kind === "drawn" ? "Drawn" : "Typed"} · saved on {savedOn(saved.created_at, locale)}{" "}
        · only you can use it
      </p>

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <label className={cardClass(route === "saved" && !removing)}>
          <input
            type="radio"
            name="saved-signature"
            value="saved"
            checked={route === "saved" && !removing}
            onChange={() => onRoute("saved")}
            className="mt-1 size-5 shrink-0 accent-accent-600"
          />
          <span>
            <span className="block font-semibold text-ink-900">Use my saved signature</span>
            <span className="block text-ink-700 text-sm leading-snug">
              Ready to place in the next step.
            </span>
          </span>
        </label>
        <label className={cardClass(route === "new" && !removing)}>
          <input
            type="radio"
            name="saved-signature"
            value="new"
            checked={route === "new" && !removing}
            onChange={() => onRoute("new")}
            className="mt-1 size-5 shrink-0 accent-accent-600"
          />
          <span>
            <span className="block font-semibold text-ink-900">Create a new one</span>
            <span className="block text-ink-700 text-sm leading-snug">
              Draw it, type it or use your printed name.
            </span>
          </span>
        </label>
        <button
          type="button"
          className={cardClass(removing)}
          aria-expanded={removing}
          aria-describedby={removeHint}
          onClick={removing ? onKeep : onRemove}
        >
          <RemoveGlyph />
          <span>
            <span className="block font-semibold text-ink-900">Remove saved signature</span>
            <span id={removeHint} className="block text-ink-700 text-sm leading-snug">
              It won't be offered again.
            </span>
          </span>
        </button>
      </div>

      {removing ? (
        <div
          className="mt-4 rounded-lg bg-warn-wash px-4 py-4 ring-1 ring-warn-edge"
          data-testid="remove-saved"
        >
          <p className="font-semibold text-ink-900">Remove your saved signature?</p>
          <p className="mt-1 text-ink-700">
            It won't be offered again, here or next time. You can save a new one whenever you sign.
            Documents you have already signed with it are not affected.
          </p>
          {failed !== null ? (
            <Notice tone="error" alert className="mt-3">
              {failed === "network"
                ? "We couldn't reach the server. Check the connection and try again, or carry on: you can still sign without it."
                : "We couldn't remove it just now. You can still sign without using it, and try again later."}
            </Notice>
          ) : null}
          <div className="mt-4 flex flex-wrap gap-3">
            <Button variant="danger" onClick={onConfirmRemove} busy={busy}>
              {busy ? "Removing" : failed !== null ? "Try again" : "Remove it"}
            </Button>
            <Button variant="secondary" onClick={onKeep} inert={busy}>
              Keep it
            </Button>
          </div>
        </div>
      ) : null}
    </fieldset>
  );
}

function SavedPreview({ look }: { look: SavedLook }) {
  return (
    <div className="signature-line flex h-28 items-center justify-center overflow-hidden rounded-lg bg-sheet px-4 ring-1 ring-edge">
      {look.kind === "drawn" ? (
        <img
          src={look.dataUrl}
          alt="Your saved signature, as drawn"
          className="max-h-20 max-w-full object-contain pb-3 dark:invert dark:hue-rotate-180"
        />
      ) : (
        <span className="truncate pb-4 font-script text-4xl text-pen">{look.text}</span>
      )}
    </div>
  );
}

/** Sits where the radio circle sits on the two cards beside it, so the three read as one row. */
function RemoveGlyph() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 20 20"
      className="mt-1 size-5 shrink-0 fill-none stroke-ink-700"
      strokeWidth="1.8"
    >
      <circle cx="10" cy="10" r="7.25" />
      <path d="M6.75 10h6.5" strokeLinecap="round" />
    </svg>
  );
}
