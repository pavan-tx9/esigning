import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type Ref, useId, useImperativeHandle, useState } from "react";
import { SignaturePad } from "@/components/SignaturePad";
import { Button, CheckRow, Notice, Sheet, useAnnounce } from "@/components/ui";
import { type AdoptedSignature, type Draft, type SavedLook, savedLook } from "@/flow/draft";
import {
  isNetworkError,
  postRevokeAdoptedSignature,
  type SavedSignature,
  type SigningSession,
  signingKeys,
} from "@/lib/signing-api";
import { exportSignaturePng, inkProblem, type Stroke } from "@/lib/strokes";
import { calendarDate } from "@/lib/time";

/**
 * "Your signature", at the top of the Sign screen (addendum 3 A 1). It used to be a screen of its
 * own between agreeing and placing marks, which meant a clinician with a signature already on file
 * had to look at a whole screen to say "yes, that one".
 *
 * Nothing about the evidence changed. The signature is still *chosen* here and *placed* by an
 * explicit act per field: this panel only says what will be placed, and hands it over when a
 * field asks for it.
 */

/** The ways to make a signature here and now. A saved one is a tab beside these, not among them. */
type Method = "drawn" | "typed" | "click";

const METHODS: { kind: Method; title: string; detail: string }[] = [
  { kind: "drawn", title: "Draw it", detail: "With your finger, a stylus or a mouse." },
  { kind: "typed", title: "Type it", detail: "Type your name and we'll set it in handwriting." },
  { kind: "click", title: "Use my printed name", detail: "No drawing or typing needed." },
];

const cardClass = (selected: boolean) =>
  `flex min-h-14 cursor-pointer items-start gap-3 rounded-lg bg-sheet p-4 text-left ring-[1.5px] ring-inset transition-colors ${
    selected ? "bg-accent-wash ring-accent-600" : "ring-edge-strong hover:bg-sunk"
  }`;

export interface SignaturePanelHandle {
  /**
   * Hand over whatever the panel is showing, so a field can place it. Returns null after saying
   * on screen why it cannot -- an empty pad, a name too short to be one -- which is the same
   * refusal the old "Use this signature" button made, moved to the act that needs it.
   */
  commit: () => AdoptedSignature | null;
}

interface SignaturePanelProps {
  session: SigningSession;
  draft: Draft;
  /** Whether this document has a signature field: initials alone leave nothing to save. */
  hasSignatureField: boolean;
  needsInitials: boolean;
  /**
   * True when the signer is back here because the saved signature they applied was no longer
   * available when they tried to sign (SPEC section 14 B). Nothing has been signed and nothing
   * they filled in is lost: all that is needed is a signature to use instead.
   */
  signatureGone: boolean;
  onDraft: (draft: Draft) => void;
  ref?: Ref<SignaturePanelHandle>;
}

export function SignaturePanel({
  session,
  draft,
  hasSignatureField,
  needsInitials,
  signatureGone,
  onDraft,
  ref,
}: SignaturePanelProps) {
  const kiosk = session.session.kiosk;
  // A shared tablet is never offered a saved signature, whatever the payload says.
  const saved: SavedSignature | null = kiosk ? null : session.adopted_signature;
  const locale = session.consent.locale;
  const queryClient = useQueryClient();
  const announce = useAnnounce();

  const [asked, setChoosing] = useState(() => saved === null && draft.adopted === null);
  const [method, setMethod] = useState<Method>(
    draft.adopted !== null && draft.adopted.kind !== "adopted" ? draft.adopted.kind : "drawn",
  );
  const [strokes, setStrokes] = useState<Stroke[]>([]);
  const [typed, setTyped] = useState(draft.adopted?.kind === "typed" ? draft.adopted.text : "");
  const [removing, setRemoving] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const ids = {
    error: useId(),
    typed: useId(),
    initials: useId(),
    padHelp: useId(),
    save: useId(),
  };

  const setInitials = (value: string) => {
    onDraft({ ...draft, initials: value });
    setProblem(null);
  };
  const setSave = (value: boolean) => onDraft({ ...draft, save: value });

  const revoke = useMutation({
    mutationFn: postRevokeAdoptedSignature,
    onSuccess: async () => {
      // The server's word for it: the refetched session no longer offers one.
      await queryClient.invalidateQueries({ queryKey: signingKeys.session });
      setRemoving(false);
      setChoosing(true);
      setProblem(null);
      announce("Your saved signature has been removed.");
    },
  });

  /**
   * What the panel is showing right now, whether or not it has been handed to a field yet: the
   * signature already chosen, or -- with nothing chosen -- the one on file, which is the whole
   * saving of taps for a clinician working a queue.
   */
  const showing: AdoptedSignature | null =
    draft.adopted !== null
      ? draft.adopted
      : saved !== null
        ? { kind: "adopted", id: saved.id, look: savedLook(saved) }
        : null;

  /**
   * Whether the chooser is open. It is open when the signer asked for it *and* whenever there is
   * nothing to show -- a saved signature revoked under them leaves nothing to preview, and a
   * panel with neither a preview nor a chooser would be a dead end.
   */
  const choosing = asked || showing === null;

  // Offered whenever a signature is being *made* here by drawing or typing -- a first-time signer
  // as much as one replacing what they saved -- never on a shared tablet, and never where this
  // document has no signature field for it to land in.
  const madeHere = choosing
    ? method === "drawn" || method === "typed"
    : draft.adopted?.kind === "drawn" || draft.adopted?.kind === "typed";
  const canSave = !kiosk && hasSignatureField && madeHere;

  function commit(): AdoptedSignature | null {
    if (removing) {
      setProblem("Please decide about your saved signature first: remove it, or keep it.");
      return null;
    }
    if (needsInitials && draft.initials.trim() === "") {
      setProblem("Please enter your initials.");
      return null;
    }
    if (!choosing) {
      return showing;
    }
    if (method === "drawn") {
      const issue = inkProblem(strokes);
      if (issue === "empty") {
        setProblem(
          "The box is empty. Draw your signature in it, or choose to type it or use your printed name.",
        );
        return null;
      }
      if (issue === "too_small") {
        setProblem("That's too small to read as a signature. Please draw it a little larger.");
        return null;
      }
      try {
        const png = exportSignaturePng(strokes);
        setChoosing(false);
        setProblem(null);
        return { kind: "drawn", dataUrl: png.dataUrl, base64: png.base64 };
      } catch {
        setProblem(
          "We couldn't save the drawing on this device. Please type your name or use your printed name instead.",
        );
        return null;
      }
    }
    if (method === "typed") {
      const text = typed.trim().replace(/\s+/g, " ");
      if (text.length < 2) {
        setProblem("Please type your full name.");
        return null;
      }
      setChoosing(false);
      setProblem(null);
      return { kind: "typed", text };
    }
    setChoosing(false);
    setProblem(null);
    return { kind: "click" };
  }

  // No dependency list on purpose: `commit` reads this render's state, and a handle frozen at
  // mount would hand a field the signature the panel showed when the screen opened.
  useImperativeHandle(ref, (): SignaturePanelHandle => ({ commit }));

  return (
    <Sheet testId="signature-panel">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <h2 className="text-ink-900 text-xl">Your signature</h2>
        {!choosing && showing !== null ? (
          <Button
            variant="secondary"
            onClick={() => {
              setChoosing(true);
              setProblem(null);
              announce("Choose a signature.");
            }}
          >
            Change
          </Button>
        ) : null}
      </div>

      {signatureGone ? (
        <Notice tone="warn" alert className="mt-4">
          <p className="font-semibold" data-testid="signature-gone">
            Your saved signature is no longer available.
          </p>
          <p className="mt-1">
            It was removed or replaced, so it couldn't be used. Nothing has been signed and nothing
            else you filled in is lost. Please choose a signature below and place it again.
          </p>
        </Notice>
      ) : null}

      {!choosing && showing !== null ? (
        <div className="mt-4" data-testid="signature-showing">
          <Preview adopted={showing} displayName={session.signer.display_name} />
          {showing.kind === "adopted" && saved !== null ? (
            <p className="mt-2 text-ink-700 text-sm" data-testid="saved-signature">
              Saved {saved.kind === "drawn" ? "drawing" : "name"} · kept from{" "}
              {calendarDate(saved.created_at, locale)} · only you can use it
            </p>
          ) : (
            <p className="mt-2 text-ink-700 text-sm">
              This is what will go in each signature box you sign.
            </p>
          )}
        </div>
      ) : null}

      {choosing ? (
        <div className="mt-4">
          <fieldset className="m-0 border-0 p-0">
            <legend className="mb-3 font-semibold text-ink-900">
              {saved !== null ? "Sign with" : "How would you like to sign?"}
            </legend>
            <div className={`grid gap-3 ${saved === null ? "sm:grid-cols-3" : "sm:grid-cols-2"}`}>
              {saved !== null ? (
                <label className={cardClass(false)}>
                  <input
                    type="radio"
                    name="signature-method"
                    value="saved"
                    checked={false}
                    onChange={() => {
                      // Back to the signature on file: nothing is placed, it is simply what the
                      // panel shows again, exactly as it did before "Change" was pressed.
                      onDraft({ ...draft, save: false });
                      setChoosing(false);
                      setProblem(null);
                    }}
                    className="mt-1 size-5 shrink-0 accent-accent-600"
                  />
                  <span>
                    <span className="block font-semibold text-ink-900">My saved signature</span>
                    <span className="block text-ink-700 text-sm leading-snug">
                      The one kept from last time.
                    </span>
                  </span>
                </label>
              ) : null}
              {METHODS.map((option) => {
                const selected = method === option.kind;
                return (
                  <label key={option.kind} className={cardClass(selected)}>
                    <input
                      type="radio"
                      name="signature-method"
                      value={option.kind}
                      checked={selected}
                      onChange={() => {
                        setMethod(option.kind);
                        setProblem(null);
                      }}
                      className="mt-1 size-5 shrink-0 accent-accent-600"
                    />
                    <span>
                      <span className="block font-semibold text-ink-900">{option.title}</span>
                      <span className="block text-ink-700 text-sm leading-snug">
                        {option.detail}
                      </span>
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
                  Draw your signature in the box. If drawing is awkward, typing your name or using
                  your printed name counts exactly the same.
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
                  {session.signer.display_name}
                </p>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      {/* Only a signature made here can be kept, and never from a shared tablet: a patient on
          a clinic kiosk must not leave their signature behind. Off by default, always. */}
      {canSave ? (
        <div className="mt-5" data-testid="save-signature">
          <CheckRow checked={draft.save} onChange={setSave} describedBy={ids.save}>
            Save this signature for next time
          </CheckRow>
          <p id={ids.save} className="mt-2 text-ink-700 text-sm">
            It will be offered the next time you sign with this clinic. Only you can use it, and you
            can remove it whenever you like.
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
            value={draft.initials}
            maxLength={4}
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            onChange={(event) => setInitials(event.target.value)}
            className="block min-h-12 w-28 rounded-lg bg-sheet px-4 py-2.5 text-ink-900 text-lg ring-[1.5px] ring-edge-strong ring-inset"
          />
          <p className="mt-1 text-ink-700 text-sm">Used where the document asks for initials.</p>
        </div>
      ) : null}

      {saved !== null ? (
        <div className="mt-5 border-edge border-t pt-4">
          <Button
            variant="quiet"
            className="px-0"
            aria-expanded={removing}
            onClick={() => {
              setRemoving(!removing);
              revoke.reset();
              setProblem(null);
            }}
          >
            {removing ? "Keep my saved signature" : "Remove my saved signature"}
          </Button>
          {removing ? (
            <div
              className="mt-3 rounded-lg bg-warn-wash px-4 py-4 ring-1 ring-warn-edge"
              data-testid="remove-saved"
            >
              <p className="font-semibold text-ink-900">Remove your saved signature?</p>
              <p className="mt-1 text-ink-700">
                It won't be offered again, here or next time. You can save a new one whenever you
                sign. Documents you have already signed with it are not affected.
              </p>
              {revoke.isError ? (
                <Notice tone="error" alert className="mt-3">
                  {isNetworkError(revoke.error)
                    ? "We couldn't reach the server. Check the connection and try again, or carry on: you can still sign without it."
                    : "We couldn't remove it just now. You can still sign without using it, and try again later."}
                </Notice>
              ) : null}
              <div className="mt-4 flex flex-wrap gap-3">
                <Button
                  variant="danger"
                  busy={revoke.isPending}
                  onClick={() => {
                    // The marks made with it go too: they would stand for a signature that is
                    // about to stop existing.
                    onDraft({ ...draft, adopted: null, save: false, values: withoutMarks(draft) });
                    revoke.mutate();
                  }}
                >
                  {revoke.isPending ? "Removing" : revoke.isError ? "Try again" : "Remove it"}
                </Button>
                <Button
                  variant="secondary"
                  inert={revoke.isPending}
                  onClick={() => setRemoving(false)}
                >
                  Keep it
                </Button>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      {problem ? (
        <p id={ids.error} role="alert" className="mt-4 font-medium text-danger-600">
          {problem}
        </p>
      ) : null}
    </Sheet>
  );
}

const withoutMarks = (draft: Draft) =>
  Object.fromEntries(Object.entries(draft.values).filter(([, value]) => value.type !== "mark"));

function Preview({ adopted, displayName }: { adopted: AdoptedSignature; displayName: string }) {
  if (adopted.kind === "click") {
    return (
      <div className="signature-line flex h-28 items-center justify-center overflow-hidden rounded-lg bg-sunk px-4 ring-1 ring-edge">
        <span className="truncate pb-4 font-semibold text-2xl text-pen">{displayName}</span>
      </div>
    );
  }
  const look: SavedLook = adopted.kind === "adopted" ? adopted.look : adopted;
  return (
    <div className="signature-line flex h-28 items-center justify-center overflow-hidden rounded-lg bg-sunk px-4 ring-1 ring-edge">
      {look.kind === "drawn" ? (
        <img
          src={look.dataUrl}
          alt="Your signature, as drawn"
          className="max-h-20 max-w-full object-contain pb-3 dark:invert dark:hue-rotate-180"
        />
      ) : (
        <span className="truncate pb-4 font-script text-4xl text-pen">{look.text}</span>
      )}
    </div>
  );
}
