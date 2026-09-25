import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type Ref, useEffect, useId, useImperativeHandle, useRef, useState } from "react";
import { SignaturePad } from "@/components/SignaturePad";
import {
  Button,
  CheckRow,
  Notice,
  prefersReducedMotion,
  Sheet,
  useAnnounce,
} from "@/components/ui";
import {
  type AdoptedSignature,
  type Draft,
  type SavedLook,
  savedLook,
  withoutInitialsMarks,
} from "@/flow/draft";
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
 * "Your signature", at the top of the Sign panel (addendum 3 A 1). It used to be a screen of its
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

/**
 * The answer to "what should I place?". A refusal carries its own sentence so the caller can say
 * it where the press happened as well: the panel can be a screen away from the field's button on
 * a phone, and a message nobody scrolls to is a press that appeared to do nothing.
 */
export type PanelChoice = { ok: true; adopted: AdoptedSignature } | { ok: false; reason: string };

export interface SignaturePanelHandle {
  /**
   * Hand over whatever the panel is showing, so a field can place it. Refuses -- saying why, on
   * screen and to the caller -- when there is nothing to hand over: an empty pad, a name too short
   * to be one. That is the refusal the old "Use this signature" button made, moved to the act that
   * needs it.
   */
  commit: () => PanelChoice;
  /**
   * Ink drawn or a name typed in the chooser that has not been placed in any field yet. The
   * signature that gets signed is the one in the draft, so a press of "Sign as ..." while this is
   * true would quietly sign something other than what the panel is showing.
   */
  uncommitted: () => boolean;
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

const inputClass =
  "block min-h-11 w-full rounded-md bg-sheet px-3 py-2 text-ink-900 ring-1 ring-edge-strong ring-inset";

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
  /**
   * What was last handed to a field, so ink still on the pad can be told apart from ink already
   * placed. Reference equality is enough: `SignaturePad` hands up a new array on every change.
   */
  const placed = useRef<{ strokes: Stroke[] | null; typed: string | null }>({
    strokes: null,
    typed: null,
  });
  const refusal = useRef<HTMLParagraphElement>(null);
  const ids = {
    error: useId(),
    typed: useId(),
    initials: useId(),
    padHelp: useId(),
    save: useId(),
  };

  /**
   * An initials mark stands for this text, so emptying the box un-places them: a row that goes on
   * saying "Initials in place" over an empty box is the screen contradicting itself, and the
   * submission it describes is one the server refuses.
   */
  const setInitials = (value: string) => {
    const next = { ...draft, initials: value };
    onDraft(value.trim() === "" ? withoutInitialsMarks(next, session.fields) : next);
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

  const refuse = (reason: string): PanelChoice => {
    setProblem(reason);
    return { ok: false, reason };
  };

  function commit(): PanelChoice {
    if (removing) {
      return refuse("Please decide about your saved signature first: remove it, or keep it.");
    }
    if (needsInitials && draft.initials.trim() === "") {
      return refuse("Please enter your initials.");
    }
    if (!choosing) {
      return showing === null
        ? refuse("Please choose a signature first.")
        : { ok: true, adopted: showing };
    }
    if (method === "drawn") {
      const issue = inkProblem(strokes);
      if (issue === "empty") {
        return refuse(
          "The box is empty. Draw your signature in it, or choose to type it or use your printed name.",
        );
      }
      if (issue === "too_small") {
        return refuse("That's too small to read as a signature. Please draw it a little larger.");
      }
      try {
        const png = exportSignaturePng(strokes);
        placed.current.strokes = strokes;
        setChoosing(false);
        setProblem(null);
        return { ok: true, adopted: { kind: "drawn", dataUrl: png.dataUrl, base64: png.base64 } };
      } catch {
        return refuse(
          "We couldn't save the drawing on this device. Please type your name or use your printed name instead.",
        );
      }
    }
    if (method === "typed") {
      const text = typed.trim().replace(/\s+/g, " ");
      if (text.length < 2) {
        return refuse("Please type your full name.");
      }
      placed.current.typed = text;
      setChoosing(false);
      setProblem(null);
      return { ok: true, adopted: { kind: "typed", text } };
    }
    setChoosing(false);
    setProblem(null);
    return { ok: true, adopted: { kind: "click" } };
  }

  /** Something made here and now that no field is carrying yet. */
  function uncommitted(): boolean {
    if (!choosing) {
      return false;
    }
    if (method === "drawn") {
      return strokes.length > 0 && strokes !== placed.current.strokes;
    }
    if (method === "typed") {
      const text = typed.trim().replace(/\s+/g, " ");
      return text !== "" && text !== placed.current.typed;
    }
    return false;
  }

  // No dependency list on purpose: `commit` reads this render's state, and a handle frozen at
  // mount would hand a field the signature the panel showed when the screen opened.
  useImperativeHandle(ref, (): SignaturePanelHandle => ({ commit, uncommitted }));

  /**
   * The refusal is at the foot of a panel that can be a whole screen tall, and the press that
   * caused it happened at a field's own button below it. Bring it to the signer. Optional call:
   * this is a convenience, and a runtime without it must not take the screen down on the one path
   * where something has already gone wrong.
   */
  useEffect(() => {
    if (problem !== null) {
      refusal.current?.scrollIntoView?.({
        block: "center",
        behavior: prefersReducedMotion() ? "auto" : "smooth",
      });
    }
  }, [problem]);

  const activeMethod = METHODS.find((option) => option.kind === method);

  return (
    <Sheet testId="signature-panel" className="p-3">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-ink-900 text-sm">Your signature</h2>
        {!choosing && showing !== null ? (
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              setChoosing(true);
              setProblem(null);
              // Choosing again makes every placed mark stale: it stands for the signature being
              // replaced. They come off, so each field asks to be signed again with whatever is
              // chosen now -- and so the screen can never show one signature while carrying
              // another into the submission.
              const placedMarks = Object.values(draft.values).some(
                (value) => value.type === "mark",
              );
              if (placedMarks) {
                onDraft({ ...draft, values: withoutMarks(draft) });
              }
              announce(
                placedMarks
                  ? "Choose a signature. What you placed has been taken off, so you can place the new one."
                  : "Choose a signature.",
              );
            }}
          >
            Change
          </Button>
        ) : null}
      </div>

      {signatureGone ? (
        <Notice tone="warn" alert className="mt-2">
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
        <div className="mt-2" data-testid="signature-showing">
          <Preview adopted={showing} displayName={session.signer.display_name} />
          {showing.kind === "adopted" && saved !== null ? (
            <p className="mt-1.5 text-ink-700 text-xs" data-testid="saved-signature">
              Saved {saved.kind === "drawn" ? "drawing" : "name"} · kept from{" "}
              {calendarDate(saved.created_at, locale)} · only you can use it
            </p>
          ) : (
            <p className="mt-1.5 text-ink-700 text-xs">
              This is what will go in each signature box you sign.
            </p>
          )}
        </div>
      ) : null}

      {choosing ? (
        <div className="mt-2">
          <fieldset className="m-0 border-0 p-0">
            <legend className="sr-only">
              {saved !== null ? "Sign with" : "How would you like to sign?"}
            </legend>
            {/* A segmented row rather than three cards with a sentence each: the sentence for
                the chosen way is printed once, under the row, where it is needed. */}
            <div className="flex gap-1 rounded-md bg-sunk p-1" role="presentation">
              {saved !== null ? (
                <label className={segmentClass(false)}>
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
                    className="absolute inset-0 cursor-pointer appearance-none rounded"
                  />
                  My saved signature
                </label>
              ) : null}
              {METHODS.map((option) => {
                const selected = method === option.kind;
                return (
                  <label key={option.kind} className={segmentClass(selected)}>
                    <input
                      type="radio"
                      name="signature-method"
                      value={option.kind}
                      checked={selected}
                      onChange={() => {
                        setMethod(option.kind);
                        setProblem(null);
                      }}
                      className="absolute inset-0 cursor-pointer appearance-none rounded"
                    />
                    {option.title}
                  </label>
                );
              })}
            </div>
          </fieldset>

          <div className="mt-2">
            {method === "drawn" ? (
              <>
                <p id={ids.padHelp} className="mb-1.5 text-ink-700 text-xs">
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
                <label
                  htmlFor={ids.typed}
                  className="mb-1 block font-semibold text-ink-900 text-sm"
                >
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
                  aria-describedby={problem ? ids.error : ids.padHelp}
                  onChange={(event) => {
                    setTyped(event.target.value);
                    setProblem(null);
                  }}
                  className={inputClass}
                />
                <p id={ids.padHelp} className="sr-only">
                  {activeMethod?.detail}
                </p>
                <div
                  aria-hidden="true"
                  className="signature-line mt-2 flex h-20 items-center justify-center overflow-hidden rounded-md bg-sheet px-3 ring-1 ring-edge"
                >
                  <span className="truncate pb-3 font-script text-3xl text-pen">
                    {typed.trim() || " "}
                  </span>
                </div>
              </div>
            ) : null}

            {method === "click" ? (
              <div className="rounded-md bg-sheet p-3 ring-1 ring-edge">
                <p className="text-ink-700 text-xs">
                  Each signature box will show your name, printed like this:
                </p>
                <p className="signature-line mt-1 flex h-16 items-center justify-center pb-3 font-semibold text-pen text-xl">
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
        <div className="mt-2" data-testid="save-signature">
          <CheckRow checked={draft.save} onChange={setSave} describedBy={ids.save}>
            <span className="text-sm">Save this signature for next time</span>
          </CheckRow>
          <p id={ids.save} className="mt-1 px-1 text-ink-700 text-xs">
            Offered the next time you sign with this clinic. Only you can use it, and you can remove
            it whenever you like.
            {saved !== null ? " It replaces the one you saved before." : ""}
          </p>
        </div>
      ) : null}

      {needsInitials ? (
        <div className="mt-2 flex items-center gap-3">
          <label htmlFor={ids.initials} className="font-semibold text-ink-900 text-sm">
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
            className={`${inputClass} w-24`}
          />
          <p className="text-ink-700 text-xs">Used where the document asks for initials.</p>
        </div>
      ) : null}

      {saved !== null ? (
        <div className="mt-2 border-edge border-t pt-2">
          <Button
            variant="quiet"
            size="sm"
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
              className="mt-2 rounded-md bg-warn-wash px-3 py-2.5 text-sm ring-1 ring-warn-edge"
              data-testid="remove-saved"
            >
              <p className="font-semibold text-ink-900">Remove your saved signature?</p>
              <p className="mt-1 text-ink-700">
                It won't be offered again, here or next time. You can save a new one whenever you
                sign. Documents you have already signed with it are not affected.
              </p>
              {revoke.isError ? (
                <Notice tone="error" alert className="mt-2">
                  {isNetworkError(revoke.error)
                    ? "We couldn't reach the server. Check the connection and try again, or carry on: you can still sign without it."
                    : "We couldn't remove it just now. You can still sign without using it, and try again later."}
                </Notice>
              ) : null}
              <div className="mt-2 flex flex-wrap gap-2">
                <Button
                  variant="danger"
                  size="sm"
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
                  size="sm"
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
        <p
          id={ids.error}
          ref={refusal}
          role="alert"
          data-testid="signature-problem"
          className="mt-2 font-medium text-danger-600 text-sm"
        >
          {problem}
        </p>
      ) : null}
    </Sheet>
  );
}

/**
 * One segment of the chooser. The radio itself is stretched over the whole segment, invisible
 * but on top, so a press anywhere on it is a press on the control -- for a finger, a pointer
 * and a test alike -- and its focus ring is the segment's.
 */
const segmentClass = (selected: boolean) =>
  `relative flex min-h-9 flex-1 cursor-pointer items-center justify-center rounded px-2 text-center font-semibold text-sm leading-tight transition-colors has-[:focus-visible]:outline-3 has-[:focus-visible]:outline-accent-600 ${
    selected ? "bg-sheet text-ink-900 shadow-sheet" : "text-ink-700 hover:text-ink-900"
  }`;

const withoutMarks = (draft: Draft) =>
  Object.fromEntries(Object.entries(draft.values).filter(([, value]) => value.type !== "mark"));

function Preview({ adopted, displayName }: { adopted: AdoptedSignature; displayName: string }) {
  if (adopted.kind === "click") {
    return (
      <div className="signature-line flex h-20 items-center justify-center overflow-hidden rounded-md bg-sunk px-3 ring-1 ring-edge">
        <span className="truncate pb-3 font-semibold text-pen text-xl">{displayName}</span>
      </div>
    );
  }
  const look: SavedLook = adopted.kind === "adopted" ? adopted.look : adopted;
  return (
    <div className="signature-line flex h-20 items-center justify-center overflow-hidden rounded-md bg-sunk px-3 ring-1 ring-edge">
      {look.kind === "drawn" ? (
        <img
          src={look.dataUrl}
          alt="Your signature, as drawn"
          className="max-h-14 max-w-full object-contain pb-2 dark:invert dark:hue-rotate-180"
        />
      ) : (
        <span className="truncate pb-3 font-script text-3xl text-pen">{look.text}</span>
      )}
    </div>
  );
}
