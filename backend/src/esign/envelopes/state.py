"""Pure transition rules for envelopes and signers.

No database, no clock, no logging, no side effects. Given what the rows currently say and a
command, :func:`decide` answers with the new statuses or a refusal code. Everything that can go
wrong with *ordering and preconditions* is decided here, so it can be enumerated in a table and
tested exhaustively without a Postgres anywhere near it.

The service layer owns everything this module deliberately does not know about: the row lock, the
clock, re-authentication freshness, capture validation, persistence and the audit events.

Refusal codes are stable machine strings. They become ``Conflict.code`` at the API boundary, so
they must stay free of anything that could describe a patient.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Final, assert_never
from uuid import UUID

from esign.contracts import EnvelopeStatus, SignerStatus

__all__ = [
    "FINISHED_SIGNER_STATUSES",
    "LIVE_ENVELOPE_STATUSES",
    "SEAL_BACKOFF_SCHEDULE",
    "Command",
    "Decision",
    "EnvelopeState",
    "Refusal",
    "SignerState",
    "Transition",
    "decide",
    "next_backoff",
]

#: An envelope in one of these statuses can still move. Everything else is terminal.
LIVE_ENVELOPE_STATUSES: Final[frozenset[str]] = frozenset({"created", "in_progress"})

#: A signer in one of these has finished, for better or worse, and takes no further commands.
FINISHED_SIGNER_STATUSES: Final[frozenset[str]] = frozenset({"signed", "declined"})

#: ``pending < viewed < consented < signed``. ``declined`` is off to one side: terminal, not higher.
_SIGNER_RANK: Final[dict[str, int]] = {"pending": 0, "viewed": 1, "consented": 2, "signed": 3, "declined": 3}

#: Why a terminal envelope refused. Distinct codes so a caller can tell "too late" from "cancelled".
_TERMINAL_REFUSAL: Final[dict[str, str]] = {
    "completed_pending_seal": "envelope_already_complete",
    "sealed": "envelope_sealed",
    "declined": "envelope_declined",
    "voided": "envelope_voided",
    "expired": "envelope_expired",
}


class Command(StrEnum):
    """Everything that can be asked of an envelope. One per ``EnvelopeService`` entry point."""

    START_SESSION = "start_session"
    PRESENT = "present"
    VIEW = "view"
    CONSENT = "consent"
    SIGN = "sign"
    DECLINE = "decline"
    VOID = "void"
    EXPIRE = "expire"
    SEAL = "seal"
    SUPERSEDE = "supersede"


#: Commands aimed at one signer. The rest act on the envelope as a whole.
_SIGNER_COMMANDS: Final[frozenset[Command]] = frozenset(
    {Command.START_SESSION, Command.PRESENT, Command.VIEW, Command.CONSENT, Command.SIGN, Command.DECLINE}
)

#: Commands that require the document to have been presented at least once (envelope in_progress).
_NEEDS_PRESENTATION: Final[frozenset[Command]] = frozenset({Command.VIEW, Command.CONSENT, Command.SIGN})


@dataclass(frozen=True)
class SignerState:
    signer_id: UUID
    order_index: int
    status: SignerStatus


@dataclass(frozen=True)
class EnvelopeState:
    status: EnvelopeStatus
    signing_order: str  # "sequential" | "parallel"
    signers: tuple[SignerState, ...]


@dataclass(frozen=True)
class Transition:
    """What the rows should say afterwards.

    ``signer_status`` is ``None`` when the acting signer does not move (presenting the document
    does not advance anyone), and ``envelope_status`` is always the full new status, even when it
    equals the old one, so a caller can write it back unconditionally.
    """

    envelope_status: EnvelopeStatus
    signer_status: SignerStatus | None = None
    completes_envelope: bool = False


@dataclass(frozen=True)
class Refusal:
    """The command is illegal here. Nothing changes; the service raises ``Conflict(code)``."""

    code: str


Decision = Transition | Refusal


def decide(state: EnvelopeState, command: Command, *, signer_id: UUID | None = None) -> Decision:
    """The whole state machine.

    Returns a :class:`Transition` describing the new statuses, or a :class:`Refusal` carrying the
    reason. Never raises: an unknown signer is a refusal like any other, because failing closed on
    a caller's mistake is cheaper than an unhandled exception in a signing flow.
    """
    signer: SignerState | None = None
    if command in _SIGNER_COMMANDS:
        if signer_id is None:
            return Refusal("unknown_signer")
        signer = _find_signer(state, signer_id)
        if signer is None:
            return Refusal("unknown_signer")

    if command is Command.SEAL:
        if state.status == "sealed":
            return Refusal("already_sealed")
        if state.status != "completed_pending_seal":
            return Refusal("not_pending_seal")
        return Transition("sealed")

    if command is Command.SUPERSEDE:
        # Only a sealed envelope can be corrected; anything still live should be voided instead.
        if state.status != "sealed":
            return Refusal("supersedes_not_sealed")
        return Transition("sealed")

    if state.status not in LIVE_ENVELOPE_STATUSES:
        return Refusal(_TERMINAL_REFUSAL.get(state.status, "envelope_not_live"))

    if command is Command.VOID:
        return Transition("voided")
    if command is Command.EXPIRE:
        return Transition("expired")

    assert signer is not None  # every remaining command is in _SIGNER_COMMANDS
    if signer.status == "signed":
        return Refusal("signer_already_signed")
    if signer.status == "declined":
        return Refusal("signer_declined")

    if command is Command.DECLINE:
        # Declining is always open to a live signer: the paper path must never be gated.
        return Transition("declined", "declined")

    if command in _NEEDS_PRESENTATION and state.status == "created":
        return Refusal("not_presented")

    if _out_of_order(state, signer):
        return Refusal("out_of_order")

    if command is Command.START_SESSION:
        return Transition(state.status)

    if command is Command.PRESENT:
        return Transition("in_progress")

    if command is Command.VIEW:
        # Never downgrade: a signer who has already consented stays consented on a repeat view.
        held = signer.status if _SIGNER_RANK[signer.status] >= _SIGNER_RANK["viewed"] else "viewed"
        return Transition("in_progress", held)

    if command is Command.CONSENT:
        if _SIGNER_RANK[signer.status] < _SIGNER_RANK["viewed"]:
            return Refusal("not_viewed")
        return Transition("in_progress", "consented")

    if command is Command.SIGN:
        if signer.status == "pending":
            return Refusal("not_viewed")
        if signer.status == "viewed":
            return Refusal("not_consented")
        others_done = all(other.status == "signed" for other in state.signers if other.signer_id != signer.signer_id)
        if others_done:
            return Transition("completed_pending_seal", "signed", completes_envelope=True)
        return Transition("in_progress", "signed")

    assert_never(command)  # every Command is handled above; mypy enforces it


def _find_signer(state: EnvelopeState, signer_id: UUID) -> SignerState | None:
    return next((s for s in state.signers if s.signer_id == signer_id), None)


def _out_of_order(state: EnvelopeState, signer: SignerState) -> bool:
    """Sequential order: nobody moves until everyone ahead of them has signed."""
    if state.signing_order != "sequential":
        return False
    return any(other.status != "signed" for other in state.signers if other.order_index < signer.order_index)


# --------------------------------------------------------------------------- seal retry schedule

#: SPEC section 3: 1m, 5m, 15m, 1h, then hourly. The last entry repeats forever.
SEAL_BACKOFF_SCHEDULE: Final[tuple[timedelta, ...]] = (
    timedelta(minutes=1),
    timedelta(minutes=5),
    timedelta(minutes=15),
    timedelta(hours=1),
)


def next_backoff(attempts: int) -> timedelta:
    """How long to wait before attempt ``attempts + 1``, given ``attempts`` failures so far.

    ``attempts`` is the number of attempts already made, including the one that just failed, so
    the first failure waits a minute. Anything below 1 is treated as 1 rather than raising: a
    worker that miscounts should still back off, not retry in a tight loop.
    """
    index = max(attempts, 1) - 1
    if index >= len(SEAL_BACKOFF_SCHEDULE):
        return SEAL_BACKOFF_SCHEDULE[-1]
    return SEAL_BACKOFF_SCHEDULE[index]
