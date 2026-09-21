"""The transition rules, exhaustively. No database: these run in a sandbox with no Postgres.

The table below is the specification of SPEC section 3's state diagram in executable form. Every
row names the envelope status, the signers, the command and what should come back. A rule that is
not in this table is not a rule.
"""

from __future__ import annotations

from datetime import timedelta
from itertools import product
from uuid import UUID, uuid4

import pytest

from esign.contracts import EnvelopeStatus, SignerStatus
from esign.envelopes.state import (
    FINISHED_SIGNER_STATUSES,
    LIVE_ENVELOPE_STATUSES,
    Command,
    EnvelopeState,
    Refusal,
    SignerState,
    Transition,
    decide,
    next_backoff,
)

A = UUID("00000000-0000-4000-8000-00000000000a")
B = UUID("00000000-0000-4000-8000-00000000000b")
C = UUID("00000000-0000-4000-8000-00000000000c")

ENVELOPE_STATUSES: tuple[EnvelopeStatus, ...] = (
    "created",
    "in_progress",
    "completed_pending_seal",
    "sealed",
    "declined",
    "voided",
    "expired",
)
SIGNER_STATUSES: tuple[SignerStatus, ...] = ("pending", "viewed", "consented", "signed", "declined")


def solo(status: EnvelopeStatus, signer_status: SignerStatus, order: str = "parallel") -> EnvelopeState:
    return EnvelopeState(status, order, (SignerState(A, 0, signer_status),))


def pair(
    status: EnvelopeStatus,
    first: SignerStatus,
    second: SignerStatus,
    order: str = "parallel",
) -> EnvelopeState:
    return EnvelopeState(status, order, (SignerState(A, 0, first), SignerState(B, 1, second)))


# --------------------------------------------------------------------------- the table

#: (name, state, command, signer, expected). ``expected`` is a Transition or a refusal code.
TABLE: list[tuple[str, EnvelopeState, Command, UUID | None, Transition | str]] = [
    # -- starting a session ------------------------------------------------
    ("session on a fresh envelope", solo("created", "pending"), Command.START_SESSION, A, Transition("created")),
    ("session mid-flow", solo("in_progress", "viewed"), Command.START_SESSION, A, Transition("in_progress")),
    ("session after signing", solo("in_progress", "signed"), Command.START_SESSION, A, "signer_already_signed"),
    ("session after declining", solo("declined", "declined"), Command.START_SESSION, A, "envelope_declined"),
    ("session on a voided envelope", solo("voided", "pending"), Command.START_SESSION, A, "envelope_voided"),
    ("session on an expired envelope", solo("expired", "pending"), Command.START_SESSION, A, "envelope_expired"),
    ("session on a sealed envelope", solo("sealed", "signed"), Command.START_SESSION, A, "envelope_sealed"),
    (
        "session while sealing",
        solo("completed_pending_seal", "signed"),
        Command.START_SESSION,
        A,
        "envelope_already_complete",
    ),
    (
        "sequential: second signer waits",
        pair("in_progress", "viewed", "pending", "sequential"),
        Command.START_SESSION,
        B,
        "out_of_order",
    ),
    (
        "sequential: second signer's turn",
        pair("in_progress", "signed", "pending", "sequential"),
        Command.START_SESSION,
        B,
        Transition("in_progress"),
    ),
    (
        "parallel: second signer need not wait",
        pair("in_progress", "pending", "pending"),
        Command.START_SESSION,
        B,
        Transition("in_progress"),
    ),
    ("unknown signer", solo("in_progress", "pending"), Command.START_SESSION, C, "unknown_signer"),
    ("no signer supplied", solo("in_progress", "pending"), Command.START_SESSION, None, "unknown_signer"),
    # -- presenting --------------------------------------------------------
    ("first presentation starts it", solo("created", "pending"), Command.PRESENT, A, Transition("in_progress")),
    ("presenting again", solo("in_progress", "viewed"), Command.PRESENT, A, Transition("in_progress")),
    ("presenting after signing", solo("in_progress", "signed"), Command.PRESENT, A, "signer_already_signed"),
    (
        "sequential: presenting out of turn",
        pair("in_progress", "pending", "pending", "sequential"),
        Command.PRESENT,
        B,
        "out_of_order",
    ),
    # -- viewing -----------------------------------------------------------
    ("view before presentation", solo("created", "pending"), Command.VIEW, A, "not_presented"),
    ("first view", solo("in_progress", "pending"), Command.VIEW, A, Transition("in_progress", "viewed")),
    ("view again", solo("in_progress", "viewed"), Command.VIEW, A, Transition("in_progress", "viewed")),
    (
        "view after consenting does not downgrade",
        solo("in_progress", "consented"),
        Command.VIEW,
        A,
        Transition("in_progress", "consented"),
    ),
    ("view after declining", solo("in_progress", "declined"), Command.VIEW, A, "signer_declined"),
    # -- consent -----------------------------------------------------------
    ("consent before viewing", solo("in_progress", "pending"), Command.CONSENT, A, "not_viewed"),
    (
        "consent after viewing",
        solo("in_progress", "viewed"),
        Command.CONSENT,
        A,
        Transition("in_progress", "consented"),
    ),
    (
        "consent twice",
        solo("in_progress", "consented"),
        Command.CONSENT,
        A,
        Transition("in_progress", "consented"),
    ),
    ("consent before presentation", solo("created", "viewed"), Command.CONSENT, A, "not_presented"),
    # -- signing -----------------------------------------------------------
    ("sign before viewing", solo("in_progress", "pending"), Command.SIGN, A, "not_viewed"),
    ("sign before consenting", solo("in_progress", "viewed"), Command.SIGN, A, "not_consented"),
    (
        "the only signer completes the envelope",
        solo("in_progress", "consented"),
        Command.SIGN,
        A,
        Transition("completed_pending_seal", "signed", completes_envelope=True),
    ),
    (
        "first of two signs",
        pair("in_progress", "consented", "pending"),
        Command.SIGN,
        A,
        Transition("in_progress", "signed"),
    ),
    (
        "last of two completes",
        pair("in_progress", "signed", "consented"),
        Command.SIGN,
        B,
        Transition("completed_pending_seal", "signed", completes_envelope=True),
    ),
    ("sign twice", solo("in_progress", "signed"), Command.SIGN, A, "signer_already_signed"),
    (
        "sequential: signing out of turn",
        pair("in_progress", "consented", "consented", "sequential"),
        Command.SIGN,
        B,
        "out_of_order",
    ),
    (
        "parallel: either may sign first",
        pair("in_progress", "pending", "consented"),
        Command.SIGN,
        B,
        Transition("in_progress", "signed"),
    ),
    ("sign a voided envelope", solo("voided", "consented"), Command.SIGN, A, "envelope_voided"),
    ("sign an expired envelope", solo("expired", "consented"), Command.SIGN, A, "envelope_expired"),
    ("sign a sealed envelope", solo("sealed", "signed"), Command.SIGN, A, "envelope_sealed"),
    # -- declining ---------------------------------------------------------
    (
        "decline ends the envelope",
        solo("in_progress", "viewed"),
        Command.DECLINE,
        A,
        Transition("declined", "declined"),
    ),
    (
        "any signer's decline ends it",
        pair("in_progress", "signed", "pending"),
        Command.DECLINE,
        B,
        Transition("declined", "declined"),
    ),
    (
        "decline before presentation is still allowed",
        solo("created", "pending"),
        Command.DECLINE,
        A,
        Transition("declined", "declined"),
    ),
    (
        "sequential: declining is never gated on turn",
        pair("in_progress", "pending", "pending", "sequential"),
        Command.DECLINE,
        B,
        Transition("declined", "declined"),
    ),
    ("decline after signing", solo("in_progress", "signed"), Command.DECLINE, A, "signer_already_signed"),
    ("decline twice", solo("declined", "declined"), Command.DECLINE, A, "envelope_declined"),
    # -- voiding -----------------------------------------------------------
    ("void a fresh envelope", solo("created", "pending"), Command.VOID, None, Transition("voided")),
    ("void mid-flow", pair("in_progress", "signed", "pending"), Command.VOID, None, Transition("voided")),
    (
        "void once everyone has signed",
        solo("completed_pending_seal", "signed"),
        Command.VOID,
        None,
        "envelope_already_complete",
    ),
    ("void a sealed envelope", solo("sealed", "signed"), Command.VOID, None, "envelope_sealed"),
    ("void a declined envelope", solo("declined", "declined"), Command.VOID, None, "envelope_declined"),
    # -- expiry ------------------------------------------------------------
    ("expire a fresh envelope", solo("created", "pending"), Command.EXPIRE, None, Transition("expired")),
    ("expire mid-flow", solo("in_progress", "consented"), Command.EXPIRE, None, Transition("expired")),
    (
        "expiry never catches a complete envelope",
        solo("completed_pending_seal", "signed"),
        Command.EXPIRE,
        None,
        "envelope_already_complete",
    ),
    ("expire a sealed envelope", solo("sealed", "signed"), Command.EXPIRE, None, "envelope_sealed"),
    # -- sealing -----------------------------------------------------------
    ("seal when complete", solo("completed_pending_seal", "signed"), Command.SEAL, None, Transition("sealed")),
    ("seal twice", solo("sealed", "signed"), Command.SEAL, None, "already_sealed"),
    ("seal mid-flow", solo("in_progress", "consented"), Command.SEAL, None, "not_pending_seal"),
    ("seal a voided envelope", solo("voided", "pending"), Command.SEAL, None, "not_pending_seal"),
    # -- superseding -------------------------------------------------------
    ("supersede a sealed envelope", solo("sealed", "signed"), Command.SUPERSEDE, None, Transition("sealed")),
    ("supersede a live envelope", solo("in_progress", "viewed"), Command.SUPERSEDE, None, "supersedes_not_sealed"),
    (
        "supersede one that is still sealing",
        solo("completed_pending_seal", "signed"),
        Command.SUPERSEDE,
        None,
        "supersedes_not_sealed",
    ),
    ("supersede a voided envelope", solo("voided", "pending"), Command.SUPERSEDE, None, "supersedes_not_sealed"),
]


@pytest.mark.parametrize(
    ("state", "command", "signer_id", "expected"),
    [(row[1], row[2], row[3], row[4]) for row in TABLE],
    ids=[row[0] for row in TABLE],
)
def test_transition_table(
    state: EnvelopeState,
    command: Command,
    signer_id: UUID | None,
    expected: Transition | str,
) -> None:
    decision = decide(state, command, signer_id=signer_id)
    if isinstance(expected, Transition):
        assert decision == expected
    else:
        assert decision == Refusal(expected)


# --------------------------------------------------------------------------- properties


@pytest.mark.parametrize(
    ("status", "signer_status", "command"),
    list(product(ENVELOPE_STATUSES, SIGNER_STATUSES, list(Command))),
)
def test_decide_is_total(status: EnvelopeStatus, signer_status: SignerStatus, command: Command) -> None:
    """Every combination answers. A state machine that raises is a state machine that fails open."""
    decision = decide(solo(status, signer_status), command, signer_id=A)
    assert isinstance(decision, Transition | Refusal)


@pytest.mark.parametrize("status", [s for s in ENVELOPE_STATUSES if s not in LIVE_ENVELOPE_STATUSES])
@pytest.mark.parametrize(
    "command",
    [Command.PRESENT, Command.VIEW, Command.CONSENT, Command.SIGN, Command.DECLINE, Command.VOID, Command.EXPIRE],
)
def test_a_terminal_envelope_refuses_everything(status: EnvelopeStatus, command: Command) -> None:
    assert isinstance(decide(solo(status, "pending"), command, signer_id=A), Refusal)


@pytest.mark.parametrize("signer_status", sorted(FINISHED_SIGNER_STATUSES))
@pytest.mark.parametrize("command", [Command.PRESENT, Command.VIEW, Command.CONSENT, Command.SIGN, Command.DECLINE])
def test_a_finished_signer_refuses_everything(signer_status: SignerStatus, command: Command) -> None:
    assert isinstance(decide(solo("in_progress", signer_status), command, signer_id=A), Refusal)


def test_only_signing_can_complete_an_envelope() -> None:
    for status, signer_status, command in product(ENVELOPE_STATUSES, SIGNER_STATUSES, list(Command)):
        decision = decide(solo(status, signer_status), command, signer_id=A)
        if isinstance(decision, Transition) and decision.completes_envelope:
            assert command is Command.SIGN


def test_completion_needs_every_signer() -> None:
    state = EnvelopeState(
        "in_progress",
        "parallel",
        (SignerState(A, 0, "consented"), SignerState(B, 1, "consented"), SignerState(C, 2, "signed")),
    )
    decision = decide(state, Command.SIGN, signer_id=A)
    assert decision == Transition("in_progress", "signed")


def test_a_declined_signer_blocks_completion_even_when_others_signed() -> None:
    """A decline ends the envelope, so this state cannot arise -- and if it did, it must not seal."""
    state = EnvelopeState("in_progress", "parallel", (SignerState(A, 0, "consented"), SignerState(B, 1, "declined")))
    assert decide(state, Command.SIGN, signer_id=A) == Transition("in_progress", "signed")


def test_ties_in_order_index_do_not_block_each_other() -> None:
    state = EnvelopeState("in_progress", "sequential", (SignerState(A, 0, "pending"), SignerState(B, 0, "consented")))
    assert decide(state, Command.SIGN, signer_id=B) == Transition("in_progress", "signed")


def test_decide_never_mutates_its_input() -> None:
    state = pair("in_progress", "consented", "pending")
    before = (state.status, tuple((s.signer_id, s.status) for s in state.signers))
    decide(state, Command.SIGN, signer_id=A)
    assert (state.status, tuple((s.signer_id, s.status) for s in state.signers)) == before


def test_an_empty_envelope_cannot_be_signed() -> None:
    assert decide(EnvelopeState("in_progress", "parallel", ()), Command.SIGN, signer_id=uuid4()) == Refusal(
        "unknown_signer"
    )


# --------------------------------------------------------------------------- backoff


@pytest.mark.parametrize(
    ("attempts", "expected"),
    [
        (1, timedelta(minutes=1)),
        (2, timedelta(minutes=5)),
        (3, timedelta(minutes=15)),
        (4, timedelta(hours=1)),
        (5, timedelta(hours=1)),
        (50, timedelta(hours=1)),
    ],
)
def test_backoff_schedule(attempts: int, expected: timedelta) -> None:
    assert next_backoff(attempts) == expected


@pytest.mark.parametrize("attempts", [0, -1, -100])
def test_backoff_never_returns_zero(attempts: int) -> None:
    """A miscounting worker must still wait, not spin against a dead key service."""
    assert next_backoff(attempts) == timedelta(minutes=1)


def test_backoff_is_monotonic() -> None:
    delays = [next_backoff(n) for n in range(1, 10)]
    assert delays == sorted(delays)
