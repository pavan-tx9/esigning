"""``docs/COMPLIANCE-CHECKLIST.md`` counts the audit event types. Keep the count true.

The checklist is the document somebody reads when they are deciding whether to trust this service,
and its answer to the guide's "write an append-only log covering ..." is a *number*: how many event
types exist, and which ones beyond the ten the guide names. A number in prose goes stale the moment
an addendum adds an event -- Addendum 1 added four and Addendum 2 added one -- and a compliance
document that is quietly wrong about something this checkable is worse than one that says less.

So it is asserted rather than remembered, like the worked hash vector in ``audit/README.md``.
"""

from __future__ import annotations

import re
from pathlib import Path

from esign.contracts import EventType

CHECKLIST = Path(__file__).resolve().parents[3] / "docs" / "COMPLIANCE-CHECKLIST.md"

#: "28 types", wherever it appears on a line that is talking about events.
_COUNT_CLAIM = re.compile(r"(\d+) types")
#: A backticked event type name: ``document.supplied``.
_NAMED_EVENT = re.compile(r"`([a-z]+(?:_[a-z]+)*\.[a-z]+(?:_[a-z]+)*)`")


def _event_lines() -> list[str]:
    return [line for line in CHECKLIST.read_text(encoding="utf-8").splitlines() if "event" in line.lower()]


def test_the_checklist_states_the_number_of_event_types_that_exist() -> None:
    claims = [int(count) for line in _event_lines() for count in _COUNT_CLAIM.findall(line)]
    assert claims, "the checklist no longer states how many event types there are"
    assert set(claims) == {len(list(EventType))}, (
        f"docs/COMPLIANCE-CHECKLIST.md claims {sorted(set(claims))} event types; "
        f"contracts.EventType has {len(list(EventType))}"
    )


def test_every_event_the_checklist_names_is_a_real_event_type() -> None:
    """The row does not only count: it names the ones beyond the guide's ten. A renamed or removed
    event type has to be noticed here, not by a reader who goes looking for it in the trail."""
    values = {event.value for event in EventType}
    # Only the row about the append-only log, so an unrelated dotted token elsewhere in the
    # document (a file name, a version) is not mistaken for an event type.
    (row,) = [line for line in _event_lines() if "`contracts.EventType`" in line]
    named = set(_NAMED_EVENT.findall(row))
    assert named, "the checklist no longer names any event type"
    assert named <= values, f"the checklist names event types that do not exist: {sorted(named - values)}"
