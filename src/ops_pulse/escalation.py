"""Escalation policy and SLA-risk evaluation over a normalized incident timeline.

This module is intentionally dependency-free (standard library only). It consumes
a *normalized* incident timeline -- a list of event dictionaries -- and produces an
:class:`EscalationResult` exposing the current escalation level, the breached policy
names, and a next recommended action.

Design decisions (pinned as module-level constants/enums so behavior is deterministic
and testable):

Severity ordering
    ``info < low < medium < high < critical`` (see :class:`Severity`). Severity strings
    are matched case-insensitively. An unrecognized severity makes the event *malformed*.

Affected-service to escalation weight
    :data:`SERVICE_WEIGHTS` maps a known service name (case-insensitive) to a weight in
    ``0..2``. An unknown/unrecognized service uses :data:`UNKNOWN_SERVICE_WEIGHT`. The
    weight contributed to the score is the **maximum** service weight across all valid
    events (the most critical service involved in the incident).

Policy thresholds and threshold comparison
    :data:`SLA_POLICIES` defines named elapsed-time thresholds in minutes. A policy is
    **breached** when the elapsed time is *strictly greater than* the threshold
    (``elapsed > threshold``). The comparison is therefore **exclusive**: an elapsed time
    exactly equal to a threshold is *not* a breach. This is captured by
    :data:`THRESHOLD_INCLUSIVE` (``False``).

Elapsed-time anchor
    Elapsed time is measured from the **first critical-or-high event** (the one with the
    earliest ``timestamp``, not the earliest list position) to the **latest event** in the
    timeline. If there is no critical/high event there is no anchor, so no elapsed time is
    computed and no time-based policy can be breached.

Timestamp normalization
    Timestamps are parsed with :func:`datetime.datetime.fromisoformat`. Timezone-aware
    timestamps are converted to UTC and made naive; naive timestamps are interpreted as
    UTC. This lets naive and aware timestamps be compared deterministically.

Malformed-event handling policy
    **Skip-and-continue.** An event is malformed when it is not a mapping, is missing any
    of the ``severity`` / ``service`` / ``timestamp`` keys, has a null/blank/unrecognized
    severity, or has an unparseable timestamp. Malformed events are skipped and the
    remaining valid events are evaluated. If *every* event is malformed (or the timeline is
    empty) the baseline result is returned. This policy is applied consistently and is
    exposed via :data:`MALFORMED_EVENT_POLICY`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Mapping, Optional, Sequence

__all__ = [
    "Severity",
    "EscalationLevel",
    "EscalationResult",
    "evaluate_escalation",
    "SERVICE_WEIGHTS",
    "UNKNOWN_SERVICE_WEIGHT",
    "SLA_POLICIES",
    "THRESHOLD_INCLUSIVE",
    "MALFORMED_EVENT_POLICY",
]


class Severity(IntEnum):
    """Event severity, ordered ``info < low < medium < high < critical``."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: Any) -> Optional["Severity"]:
        """Return the matching member for ``value`` (case-insensitive) or ``None``."""
        if not isinstance(value, str):
            return None
        try:
            return cls[value.strip().upper()]
        except KeyError:
            return None


class EscalationLevel(IntEnum):
    """Overall escalation level, ordered ``none < low < medium < high < critical``."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# --- Pinned design constants -------------------------------------------------

#: Affected-service -> escalation weight (0..2). Matched case-insensitively.
SERVICE_WEIGHTS: dict[str, int] = {
    "web": 0,
    "frontend": 0,
    "marketing": 0,
    "api": 1,
    "database": 1,
    "cache": 1,
    "search": 1,
    "auth": 2,
    "authentication": 2,
    "payments": 2,
    "billing": 2,
    "checkout": 2,
}

#: Escalation weight applied to an unknown / unrecognized service.
UNKNOWN_SERVICE_WEIGHT: int = 1

#: Named SLA policies -> elapsed-time threshold in minutes.
SLA_POLICIES: dict[str, int] = {
    "SLA-ack-15m": 15,
    "SLA-response-30m": 30,
    "SLA-resolution-60m": 60,
}

#: Threshold comparison is exclusive: a policy breaches when ``elapsed > threshold``.
THRESHOLD_INCLUSIVE: bool = False

#: How malformed events are handled. One of ``"skip"`` or ``"raise"``.
MALFORMED_EVENT_POLICY: str = "skip"

#: Severities that anchor the elapsed-time window.
_ANCHOR_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})

#: Score thresholds mapping a combined score to an escalation level.
#: score = highest-severity rank (0..4) + max service weight (0..2)
#:         + number of breached SLA policies (0..3)
_LEVEL_BANDS: tuple[tuple[int, EscalationLevel], ...] = (
    (0, EscalationLevel.NONE),
    (2, EscalationLevel.LOW),
    (4, EscalationLevel.MEDIUM),
    (6, EscalationLevel.HIGH),
)  # anything above the last band's upper bound -> CRITICAL

#: Next recommended action per escalation level.
_RECOMMENDED_ACTIONS: dict[EscalationLevel, str] = {
    EscalationLevel.NONE: "No action required; continue routine monitoring.",
    EscalationLevel.LOW: "Acknowledge the events and keep monitoring; no escalation needed.",
    EscalationLevel.MEDIUM: "Notify the on-call engineer and begin investigation.",
    EscalationLevel.HIGH: "Page the on-call engineer and open an incident bridge.",
    EscalationLevel.CRITICAL: (
        "Escalate to the incident commander and engage all responders immediately."
    ),
}


@dataclass(frozen=True)
class EscalationResult:
    """Outcome of evaluating an incident timeline.

    Attributes:
        level: Current :class:`EscalationLevel`.
        breached_policies: Names of SLA policies whose threshold was exceeded, in
            ascending-threshold order. Empty when nothing is breached.
        next_recommended_action: Non-empty guidance string appropriate to ``level``.
        score: Combined numeric score used to derive ``level``.
        highest_severity: Highest :class:`Severity` among valid events, or ``None``.
        service_weight: Maximum affected-service weight across valid events.
        elapsed_minutes: Minutes from the first critical/high event to the latest
            event, or ``None`` when there is no critical/high anchor.
        anchor_present: Whether a critical/high anchor event exists.
        evaluated_event_count: Number of valid events considered.
        skipped_event_count: Number of malformed events skipped.
    """

    level: EscalationLevel
    breached_policies: list[str]
    next_recommended_action: str
    score: int = 0
    highest_severity: Optional[Severity] = None
    service_weight: int = 0
    elapsed_minutes: Optional[float] = None
    anchor_present: bool = False
    evaluated_event_count: int = 0
    skipped_event_count: int = 0


@dataclass
class _ValidEvent:
    severity: Severity
    service_weight: int
    when: datetime


def _normalize_timestamp(value: Any) -> Optional[datetime]:
    """Parse ``value`` into a tz-naive UTC datetime, or ``None`` if unparseable."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # Accept a trailing "Z" (UTC) which older fromisoformat variants reject.
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _service_weight(value: Any) -> int:
    """Return the escalation weight for an affected service value."""
    if isinstance(value, str):
        return SERVICE_WEIGHTS.get(value.strip().lower(), UNKNOWN_SERVICE_WEIGHT)
    return UNKNOWN_SERVICE_WEIGHT


def _parse_event(event: Any) -> Optional[_ValidEvent]:
    """Return a :class:`_ValidEvent` for a well-formed event, else ``None``."""
    if not isinstance(event, Mapping):
        return None
    if "severity" not in event or "service" not in event or "timestamp" not in event:
        return None

    severity = Severity.parse(event["severity"])
    if severity is None:
        return None

    when = _normalize_timestamp(event["timestamp"])
    if when is None:
        return None

    return _ValidEvent(
        severity=severity,
        service_weight=_service_weight(event["service"]),
        when=when,
    )


def _level_for_score(score: int) -> EscalationLevel:
    """Map a combined score to an :class:`EscalationLevel`."""
    level = EscalationLevel.CRITICAL
    for upper_bound, band_level in _LEVEL_BANDS:
        if score <= upper_bound:
            level = band_level
            break
    return level


def _baseline_result(skipped: int = 0) -> EscalationResult:
    """Result for an empty timeline (or one with no valid events)."""
    return EscalationResult(
        level=EscalationLevel.NONE,
        breached_policies=[],
        next_recommended_action=_RECOMMENDED_ACTIONS[EscalationLevel.NONE],
        score=0,
        highest_severity=None,
        service_weight=0,
        elapsed_minutes=None,
        anchor_present=False,
        evaluated_event_count=0,
        skipped_event_count=skipped,
    )


def evaluate_escalation(timeline: Sequence[Mapping[str, Any]]) -> EscalationResult:
    """Evaluate escalation level and SLA risk for a normalized incident timeline.

    Args:
        timeline: A sequence of normalized event dictionaries. Each well-formed event
            has ``severity`` (info/low/medium/high/critical), ``service`` (affected
            service name), and ``timestamp`` (ISO-8601 string or ``datetime``). Malformed
            events are skipped per :data:`MALFORMED_EVENT_POLICY`.

    Returns:
        An :class:`EscalationResult`. An empty timeline -- or one whose events are all
        malformed -- yields the baseline result (lowest level, no breached policies, a
        safe default recommended action) rather than raising.
    """
    if timeline is None:
        return _baseline_result()

    valid: list[_ValidEvent] = []
    skipped = 0
    for event in timeline:
        parsed = _parse_event(event)
        if parsed is None:
            skipped += 1
        else:
            valid.append(parsed)

    if not valid:
        return _baseline_result(skipped=skipped)

    highest_severity = max(ev.severity for ev in valid)
    service_weight = max(ev.service_weight for ev in valid)

    anchor_times = [ev.when for ev in valid if ev.severity in _ANCHOR_SEVERITIES]
    anchor_present = bool(anchor_times)

    elapsed_minutes: Optional[float] = None
    breached_policies: list[str] = []
    if anchor_present:
        anchor = min(anchor_times)
        latest = max(ev.when for ev in valid)
        elapsed_minutes = (latest - anchor).total_seconds() / 60.0
        for name, threshold in sorted(SLA_POLICIES.items(), key=lambda item: item[1]):
            breached = (
                elapsed_minutes >= threshold
                if THRESHOLD_INCLUSIVE
                else elapsed_minutes > threshold
            )
            if breached:
                breached_policies.append(name)

    score = int(highest_severity) + service_weight + len(breached_policies)
    level = _level_for_score(score)

    return EscalationResult(
        level=level,
        breached_policies=breached_policies,
        next_recommended_action=_RECOMMENDED_ACTIONS[level],
        score=score,
        highest_severity=highest_severity,
        service_weight=service_weight,
        elapsed_minutes=elapsed_minutes,
        anchor_present=anchor_present,
        evaluated_event_count=len(valid),
        skipped_event_count=skipped,
    )
