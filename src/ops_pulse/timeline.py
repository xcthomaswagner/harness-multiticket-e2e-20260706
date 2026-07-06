"""Incident event timeline normalization."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any


KNOWN_FIELDS = frozenset(
    {"timestamp", "source", "severity", "message", "service", "fingerprint"}
)
REQUIRED_FIELDS = ("timestamp", "source", "severity", "message", "service")


class NormalizedTimeline(list[dict[str, Any]]):
    """A normalized timeline plus non-fatal validation errors."""

    def __init__(
        self,
        events: Iterable[dict[str, Any]] = (),
        errors: Iterable[dict[str, Any]] = (),
    ) -> None:
        super().__init__(events)
        self.errors = list(errors)

    @property
    def valid(self) -> bool:
        """Return whether every input event was accepted."""

        return not self.errors


def normalize_timeline(events: Iterable[Mapping[str, Any] | str]) -> NormalizedTimeline:
    """Normalize incident events into chronological, deduplicated records.

    Invalid events are skipped and reported on ``result.errors`` with their input
    index and failing field when known. Duplicate records keep the core fields
    from the event with the later timestamp, or the later input when timestamps
    tie; metadata from all duplicates is union-merged with the same precedence.
    """

    errors: list[dict[str, Any]] = []
    deduped: dict[str, dict[str, Any]] = {}

    for index, raw_event in enumerate(events):
        event, event_errors = _coerce_event(raw_event, index)
        errors.extend(event_errors)
        if event is None:
            continue

        missing = [
            field
            for field in REQUIRED_FIELDS
            if field not in event or event[field] in (None, "")
        ]
        if missing:
            errors.extend(
                _error(index, f"missing required field: {field}", field)
                for field in missing
            )
            continue

        timestamp = _parse_timestamp(event["timestamp"], index)
        if isinstance(timestamp, dict):
            errors.append(timestamp)
            continue

        normalized = _normalize_event(event, timestamp, index)
        identity = _dedupe_identity(normalized)

        if identity in deduped:
            deduped[identity] = _merge_duplicates(deduped[identity], normalized)
        else:
            deduped[identity] = normalized

    sorted_events = sorted(
        deduped.values(),
        key=lambda event: (event["_sort_timestamp"], event["_first_index"]),
    )
    return NormalizedTimeline(
        [_public_event(event) for event in sorted_events],
        errors,
    )


def _coerce_event(
    raw_event: Mapping[str, Any] | str,
    index: int,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    if isinstance(raw_event, str):
        try:
            decoded = json.loads(raw_event)
        except json.JSONDecodeError as exc:
            return None, [_error(index, f"invalid JSON event: {exc.msg}")]
        if not isinstance(decoded, dict):
            return None, [_error(index, "JSON event must decode to an object")]
        return dict(decoded), []

    if isinstance(raw_event, Mapping):
        return dict(raw_event), []

    return None, [_error(index, "event must be a dict or JSON object string")]


def _parse_timestamp(value: Any, index: int) -> datetime | dict[str, Any]:
    if isinstance(value, bool):
        return _error(index, "timestamp must be an ISO string or epoch number", "timestamp")

    if isinstance(value, int | float):
        try:
            return datetime.fromtimestamp(value, UTC)
        except (OSError, OverflowError, ValueError):
            return _error(index, "timestamp epoch is out of range", "timestamp")

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return _error(index, "timestamp is empty", "timestamp")

        if _looks_like_epoch(value):
            try:
                return datetime.fromtimestamp(float(value), UTC)
            except (OSError, OverflowError, ValueError):
                return _error(index, "timestamp epoch is out of range", "timestamp")

        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return _error(index, "timestamp must be parseable ISO-8601", "timestamp")

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    return _error(index, "timestamp must be an ISO string or epoch number", "timestamp")


def _normalize_event(
    event: Mapping[str, Any],
    timestamp: datetime,
    index: int,
) -> dict[str, Any]:
    fingerprint = event.get("fingerprint")
    if fingerprint in ("", None):
        fingerprint = None

    return {
        "timestamp": _format_timestamp(timestamp),
        "source": event["source"],
        "severity": event["severity"],
        "message": event["message"],
        "service": event["service"],
        "fingerprint": fingerprint,
        "metadata": {
            key: value for key, value in event.items() if key not in KNOWN_FIELDS
        },
        "_sort_timestamp": timestamp,
        "_first_index": index,
        "_canonical_index": index,
    }


def _dedupe_identity(event: Mapping[str, Any]) -> str:
    fingerprint = event["fingerprint"]
    if fingerprint is not None:
        return f"fingerprint:{_stable_value(fingerprint)}"

    fallback_parts = {
        "timestamp": event["timestamp"],
        "source": event["source"],
        "service": event["service"],
        "message": event["message"],
    }
    return f"fallback:{_stable_value(fallback_parts)}"


def _merge_duplicates(
    existing: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    incoming_wins = (
        incoming["_sort_timestamp"],
        incoming["_canonical_index"],
    ) >= (
        existing["_sort_timestamp"],
        existing["_canonical_index"],
    )

    if incoming_wins:
        merged = dict(incoming)
        merged["metadata"] = {
            **existing["metadata"],
            **incoming["metadata"],
        }
    else:
        merged = dict(existing)
        merged["metadata"] = {
            **incoming["metadata"],
            **existing["metadata"],
        }

    merged["_first_index"] = min(existing["_first_index"], incoming["_first_index"])
    return merged


def _public_event(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in event.items() if not key.startswith("_")
    }


def _format_timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _stable_value(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)


def _looks_like_epoch(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def _error(index: int, message: str, field: str | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"index": index, "message": message}
    if field is not None:
        error["field"] = field
    return error
