import json

from ops_pulse.timeline import NormalizedTimeline, normalize_timeline


def test_accepts_dict_and_json_string_inputs() -> None:
    result = normalize_timeline(
        [
            {
                "timestamp": "2026-07-06T10:02:00Z",
                "source": "pager",
                "severity": "critical",
                "message": "checkout errors rising",
                "service": "checkout",
            },
            json.dumps(
                {
                    "timestamp": 1783332000,
                    "source": "synthetics",
                    "severity": "warning",
                    "message": "latency breached",
                    "service": "catalog",
                }
            ),
        ]
    )

    assert isinstance(result, NormalizedTimeline)
    assert result.valid
    assert [event["source"] for event in result] == ["synthetics", "pager"]
    assert result[0]["timestamp"] == "2026-07-06T10:00:00Z"


def test_sorts_events_ascending_by_timestamp() -> None:
    result = normalize_timeline(
        [
            _event(timestamp="2026-07-06T10:05:00Z", message="third"),
            _event(timestamp="2026-07-06T10:01:00Z", message="first"),
            _event(timestamp="2026-07-06T10:03:00Z", message="second"),
        ]
    )

    assert [event["message"] for event in result] == ["first", "second", "third"]


def test_equal_timestamps_keep_stable_order_for_distinct_events() -> None:
    result = normalize_timeline(
        [
            _event(message="first same-time event", fingerprint="one"),
            _event(message="second same-time event", fingerprint="two"),
        ]
    )

    assert [event["message"] for event in result] == [
        "first same-time event",
        "second same-time event",
    ]


def test_dedupes_by_identical_fingerprint_and_merges_metadata() -> None:
    result = normalize_timeline(
        [
            _event(
                timestamp="2026-07-06T10:00:00Z",
                severity="warning",
                message="first signal",
                fingerprint="incident-123",
                runbook="checkout",
            ),
            _event(
                timestamp="2026-07-06T10:04:00Z",
                severity="critical",
                message="confirmed outage",
                fingerprint="incident-123",
                ticket="INC-123",
            ),
        ]
    )

    assert len(result) == 1
    assert result[0]["severity"] == "critical"
    assert result[0]["message"] == "confirmed outage"
    assert result[0]["metadata"] == {
        "runbook": "checkout",
        "ticket": "INC-123",
    }


def test_dedupes_without_fingerprint_using_stable_fallback_identity() -> None:
    duplicate = _event(
        timestamp="2026-07-06T10:00:00Z",
        source="monitor",
        service="checkout",
        message="error rate high",
        severity="warning",
        zone="us-west",
    )

    result = normalize_timeline(
        [
            duplicate,
            {
                **duplicate,
                "severity": "critical",
                "zone": "us-east",
                "detail": "same core event with updated fields",
            },
            _event(
                timestamp="2026-07-06T10:00:00Z",
                source="monitor",
                service="checkout",
                message="database pool exhausted",
                severity="critical",
            ),
        ]
    )

    assert len(result) == 2
    assert result[0]["message"] == "error rate high"
    assert result[0]["severity"] == "critical"
    assert result[0]["metadata"] == {
        "zone": "us-east",
        "detail": "same core event with updated fields",
    }
    assert result[1]["message"] == "database pool exhausted"


def test_preserves_unknown_fields_as_metadata() -> None:
    result = normalize_timeline(
        [
            _event(
                region="us-west-2",
                tags=["checkout", "payments"],
                metadata={"from_input": True},
            )
        ]
    )

    assert result[0]["metadata"] == {
        "region": "us-west-2",
        "tags": ["checkout", "payments"],
        "metadata": {"from_input": True},
    }


def test_reports_invalid_events_with_context_and_keeps_valid_events() -> None:
    result = normalize_timeline(
        [
            _event(message="valid"),
            {"timestamp": "not-a-date", "source": "monitor", "service": "api"},
            "not json",
            None,  # type: ignore[list-item]
        ]
    )

    assert [event["message"] for event in result] == ["valid"]
    assert result.errors == [
        {"index": 1, "message": "missing required field: severity", "field": "severity"},
        {"index": 1, "message": "missing required field: message", "field": "message"},
        {"index": 2, "message": "invalid JSON event: Expecting value"},
        {"index": 3, "message": "event must be a dict or JSON object string"},
    ]
    assert not result.valid


def test_rejects_malformed_timestamp_without_uncaught_exception() -> None:
    result = normalize_timeline(
        [
            _event(timestamp="2026-07-06T10:00:00Z", message="valid"),
            _event(timestamp="definitely-not-a-timestamp", message="bad timestamp"),
        ]
    )

    assert [event["message"] for event in result] == ["valid"]
    assert result.errors == [
        {
            "index": 1,
            "message": "timestamp must be parseable ISO-8601",
            "field": "timestamp",
        }
    ]


def test_empty_and_single_event_inputs() -> None:
    assert normalize_timeline([]) == []

    result = normalize_timeline([_event(message="only event")])

    assert len(result) == 1
    assert result[0]["message"] == "only event"
    assert result.errors == []


def _event(**overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "timestamp": "2026-07-06T10:00:00Z",
        "source": "monitor",
        "severity": "warning",
        "message": "checkout errors rising",
        "service": "checkout",
    }
    event.update(overrides)
    return event
