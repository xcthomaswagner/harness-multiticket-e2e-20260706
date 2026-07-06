import ast
import sys
from pathlib import Path

import pytest

from ops_pulse.escalation import (
    EscalationLevel,
    MALFORMED_EVENT_POLICY,
    SLA_POLICIES,
    Severity,
    evaluate_escalation,
)


def event(severity: str, service: str, timestamp: str) -> dict[str, str]:
    return {
        "severity": severity,
        "service": service,
        "timestamp": timestamp,
    }


def test_empty_timeline_returns_baseline_result() -> None:
    result = evaluate_escalation([])

    assert result.level is EscalationLevel.NONE
    assert result.breached_policies == []
    assert result.next_recommended_action
    assert result.highest_severity is None
    assert result.elapsed_minutes is None
    assert result.evaluated_event_count == 0


def test_level_derives_from_severity_service_and_elapsed_time() -> None:
    low_severity = evaluate_escalation(
        [event("low", "web", "2026-07-06T00:00:00Z")]
    )
    high_severity = evaluate_escalation(
        [event("high", "web", "2026-07-06T00:00:00Z")]
    )
    high_impact_service = evaluate_escalation(
        [event("high", "auth", "2026-07-06T00:00:00Z")]
    )
    elapsed_breach = evaluate_escalation(
        [
            event("high", "auth", "2026-07-06T00:00:00Z"),
            event("medium", "web", "2026-07-06T00:31:00Z"),
        ]
    )

    assert high_severity.level > low_severity.level
    assert high_impact_service.level > high_severity.level
    assert elapsed_breach.level > high_impact_service.level
    assert elapsed_breach.breached_policies == [
        "SLA-ack-15m",
        "SLA-response-30m",
    ]


def test_elapsed_time_must_exceed_threshold_to_breach_policy() -> None:
    threshold = SLA_POLICIES["SLA-ack-15m"]
    at_threshold = evaluate_escalation(
        [
            event("high", "web", "2026-07-06T00:00:00Z"),
            event("medium", "web", f"2026-07-06T00:{threshold:02d}:00Z"),
        ]
    )
    just_over_threshold = evaluate_escalation(
        [
            event("high", "web", "2026-07-06T00:00:00Z"),
            event("medium", "web", f"2026-07-06T00:{threshold:02d}:01Z"),
        ]
    )

    assert at_threshold.elapsed_minutes == threshold
    assert at_threshold.breached_policies == []
    assert just_over_threshold.elapsed_minutes == pytest.approx(
        threshold + (1 / 60)
    )
    assert just_over_threshold.breached_policies == ["SLA-ack-15m"]


def test_out_of_order_events_use_first_high_or_critical_timestamp() -> None:
    result = evaluate_escalation(
        [
            event("info", "web", "2026-07-06T01:15:00Z"),
            event("high", "web", "2026-07-06T00:30:00Z"),
            event("critical", "database", "2026-07-06T00:10:00Z"),
            event("low", "web", "2026-07-06T00:45:00Z"),
        ]
    )

    assert result.anchor_present is True
    assert result.elapsed_minutes == 65
    assert result.breached_policies == [
        "SLA-ack-15m",
        "SLA-response-30m",
        "SLA-resolution-60m",
    ]


def test_low_and_info_events_do_not_create_elapsed_time_breach_anchor() -> None:
    result = evaluate_escalation(
        [
            event("info", "web", "2026-07-06T00:00:00Z"),
            event("low", "auth", "2026-07-06T03:00:00Z"),
        ]
    )

    assert result.anchor_present is False
    assert result.elapsed_minutes is None
    assert result.breached_policies == []


def test_affected_service_changes_level_without_changing_severity_or_elapsed_time() -> None:
    low_impact = evaluate_escalation(
        [event("high", "web", "2026-07-06T00:00:00Z")]
    )
    high_impact = evaluate_escalation(
        [event("high", "payments", "2026-07-06T00:00:00Z")]
    )

    assert low_impact.highest_severity is Severity.HIGH
    assert high_impact.highest_severity is Severity.HIGH
    assert low_impact.breached_policies == []
    assert high_impact.breached_policies == []
    assert high_impact.service_weight > low_impact.service_weight
    assert high_impact.level > low_impact.level


def test_common_monitoring_severity_aliases_are_evaluated() -> None:
    result = evaluate_escalation(
        [
            event("warning", "api", "2026-07-06T00:00:00Z"),
            event("error", "api", "2026-07-06T00:05:00Z"),
            event("fatal", "auth", "2026-07-06T00:10:00Z"),
        ]
    )

    assert result.evaluated_event_count == 3
    assert result.skipped_event_count == 0
    assert result.highest_severity is Severity.CRITICAL
    assert result.level is EscalationLevel.HIGH


def test_malformed_events_are_skipped_consistently() -> None:
    result = evaluate_escalation(
        [
            event("critical", "auth", "2026-07-06T00:00:00Z"),
            {
                "severity": "mystery",
                "service": "auth",
                "timestamp": "2026-07-06T00:01:00Z",
            },
            {"service": "auth", "timestamp": "2026-07-06T00:02:00Z"},
            {"severity": "high", "service": "auth", "timestamp": "not-a-date"},
            event("low", "web", "2026-07-06T00:05:00Z"),
        ]
    )

    assert MALFORMED_EVENT_POLICY == "skip"
    assert result.evaluated_event_count == 2
    assert result.skipped_event_count == 3
    assert result.highest_severity is Severity.CRITICAL
    assert result.elapsed_minutes == 5


def test_every_result_has_a_next_recommended_action() -> None:
    timelines = [
        [],
        [event("medium", "web", "2026-07-06T00:00:00Z")],
        [event("high", "auth", "2026-07-06T00:00:00Z")],
        [
            event("critical", "payments", "2026-07-06T00:00:00Z"),
            event("medium", "web", "2026-07-06T01:01:00Z"),
        ],
    ]

    for timeline in timelines:
        result = evaluate_escalation(timeline)
        assert result.next_recommended_action.strip()


def test_escalation_module_uses_only_standard_library_imports() -> None:
    module_path = (
        Path(__file__).resolve().parents[1] / "src" / "ops_pulse" / "escalation.py"
    )
    tree = ast.parse(module_path.read_text())
    imported_roots: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.partition(".")[0])

    allowed = set(sys.stdlib_module_names) | {"__future__"}
    assert imported_roots <= allowed
