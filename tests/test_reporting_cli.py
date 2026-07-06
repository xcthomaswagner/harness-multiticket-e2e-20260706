import json
from io import StringIO

from ops_pulse.cli import render_file
from ops_pulse.reporting import render_incident_digest


def test_digest_contains_required_sections_in_deterministic_order() -> None:
    digest = render_incident_digest(_events())

    assert digest == (
        "# Incident Digest\n"
        "\n"
        "## Current State\n"
        "- Severity: critical\n"
        "- Affected services: auth, checkout\n"
        "- Escalation level: critical\n"
        "- Evaluated events: 2\n"
        "- Skipped events: 0\n"
        "\n"
        "## Breach Warnings\n"
        "- SLA-ack-15m\n"
        "- SLA-response-30m\n"
        "- SLA-resolution-60m\n"
        "\n"
        "## Timeline Summary\n"
        "- 2026-07-06T10:00:00Z | high | checkout | monitor: checkout errors rising\n"
        "- 2026-07-06T11:05:00Z | critical | auth | pager: login outage confirmed\n"
        "\n"
        "## Action Checklist\n"
        "- Escalate to the incident commander and engage all responders immediately.\n"
        "- Confirm SLA breach owner and response clock.\n"
        "- Share this digest with the incident channel.\n"
    )


def test_digest_is_stable_for_identical_input() -> None:
    first = render_incident_digest(_events())
    second = render_incident_digest(_events())

    assert first == second


def test_digest_reports_timeline_validation_warnings() -> None:
    digest = render_incident_digest(
        [
            _event(message="valid"),
            {"timestamp": "not-a-date", "source": "monitor", "service": "checkout"},
        ]
    )

    assert "- Skipped events: 2" in digest
    assert "## Input Warnings" in digest
    assert "- Event 1 (severity): missing required field: severity" in digest
    assert "- Event 1 (message): missing required field: message" in digest


def test_digest_treats_warning_severity_as_current_medium_severity() -> None:
    digest = render_incident_digest(
        [
            _event(severity="warning", service="api", message="latency breached"),
        ]
    )

    assert "- Severity: medium" in digest
    assert "- Evaluated events: 1" in digest


def test_cli_reads_json_file_and_prints_markdown(tmp_path) -> None:
    events_file = tmp_path / "events.json"
    events_file.write_text(json.dumps(_events()), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = render_file(str(events_file), stdout=stdout, stderr=stderr)

    assert exit_code == 0
    assert stdout.getvalue().startswith("# Incident Digest\n")
    assert "login outage confirmed" in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_cli_reports_clear_error_for_missing_file() -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = render_file("/missing/events.json", stdout=stdout, stderr=stderr)

    assert exit_code == 2
    assert stdout.getvalue() == ""
    assert "ops-pulse: cannot read /missing/events.json:" in stderr.getvalue()


def test_cli_reports_clear_error_for_invalid_json(tmp_path) -> None:
    events_file = tmp_path / "events.json"
    events_file.write_text("{not json", encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = render_file(str(events_file), stdout=stdout, stderr=stderr)

    assert exit_code == 2
    assert stdout.getvalue() == ""
    assert "ops-pulse: invalid JSON" in stderr.getvalue()


def _events() -> list[dict[str, object]]:
    return [
        _event(
            timestamp="2026-07-06T11:05:00Z",
            source="pager",
            severity="critical",
            service="auth",
            message="login outage confirmed",
        ),
        _event(
            timestamp="2026-07-06T10:00:00Z",
            source="monitor",
            severity="high",
            service="checkout",
            message="checkout errors rising",
        ),
    ]


def _event(**overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "timestamp": "2026-07-06T10:00:00Z",
        "source": "monitor",
        "severity": "high",
        "message": "checkout errors rising",
        "service": "checkout",
    }
    event.update(overrides)
    return event
