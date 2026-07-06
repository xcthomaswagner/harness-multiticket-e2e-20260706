"""Markdown incident digest rendering."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from ops_pulse.escalation import EscalationResult, Severity, evaluate_escalation
from ops_pulse.timeline import NormalizedTimeline, normalize_timeline


def render_incident_digest(events: Iterable[Mapping[str, Any] | str]) -> str:
    """Return a deterministic Markdown digest for incident ``events``."""

    timeline = normalize_timeline(events)
    escalation = evaluate_escalation(timeline)
    return render_digest_from_timeline(timeline, escalation)


def render_digest_from_timeline(
    timeline: NormalizedTimeline | list[dict[str, Any]],
    escalation: EscalationResult | None = None,
) -> str:
    """Render a Markdown digest from an already-normalized timeline."""

    escalation = escalation or evaluate_escalation(timeline)
    services = _affected_services(timeline)
    severity = _current_severity(timeline)
    warnings = escalation.breached_policies or ["No SLA breaches detected"]
    errors = list(getattr(timeline, "errors", []))
    skipped_event_count = _skipped_event_count(errors)

    lines = [
        "# Incident Digest",
        "",
        "## Current State",
        f"- Severity: {severity}",
        f"- Affected services: {', '.join(services) if services else 'None'}",
        f"- Escalation level: {escalation.level.name.lower()}",
        f"- Evaluated events: {escalation.evaluated_event_count}",
        f"- Skipped events: {escalation.skipped_event_count + skipped_event_count}",
        "",
        "## Breach Warnings",
    ]
    lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(
        [
            "",
            "## Timeline Summary",
        ]
    )
    if timeline:
        for event in timeline:
            lines.append(
                "- {timestamp} | {severity} | {service} | {source}: {message}".format(
                    timestamp=event.get("timestamp", "unknown-time"),
                    severity=str(event.get("severity", "unknown")).lower(),
                    service=event.get("service", "unknown-service"),
                    source=event.get("source", "unknown-source"),
                    message=event.get("message", ""),
                )
            )
    else:
        lines.append("- No valid incident events.")

    lines.extend(
        [
            "",
            "## Action Checklist",
            f"- {escalation.next_recommended_action}",
        ]
    )
    if escalation.breached_policies:
        lines.append("- Confirm SLA breach owner and response clock.")
    if errors:
        lines.append("- Review skipped event validation errors.")
    lines.append("- Share this digest with the incident channel.")

    if errors:
        lines.extend(["", "## Input Warnings"])
        for error in errors:
            field = f" ({error['field']})" if "field" in error else ""
            lines.append(f"- Event {error['index']}{field}: {error['message']}")

    return "\n".join(lines) + "\n"


def _affected_services(timeline: Iterable[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            str(event["service"])
            for event in timeline
            if str(event.get("service", "")).strip()
        }
    )


def _skipped_event_count(errors: Iterable[Mapping[str, Any]]) -> int:
    indexes = {error.get("index") for error in errors if "index" in error}
    return len(indexes)


def _current_severity(timeline: Iterable[Mapping[str, Any]]) -> str:
    highest: Severity | None = None
    for event in timeline:
        parsed = Severity.parse(event.get("severity"))
        if parsed is not None and (highest is None or parsed > highest):
            highest = parsed
    return highest.name.lower() if highest is not None else "none"
