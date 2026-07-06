# Ops Pulse

Ops Pulse is a deliberately small Python package used to verify Agent Harness
multi-ticket implementation workflows.

## Product Direction

Operators paste incident event streams into the tool and receive a compact
operations digest:

- a normalized event timeline with stable ordering and duplicate suppression
- escalation policy evaluation with SLA breach detection
- a Markdown digest suitable for a Slack or incident-room update

## Development

Run tests with:

```bash
python -m pytest -q
```

Keep implementation modules small and dependency-free unless a ticket explicitly
requires an external package.
