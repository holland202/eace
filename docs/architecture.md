# Architecture

## Components

| Module | Role |
|--------|------|
| `clock.py` | Deterministic logical clock for reproducible timestamps |
| `ledger.py` | Append-only evidence ledger with hash chaining |
| `governor.py` | Capability-envelope enforcement at (tool, target, operation, parameters) |
| `synthetic_services.py` | Localhost-only synthetic world (public + protected services) |
| `agent.py` | Synthetic agent whose actions are governed and recorded |
| `experiment.py` | Integrated replay runner |
| `verifier.py` | Historical v0.1 (vulnerable) and v0.2 (fail-closed) verifiers |

## Data flow

1. Agent proposes action.
2. Governor authorises or denies.
3. World executes (or rejects).
4. Evidence event is appended to ledger; head hash updated.
5. Verifier evaluates artifacts against external contract (v0.2).

## Design constraints

- No third-party network targets.
- No credentials.
- No destructive operations.
- Evaluator is itself an experimental object.
