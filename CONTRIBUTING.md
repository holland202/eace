# Contributing

## Principles

1. Evidence > narrative  
2. Reproduction > assertion  
3. Adversarial failure > happy-path success  
4. Explicit uncertainty > inflated conclusion  

## Pull requests

- All tests must pass: `python -m pytest -q`
- Do not remove or rewrite the historical v0.1 attack record.
- Do not convert `NOT_TESTED` / `AMBIGUOUS` into success verdicts.
- New verifier behaviour must be accompanied by adversarial tests.
- Avoid marketing language in documentation.

## Commit style

Prefer clear, research-oriented messages. Suggested historical sequence is documented in the repository specification; new work should continue the scientific record rather than squash it.
