# Commit discipline (evidence claims)

House rule: do not present a reading of a file as a verified fact —
run it, paste the output, then claim it.

## Two claim languages

| Class | When | Commit message may say |
|-------|------|------------------------|
| **Device-verified** | Ran on aarch64 / py3.14 (or other named device), hashes matched | Device counts (e.g. 37/37) |
| **Container-only** | Ran only in CI / x86 container | Must say CONTAINER ONLY; must not cite device numbers |

Mixing them in one commit with device language is an overclaim.

## What must not go in until verified

- README roadmap boxes for items only container-tested
- rish-independence language from implementation unit tests
- Android claims outside the frozen P0 record
- Contract reference hashes transcribed but not recomputed against artifacts
  (mark `UNVERIFIED — transcribed, not recomputed` or recompute first)

## Root vs tests/

Scripts that resolve paths relative to `__file__` break if moved without
path edits. Prefer `tests/` and package imports; if root placement is
required, document it and re-run after any move.

## Preserved refutations

A refuted adjudicator kept under `records/` is an asset.
Do not leave it as `.bak` (gitignore / debris).
