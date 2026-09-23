import sys

def verify_veritas_output(stdout: str, stderr: str, returncode: int) -> bool:
    """
    Fail-closed post-execution check for the Veritas gate.
    Never treats a crash, empty run, or missing pipeline stage as a PASS.
    """
    violations = []

    # 1. Exit-code discipline (0 = looked and clean)
    if returncode != 0:
        violations.append(
            f"VERITAS_FAIL: non-zero exit ({returncode}). "
            f"stderr={stderr.strip()[:400]!r}"
        )

    # 2. Masked crash / exception leakage (even on exit 0)
    crash_markers = (
        "Traceback (most recent call last)",
        "Exception:",
        "Error:",
        "AssertionError",
        "RuntimeError",
    )
    for marker in crash_markers:
        if marker in stdout or marker in stderr:
            violations.append(
                f"VERITAS_FAIL: crash/exception marker present ({marker!r})"
            )
            break

    # 3. Vacuity / pipeline-execution check
    required_tokens = (
        "STATE_VECTOR_MAPPING",
        "DETERMINISTIC_COLLAPSE",
    )
    for token in required_tokens:
        if token not in stdout:
            violations.append(
                f"VERITAS_FAIL: mandatory pipeline token missing ({token!r})"
            )

    # 4. Zero-output success is not success
    if returncode == 0 and not stdout.strip():
        violations.append(
            "VERITAS_FAIL: empty stdout on exit 0 (no evidence of work)"
        )

    if violations:
        print("\n".join(violations), file=sys.stderr)
        sys.exit(1)

    print("VERITAS_POST_CHECK: PASS")
    return True


if __name__ == "__main__":
    print("veritas_postcheck.py loaded. "
          "Import and call verify_veritas_output(stdout, stderr, rc)")
