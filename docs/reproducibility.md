# Reproducibility

## Identity tuple

    R = (
        protocol_hash,
        policy_hash,
        environment_hash,
        seed,
        test_vector,
        software_identity
    )

## Statements

- repeatability ≠ correctness  
- determinism ≠ truth  

Do not claim determinism merely because hashes repeat.

## Known integrated replay

Under the recorded protocol, three successive integrated synthetic replays produce identical final ledger hashes.

The specification records:

    3196730984a89510c9a46e39ce7f84becf52edc24d1fdf5e0a6f199fed8efc33

as the observed result of those three identical runs.  
The current implementation asserts three-run identity; if the event schema or seed handling changes, the absolute hash value may differ and must be updated deliberately.

## Environment

- Python ≥ 3.10  
- OS: any POSIX-compatible host for synthetic tests  
- Dependencies: none required for core; `pytest` optional for test runner  
- Android P0 record: device-specific; not reproduced by CI  

## CI scope

GitHub Actions runs the synthetic/regression suite only.  
It does **not** run Android/rish experiments.
