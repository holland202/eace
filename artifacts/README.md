# Artifacts

This directory is reserved for experiment outputs that are intentionally committed
(e.g., frozen hash records, small reference blobs).

Do **not** place:

- device-private data  
- credentials  
- large binaries  
- temporary run directories  

Temporary run artifacts should live under `artifacts/tmp/` (gitignored).
