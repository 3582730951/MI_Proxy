# AGENTS.md

## Agent Requirements
- Keep runtime dependency-free and suitable for a static Go binary.
- Default target RSS is below 40 MB.
- Low-resource mode must reduce metrics frequency and connection limits.
- Config apply must support validation, diff apply, and rollback.
- Dangerous tasks must be idempotent across agent restarts.

