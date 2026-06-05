# AGENTS.md

## Project Goal
Build a secure, observable, low-resource sing-box operations panel with rule compilation, WARP pool management, subscription generation, and node agents.

## Non-negotiable Constraints
- Never introduce unauthenticated admin APIs.
- Never log secrets, private keys, subscription tokens, or WARP private keys.
- All security-sensitive code must include tests.
- Any command execution must use allowlisted commands and structured args, never shell string concatenation.
- Rule changes must pass domain-classification tests.
- Google Scholar must never be routed through WARP.
- Mainland China domains and IP ranges must prefer direct routes.
- Every PR must update docs and tests.

## Required Commands
- go test ./...
- go run ./cmd/security-scan
- go run ./cmd/sbom
- go run ./cmd/acceptance
- pnpm test
- pnpm lint
- pnpm typecheck
- make security-scan
- make rule-test
- make e2e

## PR Requirements
- Explain design choices.
- Include risk analysis.
- Include rollback plan.
- Include screenshots for UI changes.
- Include benchmark results for performance-sensitive changes.

