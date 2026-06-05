# ADR 0001: Go-first monorepo for the initial acceptance slice

## Status
Accepted

## Context
The repository started with only `docs/plan.md`. The plan requires a control plane, lightweight agent, rule compiler, WARP pool scheduling, security gates, and a visual operations panel. Local tooling has Go available, while `pnpm` and `make` are not installed on the current Windows host.

## Decision
Use a Go-first monorepo for the first executable slice:

- `services/controlplane` for node, subscription, RBAC, config, audit, rule publish, and WARP pool logic.
- `agent` for low-resource mode, config apply, rollback, BBR/sysctl capability modeling, and idempotent tasks.
- `packages/rulecompiler` for rule priority, conflict detection, diff reports, and classification tests.
- `apps/web` for a dependency-free static operations dashboard.

## Consequences
This keeps local verification fast and avoids blocking on package installation. A future Next.js UI can replace `apps/web` after the API contract stabilizes.

## Rollback
If the project later requires the exact recommended stack, keep the Go packages as backend libraries and add a Next.js app as a new workspace without changing core rule or scheduling behavior.

