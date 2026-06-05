# Release gates

This project does not treat local smoke evidence as production release approval. `scripts/release-gate.ps1` has two modes:

- Local evidence mode checks license scan, IaC scan, SBOM, acceptance, and provenance files under `dist/`; the provenance artifact must include the license and IaC scan artifact hashes.
- External evidence mode adds the full `docs/plan.md` release blockers: protected main, full staging DAST, 2,000 RPS for 30 minutes, toxiproxy DB/Redis chaos, human review, GPT-5.5 architecture/security review, cosign signature, SLSA provenance, and 24-hour canary.

## Required external evidence

The release workflow passes these records to `scripts/release-gate.ps1 -RequireExternalEvidence`:

- `MAIN_BRANCH_PROTECTED=true`
- `HUMAN_REVIEW_APPROVED=true`
- `GPT55_REVIEW_APPROVED=true`
- `CANARY_24H_PASSED=true`
- `STAGING_DAST_EVIDENCE=<artifact-or-url>`
- `FULL_LOAD_EVIDENCE=<artifact-or-url>`
- `TOXIPROXY_CHAOS_EVIDENCE=<artifact-or-url>`
- `COSIGN_SIGNATURE_REF=<image-or-artifact-ref>`
- `SLSA_PROVENANCE_REF=<attestation-ref>`

If any value is missing, the release gate fails. The local acceptance report records the smoke status, while the external evidence variables decide release readiness.

## Rollback

Release rollback uses the previous signed image digest and the previous accepted config version. If canary detects P0/P1 impact, pause rollout, restore the prior digest, run `cmd/acceptance` and `cmd/chaos-smoke`, then attach the incident and rollback evidence to the release record.
