# Runbooks

## P0: Suspected secret leakage
1. Revoke suspected subscription tokens, API keys, and Agent certificates.
2. Pause node config deployment.
3. Rotate database encryption keys and subscription signing keys.
4. Audit the last 7 to 30 days of access logs.
5. Produce an impact report.
6. Patch, retest, and publish only after security approval.

## P1: Subscription API high latency
1. Enable forced subscription cache mode.
2. Rate limit abnormal token and IP pairs.
3. Disable realtime compilation and serve the latest stable artifact.
4. Inspect database slow queries and Redis hit rate.
5. Scale API replicas if capacity is exhausted.

## P1: Bad route rules send mainland China sites through proxy
1. Freeze rule publication.
2. Roll back to the previous stable rule version.
3. Run `go test ./packages/rulecompiler`.
4. Inspect the diff report for direct rules covered by proxy or WARP rules.
5. Publish the fix to 5% canary.
6. Observe direct hit rate for 30 minutes before increasing rollout.

## P2: WARP pool degraded
1. Remove profiles with failed health probes.
2. Fallback affected sites to proxy-default or direct according to policy.
3. Pause WARP profile creation.
4. Inspect DNS, HTTP, and WireGuard handshake logs.
5. Restore recovered profiles through cooldown and low traffic canary.

## P2: Agent batch offline
1. Check control plane certificates, Agent mTLS, and time sync.
2. Check whether the latest config caused Agent crashes.
3. Roll back the Agent config version.
4. Restart Agents in batches capped at 5%.
5. Mark unrecovered nodes degraded and drain scheduled traffic away.

## P3: UI or metric display issue
1. Confirm API health and data availability.
2. Capture the affected view and browser console errors.
3. Patch the visualization or query.
4. Verify the dashboard and audit that no operational action was affected.

