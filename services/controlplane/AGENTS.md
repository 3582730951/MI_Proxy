# AGENTS.md

## Control Plane Requirements
- Admin APIs must require authentication and tenant authorization.
- Security-sensitive actions must append audit logs.
- Failed rule or config publication must not replace the active version.
- Subscription tokens must be hashed at rest and individually revocable.
- WARP profile health must drive scheduler decisions.

