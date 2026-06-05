# Toxiproxy Chaos Plan

Run from a deployed staging environment:

```sh
docker compose -f tests/chaos/docker-compose.toxiproxy.yml up -d
toxiproxy-cli create postgres -l 0.0.0.0:15432 -u postgres:5432
toxiproxy-cli create redis -l 0.0.0.0:16379 -u redis:6379
toxiproxy-cli toxic add postgres -t timeout -a timeout=60000
toxiproxy-cli toxic add redis -t timeout -a timeout=300000
```

Passing criteria from `docs/plan.md`:

- Database failover or restart recovers within 60 seconds without data loss.
- Redis outage for 5 minutes leaves core APIs degraded but available.
- Agent batch restart does not repeat dangerous tasks.

