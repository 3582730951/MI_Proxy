CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'dev',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  agent_version TEXT NOT NULL DEFAULT '',
  singbox_version TEXT NOT NULL DEFAULT '',
  kernel_version TEXT NOT NULL DEFAULT '',
  congestion_control TEXT NOT NULL DEFAULT '',
  queue_discipline TEXT NOT NULL DEFAULT '',
  public_ip INET,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS node_metrics (
  id BIGSERIAL PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id),
  ts TIMESTAMPTZ NOT NULL,
  cpu DOUBLE PRECISION NOT NULL,
  memory DOUBLE PRECISION NOT NULL,
  load_avg DOUBLE PRECISION NOT NULL,
  rx_bps BIGINT NOT NULL,
  tx_bps BIGINT NOT NULL,
  connections INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS configs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  version INTEGER NOT NULL,
  content_hash TEXT NOT NULL,
  content JSONB NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL,
  UNIQUE (tenant_id, version)
);

CREATE TABLE IF NOT EXISTS config_deployments (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id),
  config_id TEXT NOT NULL REFERENCES configs(id),
  status TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  priority INTEGER NOT NULL,
  type TEXT NOT NULL,
  matcher TEXT NOT NULL,
  outbound TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  source TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_sets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  source_url TEXT NOT NULL,
  checksum TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL,
  token_kind TEXT NOT NULL,
  scope TEXT NOT NULL,
  client_type TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  revoked BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS warp_profiles (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  node_id TEXT NOT NULL REFERENCES nodes(id),
  name TEXT NOT NULL,
  public_key TEXT NOT NULL,
  encrypted_private_key BYTEA NOT NULL,
  status TEXT NOT NULL,
  last_probe_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS warp_probe_results (
  id BIGSERIAL PRIMARY KEY,
  warp_profile_id TEXT NOT NULL REFERENCES warp_profiles(id),
  ts TIMESTAMPTZ NOT NULL,
  latency_ms DOUBLE PRECISION NOT NULL,
  loss DOUBLE PRECISION NOT NULL,
  http_success BOOLEAN NOT NULL,
  exit_ip INET,
  asn TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  ip INET,
  user_agent TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  title TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL,
  resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_nodes_tenant_status ON nodes(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_node_metrics_node_ts ON node_metrics(node_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_configs_tenant_version ON configs(tenant_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_configs_created_at ON configs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_config_deployments_node ON config_deployments(node_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_rules_tenant_priority ON rules(tenant_id, priority);
CREATE INDEX IF NOT EXISTS idx_subscriptions_token_hash ON subscriptions(token_hash);
CREATE INDEX IF NOT EXISTS idx_subscriptions_tenant_user ON subscriptions(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_warp_profiles_tenant_status ON warp_profiles(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_warp_probe_profile_ts ON warp_probe_results(warp_profile_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status ON incidents(tenant_id, status);

