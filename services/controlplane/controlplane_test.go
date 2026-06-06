package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sing-box-next-panel/packages/rulecompiler"
)

func TestNodeRegistryHeartbeatsOfflineAlertAndTaskRecovery(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	node, err := cp.RegisterNode(ctx, NodeRegistration{
		ID:                "node-1",
		TenantID:          "tenant-a",
		Name:              "hk-01",
		Region:            "HK",
		Provider:          "vps",
		AgentVersion:      "0.1.0",
		SingBoxVersion:    "1.11.0",
		KernelVersion:     "6.8",
		CongestionControl: "bbr",
		QueueDiscipline:   "fq",
		PublicIP:          "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	if node.Status != NodeOnline {
		t.Fatalf("node status %s, want online", node.Status)
	}

	for i := 0; i < 1000; i++ {
		if err := cp.Heartbeat(ctx, "node-1", Heartbeat{CPU: 0.2, Memory: 0.3, Connections: i, At: now.Add(time.Duration(i) * time.Millisecond)}); err != nil {
			t.Fatalf("heartbeat %d: %v", i, err)
		}
	}

	cp.SweepNodeStates(now.Add(29 * time.Second))
	got, _ := cp.Overview(ctx, "tenant-a")
	if got.OfflineNodes != 0 {
		t.Fatalf("latest heartbeat should keep node online, offline=%d", got.OfflineNodes)
	}

	cp.mu.Lock()
	stale := cp.nodes["node-1"]
	stale.LastSeenAt = now
	cp.nodes["node-1"] = stale
	cp.mu.Unlock()
	cp.SweepNodeStates(now.Add(31 * time.Second))
	got, _ = cp.Overview(ctx, "tenant-a")
	if got.OfflineNodes != 1 {
		t.Fatalf("offline after 30s not reflected: %+v", got)
	}
	alerts := cp.SweepNodeStates(now.Add(2*time.Minute + time.Second))
	if len(alerts) != 1 {
		t.Fatalf("expected offline alert within 2m, got %d", len(alerts))
	}

	if !cp.ClaimDangerousTask("node-1", "restart-sing-box") {
		t.Fatal("first dangerous task claim failed")
	}
	if cp.ClaimDangerousTask("node-1", "restart-sing-box") {
		t.Fatal("duplicate dangerous task was accepted")
	}
	recovered := cp.RecoverRunningTasks("node-1")
	if len(recovered) != 1 || recovered[0] != "restart-sing-box" {
		t.Fatalf("running task not recoverable after agent restart: %v", recovered)
	}
	cp.CompleteDangerousTask("node-1", "restart-sing-box")
	if cp.ClaimDangerousTask("node-1", "restart-sing-box") {
		t.Fatal("completed dangerous task should not repeat")
	}
}

func TestNodeMetricTimeSeriesRetentionOverviewAndABAC(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	if _, err := cp.RegisterNode(ctx, NodeRegistration{ID: "node-hk", TenantID: "tenant-a", Region: "HK", Tags: []string{"warp"}, Environment: "prod"}); err != nil {
		t.Fatalf("register hk node: %v", err)
	}
	if _, err := cp.RegisterNode(ctx, NodeRegistration{ID: "node-us", TenantID: "tenant-a", Region: "US", Tags: []string{"edge"}, Environment: "prod"}); err != nil {
		t.Fatalf("register us node: %v", err)
	}

	sanitized, err := cp.RecordNodeMetric(ctx, NodeMetricSample{
		NodeID:      "node-hk",
		CPU:         2,
		Memory:      -1,
		RxBps:       100,
		TxBps:       200,
		RxBytes:     10,
		TxBytes:     20,
		NetworkPPS:  7,
		Connections: -3,
	})
	if err != nil {
		t.Fatalf("record metric: %v", err)
	}
	if sanitized.CPU != 1 || sanitized.Memory != 0 || sanitized.Connections != 0 {
		t.Fatalf("metric sample not sanitized: %+v", sanitized)
	}

	for i := 0; i < nodeMetricSampleLimit+5; i++ {
		_, err := cp.RecordNodeMetric(ctx, NodeMetricSample{
			NodeID:      "node-hk",
			At:          now.Add(time.Duration(i) * time.Second),
			CPU:         0.4,
			Memory:      0.5,
			Disk:        0.6,
			FDUsage:     0.7,
			RxBps:       int64(i),
			TxBps:       int64(i * 2),
			RxBytes:     int64(i * 10),
			TxBytes:     int64(i * 20),
			NetworkPPS:  float64(i),
			Connections: i,
		})
		if err != nil {
			t.Fatalf("record metric %d: %v", i, err)
		}
	}

	cp.mu.RLock()
	retained := len(cp.nodeMetricSamples)
	firstRetained := cp.nodeMetricSamples[0]
	cp.mu.RUnlock()
	if retained != nodeMetricSampleLimit || firstRetained.Connections != 5 {
		t.Fatalf("metric retention failed: retained=%d first=%+v", retained, firstRetained)
	}

	samples, err := cp.QueryNodeMetrics(ctx, "tenant-a", "node-hk", 3)
	if err != nil {
		t.Fatalf("query metrics: %v", err)
	}
	if len(samples) != 3 || samples[0].Connections != nodeMetricSampleLimit+2 || samples[2].Connections != nodeMetricSampleLimit+4 {
		t.Fatalf("query should return recent samples in time order: %+v", samples)
	}

	overview, err := cp.Overview(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	latestConnectionCount := nodeMetricSampleLimit + 4
	latestBps := int64(latestConnectionCount)
	if overview.TotalConnections != latestConnectionCount || overview.DownBps != latestBps || overview.UpBps != latestBps*2 {
		t.Fatalf("overview did not aggregate latest metric sample: %+v", overview)
	}
	capacity, err := cp.CapacityPlan(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("capacity plan: %v", err)
	}
	if capacity.Tier != "Medium" || capacity.TargetSubscriptionRPS != 500 || capacity.TargetAPIRPS != 1000 || capacity.RecommendedAPIReplicas != 3 {
		t.Fatalf("capacity plan did not map load to medium tier: %+v", capacity)
	}
	if len(capacity.AutoscalingActions) == 0 || len(capacity.CostActions) == 0 {
		t.Fatalf("capacity plan missing autoscaling or cost actions: %+v", capacity)
	}

	if _, err := cp.RecordNodeMetric(ctx, NodeMetricSample{NodeID: "node-us", Connections: 77}); err != nil {
		t.Fatalf("record us metric: %v", err)
	}
	restricted := adminCtx("tenant-a")
	restricted.AllowedRegions = []string{"HK"}
	if _, err := cp.QueryNodeMetrics(restricted, "tenant-a", "node-us", 1); !errors.Is(err, ErrForbidden) {
		t.Fatalf("restricted metrics query err=%v, want forbidden", err)
	}
	overview, err = cp.Overview(restricted, "tenant-a")
	if err != nil {
		t.Fatalf("restricted overview: %v", err)
	}
	if overview.OnlineNodes != 1 || overview.TotalConnections != nodeMetricSampleLimit+4 {
		t.Fatalf("restricted overview leaked disallowed node metrics: %+v", overview)
	}
}

func TestAlertsQuerySanitizesAcknowledgesAndHonorsABAC(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	if _, err := cp.RegisterNode(ctx, NodeRegistration{ID: "node-hk", TenantID: "tenant-a", Region: "HK", Tags: []string{"warp"}, Environment: "prod"}); err != nil {
		t.Fatalf("register hk node: %v", err)
	}
	if _, err := cp.RegisterNode(ctx, NodeRegistration{ID: "node-us", TenantID: "tenant-a", Region: "US", Tags: []string{"edge"}, Environment: "prod"}); err != nil {
		t.Fatalf("register us node: %v", err)
	}
	cp.mu.Lock()
	cp.alerts = append(cp.alerts,
		Alert{ID: "alert-hk", TenantID: "tenant-a", NodeID: "node-hk", Severity: "P2", Message: `<script>alert(1)</script> token=secret`, CreatedAt: now},
		Alert{ID: "alert-us", TenantID: "tenant-a", NodeID: "node-us", Severity: "P3", Message: "node overloaded", CreatedAt: now.Add(time.Second)},
	)
	cp.mu.Unlock()

	restricted := adminCtx("tenant-a")
	restricted.AllowedRegions = []string{"HK"}
	alerts, err := cp.Alerts(restricted, "tenant-a")
	if err != nil {
		t.Fatalf("restricted alerts: %v", err)
	}
	if len(alerts) != 1 || alerts[0].ID != "alert-hk" {
		t.Fatalf("restricted alert query leaked disallowed node: %+v", alerts)
	}
	if strings.Contains(alerts[0].Message, "<script>") || strings.Contains(alerts[0].Message, "secret") || !strings.Contains(alerts[0].Message, "REDACTED") {
		t.Fatalf("alert message not sanitized: %q", alerts[0].Message)
	}
	if _, err := cp.AcknowledgeAlert(restricted, "tenant-a", "alert-us"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("restricted ack err=%v, want forbidden", err)
	}
	noConfirm := restricted
	noConfirm.Confirmed = false
	if _, err := cp.AcknowledgeAlert(noConfirm, "tenant-a", "alert-hk"); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("ack without confirmation err=%v, want confirmation required", err)
	}

	ack, err := cp.AcknowledgeAlert(restricted, "tenant-a", "alert-hk")
	if err != nil {
		t.Fatalf("ack alert: %v", err)
	}
	if ack.Status != alertStatusAcknowledged || ack.AcknowledgedBy != restricted.User.ID {
		t.Fatalf("ack response incomplete: %+v", ack)
	}
	overview, err := cp.Overview(restricted, "tenant-a")
	if err != nil {
		t.Fatalf("restricted overview: %v", err)
	}
	if overview.Alerts != 0 {
		t.Fatalf("acknowledged alert should not count in restricted overview: %+v", overview)
	}
	auditLogs, err := cp.AuditLogs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("audit logs: %v", err)
	}
	if !hasAuditAction(auditLogs, "alert.acknowledge") {
		t.Fatalf("alert acknowledgement missing audit log: %+v", auditLogs)
	}
}

func TestSecurityWaiversRequireOwnerExpiryRemediationAndAudit(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	if _, err := cp.CreateSecurityWaiver(ctx, SecurityWaiver{
		Gate:            "DAST",
		Owner:           "sec@example.com",
		RemediationPlan: "rerun staging zap",
		ExpiresAt:       now.Add(-time.Hour),
	}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("expired waiver err=%v, want bad request", err)
	}
	noConfirm := ctx
	noConfirm.Confirmed = false
	if _, err := cp.CreateSecurityWaiver(noConfirm, SecurityWaiver{
		Gate:            "DAST",
		Owner:           "sec@example.com",
		RemediationPlan: "rerun staging zap",
		ExpiresAt:       now.Add(time.Hour),
	}); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("unconfirmed waiver err=%v, want confirmation", err)
	}

	waiver, err := cp.CreateSecurityWaiver(ctx, SecurityWaiver{
		ID:              "waiver-1",
		Gate:            `<script>DAST</script>`,
		Severity:        "P1",
		Owner:           "sec@example.com",
		Reason:          "scanner outage token=secret",
		RemediationPlan: "rerun staging zap and attach report",
		ExpiresAt:       now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("create security waiver: %v", err)
	}
	if strings.Contains(waiver.Gate, "<script>") || strings.Contains(waiver.Reason, "secret") || !strings.Contains(waiver.Reason, "REDACTED") {
		t.Fatalf("waiver fields not sanitized: %+v", waiver)
	}
	waivers, err := cp.ListSecurityWaivers(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("list security waivers: %v", err)
	}
	if len(waivers) != 1 || waivers[0].Owner == "" || waivers[0].RemediationPlan == "" || !waivers[0].ExpiresAt.After(now) {
		t.Fatalf("waiver missing required evidence: %+v", waivers)
	}
	logs, err := cp.AuditLogs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("audit logs: %v", err)
	}
	if !hasAuditAction(logs, "security.waiver.create") {
		t.Fatalf("security waiver creation missing audit log: %+v", logs)
	}
}

func TestProtocolInboundStatsFromHeartbeatAndABAC(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	if _, err := cp.RegisterNode(ctx, NodeRegistration{ID: "node-hk", TenantID: "tenant-a", Region: "HK", Tags: []string{"warp"}, Environment: "prod"}); err != nil {
		t.Fatalf("register hk node: %v", err)
	}
	if _, err := cp.RegisterNode(ctx, NodeRegistration{ID: "node-us", TenantID: "tenant-a", Region: "US", Tags: []string{"edge"}, Environment: "prod"}); err != nil {
		t.Fatalf("register us node: %v", err)
	}
	if err := cp.Heartbeat(ctx, "node-hk", Heartbeat{ProtocolStats: []ProtocolInboundStat{
		{Protocol: "VLESS", Connections: 4, RxBps: 100, TxBps: 50},
		{Protocol: "hy2", Connections: 2, RxBps: 40, TxBps: 20, Errors: 1},
		{Protocol: "unknown", Connections: 99, RxBps: 99, TxBps: 99},
		{Protocol: "vless", Connections: -10, RxBps: -5, TxBps: 5, Errors: -1},
	}}); err != nil {
		t.Fatalf("hk heartbeat: %v", err)
	}
	if err := cp.Heartbeat(ctx, "node-us", Heartbeat{ProtocolStats: []ProtocolInboundStat{
		{Protocol: "trojan", Connections: 7, RxBps: 700, TxBps: 300},
	}}); err != nil {
		t.Fatalf("us heartbeat: %v", err)
	}

	node, err := cp.GetNode(ctx, "node-hk")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if len(node.ProtocolStats) != 2 || node.ProtocolStats[0].Protocol != "vless" || node.ProtocolStats[0].Connections != 4 || node.ProtocolStats[0].TxBps != 55 || node.ProtocolStats[1].Protocol != "hysteria2" {
		t.Fatalf("node protocol stats not normalized: %+v", node.ProtocolStats)
	}
	node.ProtocolStats[0].Connections = 999
	stored, err := cp.GetNode(ctx, "node-hk")
	if err != nil {
		t.Fatalf("get stored node: %v", err)
	}
	if stored.ProtocolStats[0].Connections == 999 {
		t.Fatalf("node protocol stats were not copied on return: %+v", stored.ProtocolStats)
	}

	stats, err := cp.ProtocolStats(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("protocol stats: %v", err)
	}
	if len(stats) != 3 || stats[0].Protocol != "vless" || stats[1].Protocol != "hysteria2" || stats[2].Protocol != "trojan" {
		t.Fatalf("protocol stats not aggregated in stable order: %+v", stats)
	}
	restricted := adminCtx("tenant-a")
	restricted.AllowedRegions = []string{"HK"}
	stats, err = cp.ProtocolStats(restricted, "tenant-a")
	if err != nil {
		t.Fatalf("restricted protocol stats: %v", err)
	}
	if len(stats) != 2 || stats[0].Protocol != "vless" || stats[1].Protocol != "hysteria2" {
		t.Fatalf("restricted protocol stats leaked disallowed node: %+v", stats)
	}
}

func TestKernelTuningStatusFromRegistrationHeartbeatAndABAC(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	if _, err := cp.RegisterNode(ctx, NodeRegistration{
		ID:                "node-good",
		TenantID:          "tenant-a",
		Region:            "HK",
		CongestionControl: "bbr2",
		QueueDiscipline:   "fq",
		NoFile:            1_048_576,
		SomaxConn:         4096,
		TCPFastOpen:       3,
		PortRangeStart:    10000,
		PortRangeEnd:      65000,
	}); err != nil {
		t.Fatalf("register tuned node: %v", err)
	}
	if _, err := cp.RegisterNode(ctx, NodeRegistration{
		ID:                "node-needs-tune",
		TenantID:          "tenant-a",
		Region:            "US",
		CongestionControl: "cubic",
		NoFile:            1024,
		SomaxConn:         128,
		PortRangeStart:    40000,
		PortRangeEnd:      45000,
	}); err != nil {
		t.Fatalf("register untuned node: %v", err)
	}

	rows, err := cp.KernelTuning(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("kernel tuning: %v", err)
	}
	if len(rows) != 2 || !rows[0].Tuned || rows[1].Tuned || !containsString(rows[1].Issues, "nofile_below_target") {
		t.Fatalf("unexpected kernel tuning rows: %+v", rows)
	}

	if err := cp.Heartbeat(ctx, "node-needs-tune", Heartbeat{
		CongestionControl: "bbr",
		QueueDiscipline:   "fq",
		NoFile:            1_048_576,
		SomaxConn:         4096,
		TCPFastOpen:       3,
		PortRangeStart:    10000,
		PortRangeEnd:      65000,
	}); err != nil {
		t.Fatalf("heartbeat tuning update: %v", err)
	}
	rows, err = cp.KernelTuning(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("kernel tuning after heartbeat: %v", err)
	}
	if !rows[1].Tuned {
		t.Fatalf("heartbeat tuning update not reflected: %+v", rows[1])
	}

	restricted := adminCtx("tenant-a")
	restricted.AllowedRegions = []string{"HK"}
	rows, err = cp.KernelTuning(restricted, "tenant-a")
	if err != nil {
		t.Fatalf("restricted kernel tuning: %v", err)
	}
	if len(rows) != 1 || rows[0].NodeID != "node-good" {
		t.Fatalf("restricted kernel tuning leaked disallowed node: %+v", rows)
	}
}

func TestRBACAndTenantIsolation(t *testing.T) {
	cp := New(nil)
	ctxA := adminCtx("tenant-a")
	if _, err := cp.RegisterNode(ctxA, NodeRegistration{ID: "node-a", TenantID: "tenant-a"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	ctxB := RequestContext{User: User{ID: "admin-b", TenantID: "tenant-b", Role: RoleAdmin}}
	if err := cp.Heartbeat(ctxB, "node-a", Heartbeat{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant B heartbeat err=%v, want forbidden", err)
	}

	operator := RequestContext{User: User{ID: "op-a", TenantID: "tenant-a", Role: RoleOperator}, Confirmed: true}
	if _, err := cp.PublishConfig(operator, "tenant-a", "{}", false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("operator publish err=%v, want forbidden", err)
	}
	if err := cp.Runbook(operator, "tenant-a", "inc-1", "rollback-config"); err != nil {
		t.Fatalf("operator should run runbook: %v", err)
	}
}

func TestNodeABACRestrictsRegionTagsAndEnvironment(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	if _, err := cp.RegisterNode(ctx, NodeRegistration{
		ID:          "node-hk-prod",
		TenantID:    "tenant-a",
		Region:      "HK",
		Tags:        []string{"edge", "warp"},
		Environment: "prod",
	}); err != nil {
		t.Fatalf("register hk prod: %v", err)
	}
	if _, err := cp.RegisterNode(ctx, NodeRegistration{
		ID:          "node-us-dev",
		TenantID:    "tenant-a",
		Region:      "US",
		Tags:        []string{"edge"},
		Environment: "dev",
	}); err != nil {
		t.Fatalf("register us dev: %v", err)
	}

	restricted := RequestContext{
		User:                User{ID: "regional-admin", TenantID: "tenant-a", Role: RoleAdmin},
		IP:                  net.ParseIP("198.51.100.20"),
		AllowedRegions:      []string{"hk"},
		AllowedNodeTags:     []string{"warp"},
		AllowedEnvironments: []string{"PROD"},
		Confirmed:           true,
	}
	nodes, err := cp.ListNodes(restricted, "tenant-a")
	if err != nil {
		t.Fatalf("list restricted nodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].ID != "node-hk-prod" {
		t.Fatalf("restricted list returned %+v, want only node-hk-prod", nodes)
	}
	nodes[0].Tags[0] = "mutated"
	stored, err := cp.GetNode(ctx, "node-hk-prod")
	if err != nil {
		t.Fatalf("get stored node: %v", err)
	}
	if stored.Tags[0] != "edge" {
		t.Fatalf("node tags were not copied on return: %+v", stored.Tags)
	}

	if _, err := cp.GetNode(restricted, "node-hk-prod"); err != nil {
		t.Fatalf("restricted get allowed node: %v", err)
	}
	if _, err := cp.GetNode(restricted, "node-us-dev"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("restricted get disallowed node err=%v, want forbidden", err)
	}
	if err := cp.Heartbeat(restricted, "node-us-dev", Heartbeat{Connections: 11}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("restricted heartbeat disallowed node err=%v, want forbidden", err)
	}
	if err := cp.Heartbeat(restricted, "node-hk-prod", Heartbeat{Connections: 3}); err != nil {
		t.Fatalf("restricted heartbeat allowed node: %v", err)
	}
	if _, err := cp.RegisterNode(restricted, NodeRegistration{ID: "node-us-prod", TenantID: "tenant-a", Region: "US", Tags: []string{"warp"}, Environment: "prod"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("restricted register disallowed node err=%v, want forbidden", err)
	}
	if _, err := cp.RegisterNode(restricted, NodeRegistration{ID: "node-hk-prod-2", TenantID: "tenant-a", Region: "HK", Tags: []string{"warp"}, Environment: "prod"}); err != nil {
		t.Fatalf("restricted register allowed node: %v", err)
	}
	if _, err := cp.DeployConfig(restricted, "node-us-dev", "{}", false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("restricted deploy disallowed node err=%v, want forbidden", err)
	}
	if _, _, err := cp.RotateAgentCredential(restricted, "node-us-dev", time.Now().Add(time.Hour)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("restricted rotate disallowed node err=%v, want forbidden", err)
	}
	overview, err := cp.Overview(restricted, "tenant-a")
	if err != nil {
		t.Fatalf("restricted overview: %v", err)
	}
	if overview.OnlineNodes != 2 || overview.TotalConnections != 3 {
		t.Fatalf("restricted overview leaked disallowed node metrics: %+v", overview)
	}
}

func TestAgentMTLSCredentialRotationAndHeartbeatScope(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	if _, err := cp.RegisterNode(ctx, NodeRegistration{ID: "node-agent", TenantID: "tenant-a"}); err != nil {
		t.Fatalf("register node: %v", err)
	}

	credential, fingerprint, err := cp.RotateAgentCredential(ctx, "node-agent", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("rotate credential: %v", err)
	}
	if credential.FingerprintHash == "" || credential.FingerprintHash == fingerprint {
		t.Fatalf("agent fingerprint must be hashed at rest: %+v", credential)
	}
	agentCtx, err := cp.AuthenticateAgent("node-agent", fingerprint, "198.51.100.20")
	if err != nil {
		t.Fatalf("authenticate agent: %v", err)
	}
	if err := cp.Heartbeat(agentCtx, "node-agent", Heartbeat{AgentVersion: "agent-mtls", Connections: 7}); err != nil {
		t.Fatalf("agent heartbeat: %v", err)
	}
	node, err := cp.GetNode(ctx, "node-agent")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if node.AgentVersion != "agent-mtls" || node.Connections != 7 {
		t.Fatalf("agent heartbeat did not update node: %+v", node)
	}

	_, nextFingerprint, err := cp.RotateAgentCredential(ctx, "node-agent", now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("rotate second credential: %v", err)
	}
	if _, err := cp.AuthenticateAgent("node-agent", fingerprint, "198.51.100.20"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("old agent fingerprint err=%v, want revoked", err)
	}
	if _, err := cp.AuthenticateAgent("node-agent", nextFingerprint, "198.51.100.20"); err != nil {
		t.Fatalf("new agent fingerprint failed: %v", err)
	}

	spoofedAgent := RequestContext{User: User{ID: "agent:node-agent", TenantID: "tenant-a", Role: RoleDeveloper}}
	if err := cp.Heartbeat(spoofedAgent, "node-agent", Heartbeat{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("spoofed agent header err=%v, want forbidden", err)
	}

	_, scopedToken, err := cp.CreateAPIToken(ctx, "tenant-a", RoleAdmin, []string{"rules:read"}, []string{"198.51.100.10"}, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("create scoped token: %v", err)
	}
	scopedCtx, err := cp.AuthenticateAPIToken(scopedToken, "198.51.100.10")
	if err != nil {
		t.Fatalf("authenticate scoped token: %v", err)
	}
	if err := cp.Heartbeat(scopedCtx, "node-agent", Heartbeat{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("scoped token heartbeat err=%v, want forbidden", err)
	}
}

func TestPasskeyRegistrationAuthenticationAndReplayProtection(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	challenge, rawChallenge, err := cp.BeginPasskeyRegistration(ctx, "example.com", "https://panel.example.com", now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("begin passkey registration: %v", err)
	}
	if challenge.ChallengeHash != "" {
		t.Fatal("public registration challenge leaked challenge hash")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate passkey key: %v", err)
	}
	encodedPublicKey, err := EncodePasskeyPublicKey(privateKey.PublicKey)
	if err != nil {
		t.Fatalf("encode passkey public key: %v", err)
	}
	credential, err := cp.RegisterPasskey(ctx, challenge.ID, rawChallenge, "cred-admin", encodedPublicKey, 1)
	if err != nil {
		t.Fatalf("register passkey: %v", err)
	}
	if credential.PublicKey == "" || credential.TenantID != "tenant-a" || credential.Role != RoleAdmin {
		t.Fatalf("invalid stored passkey credential: %+v", credential)
	}
	if _, err := cp.RegisterPasskey(ctx, challenge.ID, rawChallenge, "cred-admin-2", encodedPublicKey, 1); !errors.Is(err, ErrForbidden) {
		t.Fatalf("passkey challenge replay err=%v, want forbidden", err)
	}

	authChallenge, rawAuthChallenge, err := cp.BeginPasskeyAuthentication(ctx.User.ID, "cred-admin", "example.com", "https://panel.example.com", now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("begin passkey auth: %v", err)
	}
	signCount := uint32(2)
	hash := PasskeySignatureHash(rawAuthChallenge, "example.com", "https://panel.example.com", ctx.User.ID, "cred-admin", signCount)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash)
	if err != nil {
		t.Fatalf("sign passkey assertion: %v", err)
	}
	passkeyCtx, err := cp.VerifyPasskeyAuthentication(authChallenge.ID, rawAuthChallenge, signature, signCount, "198.51.100.10")
	if err != nil {
		t.Fatalf("verify passkey auth: %v", err)
	}
	if passkeyCtx.User.ID != ctx.User.ID || passkeyCtx.User.TenantID != ctx.User.TenantID || !passkeyCtx.Confirmed {
		t.Fatalf("invalid passkey auth context: %+v", passkeyCtx)
	}

	nextChallenge, nextRawChallenge, err := cp.BeginPasskeyAuthentication(ctx.User.ID, "cred-admin", "example.com", "https://panel.example.com", now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("begin replay auth: %v", err)
	}
	replayHash := PasskeySignatureHash(nextRawChallenge, "example.com", "https://panel.example.com", ctx.User.ID, "cred-admin", signCount)
	replaySignature, err := ecdsa.SignASN1(rand.Reader, privateKey, replayHash)
	if err != nil {
		t.Fatalf("sign replay assertion: %v", err)
	}
	if _, err := cp.VerifyPasskeyAuthentication(nextChallenge.ID, nextRawChallenge, replaySignature, signCount, "198.51.100.10"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("replayed sign count err=%v, want forbidden", err)
	}
}

func TestConfigPublishFailureDoesNotReplaceCurrentAndRollbackWorks(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	cfg1, err := cp.PublishConfig(ctx, "tenant-a", `{"version":1}`, false)
	if err != nil {
		t.Fatalf("publish cfg1: %v", err)
	}
	if _, err := cp.PublishConfig(ctx, "tenant-a", `{"version":2}`, true); err == nil {
		t.Fatal("expected simulated publish failure")
	}
	current, ok := cp.CurrentConfig("tenant-a")
	if !ok || current.ID != cfg1.ID {
		t.Fatalf("failed publish replaced current config: %+v", current)
	}
	if _, err := cp.PublishConfig(ctx, "tenant-a", `{"version":3}`, false); err != nil {
		t.Fatalf("publish cfg3: %v", err)
	}
	rolled, err := cp.RollbackConfig(ctx, "tenant-a", cfg1.Version)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolled.ID != cfg1.ID {
		t.Fatalf("rollback got %s want %s", rolled.ID, cfg1.ID)
	}
}

func TestConfigDeploymentRendersOnlyNodeNecessarySubset(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	for _, nodeID := range []string{"node-a", "node-b"} {
		if _, err := cp.RegisterNode(ctx, NodeRegistration{
			ID:          nodeID,
			TenantID:    "tenant-a",
			Region:      "HK",
			Tags:        []string{"edge"},
			Environment: "prod",
		}); err != nil {
			t.Fatalf("register %s: %v", nodeID, err)
		}
	}

	content := `{
		"global":{"log":{"level":"warn"},"route":{"final":"proxy-default"}},
		"nodes":{
			"node-a":{"outbounds":[{"tag":"node-a-out"}],"nodeSecret":"node-a-only"},
			"node-b":{"outbounds":[{"tag":"node-b-out"}],"nodeSecret":"node-b-must-not-ship"}
		},
		"operatorOnly":{"contains":"control-plane-only"}
	}`
	payload, err := cp.BuildNodeConfigPayload(ctx, "node-a", content)
	if err != nil {
		t.Fatalf("build node payload: %v", err)
	}
	for _, want := range []string{"node-a", "node-a-only", "proxy-default"} {
		if !strings.Contains(payload.Content, want) {
			t.Fatalf("node payload missing %q: %s", want, payload.Content)
		}
	}
	for _, forbidden := range []string{"node-b-must-not-ship", "node-b-out", "operatorOnly", "control-plane-only"} {
		if strings.Contains(payload.Content, forbidden) {
			t.Fatalf("node payload leaked %q: %s", forbidden, payload.Content)
		}
	}

	deployment, err := cp.DeployConfig(ctx, "node-a", content, false)
	if err != nil {
		t.Fatalf("deploy config: %v", err)
	}
	if deployment.PayloadHash != payload.Hash || deployment.PayloadBytes != payload.Bytes {
		t.Fatalf("deployment did not record node payload metadata: deployment=%+v payload=%+v", deployment, payload)
	}
	current, ok := cp.CurrentConfig("tenant-a")
	if !ok {
		t.Fatal("current config missing after deploy")
	}
	if current.Hash == deployment.PayloadHash {
		t.Fatalf("deployment payload hash should differ from full config hash when other node blocks are omitted")
	}
	if !strings.Contains(current.Content, "node-b-must-not-ship") {
		t.Fatalf("full config version should preserve non-target node blocks for later deployments: %s", current.Content)
	}
}

func TestSubscriptionFormatsP99RevocationAndRateLimit(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	sub, token, err := cp.CreateSubscription(ctx, "tenant-a", "user-1", "sing-box", "policy-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if sub.TokenHash == token || sub.TokenHash == "" {
		t.Fatal("subscription token must be hashed at rest")
	}
	clients := []string{"sing-box", "clash-meta", "shadowrocket", "v2rayn", "nekobox"}
	for _, client := range clients {
		content, err := cp.RenderSubscription(token, client, "198.51.100.1")
		if err != nil {
			t.Fatalf("render %s: %v", client, err)
		}
		if content == "" || containsSecret(content, token) {
			t.Fatalf("invalid %s subscription content", client)
		}
	}
	auditLogs, err := cp.AuditLogs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("audit logs after subscription access: %v", err)
	}
	if !hasAuditAction(auditLogs, "subscription.access") {
		t.Fatalf("subscription access was not audited: %+v", auditLogs)
	}
	auditJSON, err := json.Marshal(auditLogs)
	if err != nil {
		t.Fatalf("marshal audit logs: %v", err)
	}
	if strings.Contains(string(auditJSON), token) {
		t.Fatalf("subscription audit leaked token: %s", string(auditJSON))
	}
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if _, err := cp.RenderSubscription(token, "sing-box", "198.51.100.2"); err != nil {
			t.Fatalf("render load %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("1000 subscription renders took %s, expected p99 budget-friendly path", elapsed)
	}
	if err := cp.RevokeSubscription(ctx, sub.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := cp.RenderSubscription(token, "sing-box", "198.51.100.3"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked token err=%v, want ErrRevoked", err)
	}
	_, otherToken, err := cp.CreateSubscription(ctx, "tenant-a", "user-2", "sing-box", "policy-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("create second subscription: %v", err)
	}
	if _, err := cp.RenderSubscription(otherToken, "sing-box", "198.51.100.3"); err != nil {
		t.Fatalf("revoking one token affected another: %v", err)
	}
}

func TestSubscriptionContextRendersUserDeviceRegionProtocolAndOutboundPolicy(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	sub, token, err := cp.CreateSubscriptionWithOptions(ctx, "tenant-a", "user-1", "sing-box", "policy-warp", now.Add(time.Hour), SubscriptionOptions{
		TokenKind:      "long",
		Scope:          "read",
		DeviceID:       "phone-01",
		Region:         "HK",
		Protocol:       "tuic",
		OutboundPolicy: "warp-pool",
	})
	if err != nil {
		t.Fatalf("create contextual subscription: %v", err)
	}
	if sub.DeviceID != "phone-01" || sub.Region != "HK" || sub.Protocol != "tuic" || sub.OutboundPolicy != "warp-pool" {
		t.Fatalf("subscription context not stored: %+v", sub)
	}
	content, err := cp.RenderSubscription(token, "sing-box", "198.51.100.44")
	if err != nil {
		t.Fatalf("render contextual subscription: %v", err)
	}
	if containsSecret(content, token) || containsSecret(content, sub.TokenHash) {
		t.Fatalf("contextual subscription leaked token material: %s", content)
	}
	var rendered struct {
		Metadata struct {
			UserID         string `json:"userId"`
			DeviceID       string `json:"deviceId"`
			Region         string `json:"region"`
			Protocol       string `json:"protocol"`
			OutboundPolicy string `json:"outboundPolicy"`
			PolicyID       string `json:"policyId"`
		} `json:"metadata"`
		Outbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		} `json:"outbounds"`
		DNS struct {
			Servers []struct {
				Tag     string `json:"tag"`
				Address string `json:"address"`
				Detour  string `json:"detour"`
			} `json:"servers"`
			Rules []struct {
				RuleSet []string `json:"rule_set,omitempty"`
				Domain  []string `json:"domain,omitempty"`
				Server  string   `json:"server"`
			} `json:"rules"`
			Final string `json:"final"`
		} `json:"dns"`
		Route struct {
			Rules []struct {
				IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
				RuleSet      []string `json:"rule_set,omitempty"`
				DomainSuffix []string `json:"domain_suffix,omitempty"`
				Outbound     string   `json:"outbound"`
			} `json:"rules"`
			Final string `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(content), &rendered); err != nil {
		t.Fatalf("decode contextual sing-box subscription: %v content=%s", err, content)
	}
	if rendered.Metadata.UserID != "user-1" || rendered.Metadata.DeviceID != "phone-01" || rendered.Metadata.Region != "HK" || rendered.Metadata.Protocol != "tuic" || rendered.Metadata.OutboundPolicy != "warp-pool" || rendered.Metadata.PolicyID != "policy-warp" {
		t.Fatalf("rendered subscription metadata mismatch: %+v", rendered.Metadata)
	}
	if !subscriptionHasOutbound(rendered.Outbounds, "tuic", "warp-pool") || rendered.Route.Final != "warp-pool" {
		t.Fatalf("rendered subscription did not apply protocol/outbound policy: %+v", rendered)
	}
	if len(rendered.Route.Rules) < 4 || !rendered.Route.Rules[0].IPIsPrivate || rendered.Route.Rules[0].Outbound != "direct" {
		t.Fatalf("subscription route rules must start with private direct: %+v", rendered.Route.Rules)
	}
	if !subscriptionHasRuleSetOutbound(rendered.Route.Rules, "geoip-cn", "direct") || !subscriptionHasDomainSuffixOutbound(rendered.Route.Rules, "scholar.google.com", "proxy-default") || !subscriptionHasRuleSetOutbound(rendered.Route.Rules, "warp-include", "warp-pool") {
		t.Fatalf("subscription route rules missing CN direct, scholar proxy, or WARP include: %+v", rendered.Route.Rules)
	}
	if rendered.DNS.Final != "dns-global" || !subscriptionHasDNSServer(rendered.DNS.Servers, "dns-cn", "direct") || !subscriptionHasDNSServer(rendered.DNS.Servers, "dns-global", "proxy-default") || !subscriptionHasDNSRuleSet(rendered.DNS.Rules, "geosite-cn", "dns-cn") {
		t.Fatalf("subscription DNS strategy missing split DNS consistency: %+v", rendered.DNS)
	}
	clashContent, err := cp.RenderSubscription(token, "clash-meta", "198.51.100.45")
	if err != nil {
		t.Fatalf("render clash contextual subscription: %v", err)
	}
	for _, want := range []string{"mixed-port: 7890", "type: tuic", "server: \"example.invalid\"", "port: 443", "uuid:", "password:", "alpn:", "congestion-controller: bbr", "rule-providers:", "type: inline", "payload:", "GEOSITE,cn,DIRECT", "DOMAIN-SUFFIX,scholar.google.com,proxy-default", "RULE-SET,warp-include,warp-pool"} {
		if !strings.Contains(clashContent, want) {
			t.Fatalf("clash subscription missing %q: %s", want, clashContent)
		}
	}
	for _, forbidden := range []string{"region: HK", "device: phone-01", "proxies: [warp-pool]"} {
		if strings.Contains(clashContent, forbidden) {
			t.Fatalf("clash subscription still contains non-importable field %q: %s", forbidden, clashContent)
		}
	}
	if containsSecret(clashContent, token) || containsSecret(clashContent, sub.TokenHash) {
		t.Fatalf("clash subscription leaked subscription token material: %s", clashContent)
	}
	if !strings.Contains(clashContent, "  proxies:\n    - \"warp-pool\"\n    - \"DIRECT\"\n") {
		t.Fatalf("clash AUTO group proxies are not a valid nested YAML list: %s", clashContent)
	}
	if strings.Contains(clashContent, "  proxies:\n    - \"warp-pool\"\n  - DIRECT") {
		t.Fatalf("clash AUTO group leaked invalid DIRECT indentation: %s", clashContent)
	}
	if !strings.Contains(clashContent, "  alpn:\n    - h3\n") {
		t.Fatalf("clash TUIC alpn list is not correctly indented: %s", clashContent)
	}
}

func TestClashMetaSubscriptionRendersImportableProtocolFields(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	cases := map[string][]string{
		"vless":     {"type: vless", "uuid:", "tls: true", "servername:", "client-fingerprint: firefox"},
		"vmess":     {"type: vmess", "uuid:", "alterId: 0", "cipher: auto", "tls: true"},
		"hysteria2": {"type: hysteria2", "password:", "sni:", "skip-cert-verify: true", "up: \"200 Mbps\"", "down: \"1000 Mbps\""},
		"tuic":      {"type: tuic", "uuid:", "password:", "alpn:", "udp-relay-mode: native", "congestion-controller: bbr"},
		"trojan":    {"type: trojan", "password:", "sni:", "skip-cert-verify: true"},
	}
	for protocol, wants := range cases {
		t.Run(protocol, func(t *testing.T) {
			sub, token, err := cp.CreateSubscriptionWithOptions(ctx, "tenant-a", "user-"+protocol, "clash-meta", "policy-1", now.Add(time.Hour), SubscriptionOptions{
				TokenKind:      "long",
				Scope:          "read",
				Protocol:       protocol,
				OutboundPolicy: "proxy-default",
			})
			if err != nil {
				t.Fatalf("create subscription: %v", err)
			}
			content, err := cp.RenderSubscription(token, "clash-meta", "198.51.100.46")
			if err != nil {
				t.Fatalf("render clash %s: %v", protocol, err)
			}
			for _, want := range append([]string{"proxies:", "proxy-groups:", "rules:", "server: \"example.invalid\"", "port: 443", "MATCH,proxy-default"}, wants...) {
				if !strings.Contains(content, want) {
					t.Fatalf("clash %s missing %q: %s", protocol, want, content)
				}
			}
			if strings.Contains(content, "region:") || strings.Contains(content, "device:") || containsSecret(content, token) || containsSecret(content, sub.TokenHash) {
				t.Fatalf("clash %s rendered unsafe or non-importable content: %s", protocol, content)
			}
			if strings.Contains(content, "\n  - DIRECT\n") || strings.Contains(content, "\n  - h3\n") {
				t.Fatalf("clash %s rendered invalid list indentation: %s", protocol, content)
			}
		})
	}
}

func TestSubscriptionContextSanitizesUnsafeValues(t *testing.T) {
	if got := sanitizeSubscriptionField(" phone/01:<secret> ", 64); got != "phone01secret" {
		t.Fatalf("unsafe subscription field sanitized to %q", got)
	}
	if got := sanitizeSubscriptionField("abcdef", 4); got != "abcd" {
		t.Fatalf("subscription field max length sanitized to %q", got)
	}
	if got := normalizeSubscriptionProtocol("socks5"); got != "vless" {
		t.Fatalf("unsupported subscription protocol normalized to %q", got)
	}
	if got := normalizeSubscriptionProtocol(" TUIC "); got != "tuic" {
		t.Fatalf("supported subscription protocol normalized to %q", got)
	}
	if got := normalizeSubscriptionOutboundPolicy(" "); got != "proxy-default" {
		t.Fatalf("empty outbound policy normalized to %q", got)
	}
	if got := normalizeSubscriptionOutboundPolicy("warp pool/secret"); got != "warppoolsecret" {
		t.Fatalf("unsafe outbound policy normalized to %q", got)
	}
}

func TestSubscriptionConversionRejectsSSRFAndRequiresChecksum(t *testing.T) {
	cp := New(func() time.Time { return time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC) })
	ctx := adminCtx("tenant-a")
	checksum := strings.Repeat("c", 64)
	base := SubscriptionConversionRequest{
		TenantID:         "tenant-a",
		Name:             "convert",
		SourceURL:        "https://subs.example.com/user.txt",
		SourceChecksum:   checksum,
		SourceClientType: "clash-meta",
		TargetClientType: "sing-box",
		DeviceID:         "phone-01",
		Region:           "HK",
		Protocol:         "tuic",
		OutboundPolicy:   "warp-pool",
	}
	noConfirm := ctx
	noConfirm.Confirmed = false
	if _, err := cp.RegisterSubscriptionConversion(noConfirm, base); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("unconfirmed subscription conversion err=%v, want confirmation", err)
	}
	for _, sourceURL := range []string{
		"http://subs.example.com/user.txt",
		"https://127.0.0.1/sub.txt",
		"https://10.0.0.1/sub.txt",
		"https://169.254.169.254/latest/meta-data",
		"https://localhost/sub.txt",
		"https://subs.internal/sub.txt",
		"https://subs.example.com/sub.txt?token=secret",
		"https://user:secret@subs.example.com/sub.txt",
		"file:///etc/passwd",
	} {
		t.Run(sourceURL, func(t *testing.T) {
			req := base
			req.SourceURL = sourceURL
			_, err := cp.RegisterSubscriptionConversion(ctx, req)
			if !errors.Is(err, ErrBadRequest) {
				t.Fatalf("source URL %q err=%v, want bad request", sourceURL, err)
			}
		})
	}
	badChecksum := base
	badChecksum.SourceChecksum = "bad"
	if _, err := cp.RegisterSubscriptionConversion(ctx, badChecksum); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad subscription conversion checksum err=%v, want bad request", err)
	}
	badTarget := base
	badTarget.TargetClientType = "unknown-client"
	if _, err := cp.RegisterSubscriptionConversion(ctx, badTarget); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad subscription conversion target err=%v, want bad request", err)
	}
	conversion, err := cp.RegisterSubscriptionConversion(ctx, base)
	if err != nil {
		t.Fatalf("register subscription conversion: %v", err)
	}
	if conversion.SourceURL != "https://subs.example.com/user.txt" || conversion.SourceChecksum != checksum || conversion.TargetClientType != "sing-box" || conversion.Protocol != "tuic" {
		t.Fatalf("subscription conversion not normalized: %+v", conversion)
	}
	listed, err := cp.ListSubscriptionConversions(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("list subscription conversions: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != conversion.ID {
		t.Fatalf("unexpected subscription conversions: %+v", listed)
	}
	if _, err := cp.ListSubscriptionConversions(adminCtx("tenant-b"), "tenant-a"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-tenant subscription conversion list err=%v, want forbidden", err)
	}
}

func subscriptionHasOutbound(outbounds []struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}, typ, tag string) bool {
	for _, outbound := range outbounds {
		if outbound.Type == typ && outbound.Tag == tag {
			return true
		}
	}
	return false
}

func subscriptionHasRuleSetOutbound(rules []struct {
	IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
	RuleSet      []string `json:"rule_set,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Outbound     string   `json:"outbound"`
}, ruleSet, outbound string) bool {
	for _, rule := range rules {
		if rule.Outbound != outbound {
			continue
		}
		for _, got := range rule.RuleSet {
			if got == ruleSet {
				return true
			}
		}
	}
	return false
}

func subscriptionHasDomainSuffixOutbound(rules []struct {
	IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
	RuleSet      []string `json:"rule_set,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Outbound     string   `json:"outbound"`
}, suffix, outbound string) bool {
	for _, rule := range rules {
		if rule.Outbound != outbound {
			continue
		}
		for _, got := range rule.DomainSuffix {
			if got == suffix {
				return true
			}
		}
	}
	return false
}

func subscriptionHasDNSServer(servers []struct {
	Tag     string `json:"tag"`
	Address string `json:"address"`
	Detour  string `json:"detour"`
}, tag, detour string) bool {
	for _, server := range servers {
		if server.Tag == tag && server.Detour == detour {
			return true
		}
	}
	return false
}

func subscriptionHasDNSRuleSet(rules []struct {
	RuleSet []string `json:"rule_set,omitempty"`
	Domain  []string `json:"domain,omitempty"`
	Server  string   `json:"server"`
}, ruleSet, server string) bool {
	for _, rule := range rules {
		if rule.Server != server {
			continue
		}
		for _, got := range rule.RuleSet {
			if got == ruleSet {
				return true
			}
		}
	}
	return false
}

func TestRulesPublishDiffAndDomainTest(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	report, err := cp.PublishRules(ctx, "tenant-a", rulecompiler.CompileOptions{
		WarpInclude: []string{"warp-only.example"},
		UserDirect:  []string{"direct-only.example.cn"},
	})
	if err != nil {
		t.Fatalf("publish rules: %v", err)
	}
	if len(report.Added) == 0 && len(report.Removed) == 0 && len(report.Changed) == 0 {
		t.Fatal("rules publish should generate diff report")
	}
	if !ruleHitChangeIncludes(report.HitChanges, "warp-only.example", rulecompiler.OutboundProxy, rulecompiler.OutboundWarp) {
		t.Fatalf("rules publish diff missing hit change: %+v", report.HitChanges)
	}
	if report.Coverage.TotalSamples == 0 || report.Coverage.ByOutbound[rulecompiler.OutboundDirect] == 0 || report.Coverage.ByOutbound[rulecompiler.OutboundWarp] == 0 {
		t.Fatalf("rules publish missing coverage analysis: %+v", report.Coverage)
	}
	if got := cp.TestDomain("direct-only.example.cn"); got.Outbound != rulecompiler.OutboundDirect {
		t.Fatalf("direct domain classified as %s", got.Outbound)
	}
	if got := cp.TestDomain("warp-only.example"); got.Outbound != rulecompiler.OutboundWarp {
		t.Fatalf("warp domain classified as %s", got.Outbound)
	}
	if _, err := cp.PublishRules(ctx, "tenant-a", rulecompiler.CompileOptions{WarpInclude: []string{"scholar.google.com"}}); err == nil {
		t.Fatal("Google Scholar WARP rule publish should be blocked")
	}
}

func TestRulesHundredThousandPublishDoesNotBlockSubscriptionsOrAPI(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	_, token, err := cp.CreateSubscription(ctx, "tenant-a", "user-1", "sing-box", "policy-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	rules := make([]rulecompiler.Rule, 100_000)
	for i := range rules {
		rules[i] = rulecompiler.Rule{
			ID:       fmt.Sprintf("bulk-%06d", i),
			Priority: 1000 + i,
			Type:     rulecompiler.RuleDomainSuffix,
			Matcher:  fmt.Sprintf("bulk-%06d.example", i),
			Outbound: rulecompiler.OutboundDirect,
			Source:   "bulk-stability",
			Enabled:  true,
		}
	}

	start := make(chan struct{})
	done := make(chan struct{})
	var wg sync.WaitGroup
	var renders, apiReads, renderErrors, apiErrors int64
	var maxRenderNs, maxAPINs int64
	for worker := 0; worker < 2; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				renderStart := time.Now()
				ip := fmt.Sprintf("198.51.%d.%d", worker, 10+(i%200))
				if _, err := cp.RenderSubscription(token, "sing-box", ip); err != nil {
					atomic.AddInt64(&renderErrors, 1)
				} else {
					atomic.AddInt64(&renders, 1)
				}
				observeMaxDuration(&maxRenderNs, time.Since(renderStart))

				apiStart := time.Now()
				if got := cp.TestDomain("www.taobao.com"); got.Outbound != rulecompiler.OutboundDirect {
					atomic.AddInt64(&apiErrors, 1)
				} else {
					atomic.AddInt64(&apiReads, 1)
				}
				observeMaxDuration(&maxAPINs, time.Since(apiStart))
				time.Sleep(time.Millisecond)
			}
		}()
	}
	close(start)
	waitForAtomicAtLeast(t, &renders, 4, 500*time.Millisecond)

	publishStart := time.Now()
	report, err := cp.PublishRules(ctx, "tenant-a", rulecompiler.CompileOptions{Rules: rules})
	publishElapsed := time.Since(publishStart)
	close(done)
	wg.Wait()
	if err != nil {
		t.Fatalf("publish 100k rules: %v", err)
	}
	if publishElapsed > 10*time.Second {
		t.Fatalf("100k rule publish took %s, want under 10s", publishElapsed)
	}
	if atomic.LoadInt64(&renderErrors) != 0 || atomic.LoadInt64(&apiErrors) != 0 {
		t.Fatalf("concurrent subscription/API errors: render=%d api=%d", renderErrors, apiErrors)
	}
	if atomic.LoadInt64(&renders) < 20 || atomic.LoadInt64(&apiReads) < 20 {
		t.Fatalf("subscription/API did not keep making progress during publish: renders=%d apiReads=%d elapsed=%s", renders, apiReads, publishElapsed)
	}
	if maxRender := time.Duration(atomic.LoadInt64(&maxRenderNs)); maxRender > time.Second {
		t.Fatalf("subscription render blocked too long during rule publish: %s", maxRender)
	}
	if maxAPI := time.Duration(atomic.LoadInt64(&maxAPINs)); maxAPI > time.Second {
		t.Fatalf("domain API read blocked too long during rule publish: %s", maxAPI)
	}
	if len(report.Added) < 100_000 || report.Coverage.TotalSamples == 0 {
		t.Fatalf("publish report missing large-rule evidence: added=%d coverage=%+v", len(report.Added), report.Coverage)
	}
	if got := cp.TestDomain("www.bulk-099999.example"); got.Outbound != rulecompiler.OutboundDirect {
		t.Fatalf("tail bulk rule classified as %s, want direct", got.Outbound)
	}
}

func TestRulesPublishCanaryRolloutAndReleasePause(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	report, err := cp.PublishRules(ctx, "tenant-a", rulecompiler.CompileOptions{
		UserDirect:     []string{"canary-direct.example.cn"},
		RolloutPercent: 5,
	})
	if err != nil {
		t.Fatalf("publish rules with canary rollout: %v", err)
	}
	if report.RolloutPercent != 5 || cp.CurrentRuleRollout("tenant-a") != 5 {
		t.Fatalf("rule rollout not stored in report/control-plane: report=%d current=%d", report.RolloutPercent, cp.CurrentRuleRollout("tenant-a"))
	}
	if _, err := cp.PublishRules(ctx, "tenant-a", rulecompiler.CompileOptions{RolloutPercent: 7}); err == nil {
		t.Fatal("unsupported rollout percent was accepted")
	}
	if cp.CurrentRuleRollout("tenant-a") != 5 {
		t.Fatalf("invalid rollout changed current rollout to %d", cp.CurrentRuleRollout("tenant-a"))
	}
	if err := cp.Runbook(ctx, "tenant-a", "inc-release", "pause-release"); err != nil {
		t.Fatalf("pause release runbook: %v", err)
	}
	if _, err := cp.PublishRules(ctx, "tenant-a", rulecompiler.CompileOptions{RolloutPercent: 20}); !errors.Is(err, ErrReleasePaused) {
		t.Fatalf("paused release publish rules err=%v, want ErrReleasePaused", err)
	}
	if _, err := cp.PublishConfig(ctx, "tenant-a", `{"version":1}`, false); !errors.Is(err, ErrReleasePaused) {
		t.Fatalf("paused release publish config err=%v, want ErrReleasePaused", err)
	}
	if err := cp.Runbook(ctx, "tenant-a", "inc-release", "resume-release"); err != nil {
		t.Fatalf("resume release runbook: %v", err)
	}
	if _, err := cp.PublishConfig(ctx, "tenant-a", `{"version":1}`, false); err != nil {
		t.Fatalf("publish config after resume: %v", err)
	}
}

func TestRuleSetSourceRejectsSSRFAndRequiresChecksum(t *testing.T) {
	cp := New(func() time.Time { return time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC) })
	ctx := adminCtx("tenant-a")
	checksum := strings.Repeat("a", 64)
	for _, sourceURL := range []string{
		"http://rules.example.com/cn.srs",
		"https://127.0.0.1/rules.srs",
		"https://10.0.0.1/rules.srs",
		"https://169.254.169.254/latest/meta-data",
		"https://localhost/rules.srs",
		"https://rules.internal/cn.srs",
		"https://rules.example.com/cn.srs?token=secret",
		"https://user:secret@rules.example.com/cn.srs",
		"file:///etc/passwd",
	} {
		t.Run(sourceURL, func(t *testing.T) {
			_, err := cp.RegisterRuleSetSource(ctx, RuleSetSource{
				TenantID:  "tenant-a",
				Name:      "cn-direct",
				SourceURL: sourceURL,
				Checksum:  checksum,
			})
			if !errors.Is(err, ErrBadRequest) {
				t.Fatalf("source URL %q err=%v, want bad request", sourceURL, err)
			}
		})
	}
	if _, err := cp.RegisterRuleSetSource(ctx, RuleSetSource{TenantID: "tenant-a", Name: "cn-direct", SourceURL: "https://rules.example.com/cn.srs", Checksum: "bad"}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad checksum err=%v, want bad request", err)
	}
	created, err := cp.RegisterRuleSetSource(ctx, RuleSetSource{
		ID:        "ruleset-cn",
		TenantID:  "tenant-a",
		Name:      "CN Direct",
		SourceURL: "https://Rules.Example.com/cn.srs",
		Checksum:  checksum,
	})
	if err != nil {
		t.Fatalf("register safe rule set source: %v", err)
	}
	if created.SourceURL != "https://rules.example.com/cn.srs" || created.Checksum != checksum {
		t.Fatalf("rule set source not normalized: %+v", created)
	}
	if _, err := cp.ListRuleSetSources(adminCtx("tenant-b"), "tenant-a"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-tenant rule set list err=%v, want forbidden", err)
	}
}

func TestWebhookEndpointRejectsSSRFAndRedactsSigningSecret(t *testing.T) {
	cp := New(func() time.Time { return time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC) })
	ctx := adminCtx("tenant-a")
	for _, targetURL := range []string{
		"http://hooks.example.com/events",
		"https://127.0.0.1/events",
		"https://10.0.0.1/events",
		"https://169.254.169.254/latest/meta-data",
		"https://localhost/events",
		"https://hooks.internal/events",
		"https://hooks.example.com/events?token=secret",
		"https://user:secret@hooks.example.com/events",
		"file:///etc/passwd",
	} {
		t.Run(targetURL, func(t *testing.T) {
			_, err := cp.RegisterWebhookEndpoint(ctx, WebhookEndpointRegistration{
				TenantID:      "tenant-a",
				Name:          "alerts",
				TargetURL:     targetURL,
				EventTypes:    []string{"alert.created"},
				SigningSecret: "super-secret-webhook-value",
			})
			if !errors.Is(err, ErrBadRequest) {
				t.Fatalf("target URL %q err=%v, want bad request", targetURL, err)
			}
		})
	}
	created, err := cp.RegisterWebhookEndpoint(ctx, WebhookEndpointRegistration{
		ID:            "webhook-1",
		TenantID:      "tenant-a",
		Name:          "Alerts",
		TargetURL:     "https://Hooks.Example.com/events",
		EventTypes:    []string{"alert.created", "alert.created", "incident:p1"},
		SigningSecret: "super-secret-webhook-value",
	})
	if err != nil {
		t.Fatalf("register webhook endpoint: %v", err)
	}
	if created.TargetURL != "https://hooks.example.com/events" || created.SigningSecretHash == "" {
		t.Fatalf("webhook endpoint not normalized or hashed: %+v", created)
	}
	encoded, err := json.Marshal(created)
	if err != nil {
		t.Fatalf("marshal webhook endpoint: %v", err)
	}
	if strings.Contains(string(encoded), "super-secret") || strings.Contains(string(encoded), "SigningSecretHash") {
		t.Fatalf("webhook endpoint JSON leaked secret material: %s", encoded)
	}
	listed, err := cp.ListWebhookEndpoints(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("list webhook endpoints: %v", err)
	}
	if len(listed) != 1 || listed[0].SigningSecretHash != "" || len(listed[0].EventTypes) != 2 {
		t.Fatalf("webhook list leaked hash or events not normalized: %+v", listed)
	}
	if _, err := cp.ListWebhookEndpoints(adminCtx("tenant-b"), "tenant-a"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-tenant webhook list err=%v, want forbidden", err)
	}
}

func TestRunbooksApplyOperationalActions(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	catalog, err := cp.RunbookCatalog(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("runbook catalog: %v", err)
	}
	for _, severity := range []string{"P0", "P1", "P2", "P3"} {
		if !runbookCatalogHasSeverity(catalog, severity) {
			t.Fatalf("runbook catalog missing %s coverage: %+v", severity, catalog)
		}
	}
	if err := cp.Runbook(ctx, "tenant-a", "inc-p0", "pause-node-deployments"); err != nil {
		t.Fatalf("pause node deployments runbook: %v", err)
	}
	if err := cp.Runbook(ctx, "tenant-a", "inc-p0", "require-credential-rotation"); err != nil {
		t.Fatalf("credential rotation runbook: %v", err)
	}
	if err := cp.Runbook(ctx, "tenant-a", "inc-p3", "p3-triage"); err != nil {
		t.Fatalf("p3 triage runbook: %v", err)
	}
	state, err := cp.RunbookState(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("read p0/p3 runbook state: %v", err)
	}
	if !state.NodeDeploymentsPaused || !state.CredentialRotationRequired || !state.P3TriageRecorded {
		t.Fatalf("p0/p3 runbook state not applied: %+v", state)
	}

	first, err := cp.PublishConfig(ctx, "tenant-a", `{"version":1}`, false)
	if err != nil {
		t.Fatalf("publish first config: %v", err)
	}
	second, err := cp.PublishConfig(ctx, "tenant-a", `{"version":2}`, false)
	if err != nil {
		t.Fatalf("publish second config: %v", err)
	}
	if current, _ := cp.CurrentConfig("tenant-a"); current.ID != second.ID {
		t.Fatalf("current config before runbook = %+v, want %+v", current, second)
	}
	if err := cp.Runbook(ctx, "tenant-a", "inc-rules", "rollback-config"); err != nil {
		t.Fatalf("rollback config runbook: %v", err)
	}
	if current, _ := cp.CurrentConfig("tenant-a"); current.ID != first.ID {
		t.Fatalf("runbook did not roll back config: %+v", current)
	}

	if _, err := cp.AddWarpProfile(ctx, WarpProfile{
		ID:       "warp-slow",
		TenantID: "tenant-a",
		Name:     "warp-slow",
		Status:   "healthy",
		LastProbe: WarpProbeResult{
			LatencyMs:   200,
			Loss:        0.05,
			HTTPSuccess: true,
		},
	}); err != nil {
		t.Fatalf("add slow warp: %v", err)
	}
	if _, err := cp.AddWarpProfile(ctx, WarpProfile{
		ID:       "warp-fast",
		TenantID: "tenant-a",
		Name:     "warp-fast",
		Status:   "healthy",
		LastProbe: WarpProbeResult{
			LatencyMs:   30,
			Loss:        0,
			HTTPSuccess: true,
		},
	}); err != nil {
		t.Fatalf("add fast warp: %v", err)
	}
	if err := cp.Runbook(ctx, "tenant-a", "inc-warp", "switch-exit"); err != nil {
		t.Fatalf("switch exit runbook: %v", err)
	}
	state, err = cp.RunbookState(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("read runbook state: %v", err)
	}
	if state.LastSelectedExit != "warp-fast" {
		t.Fatalf("switch-exit selected %q, want warp-fast", state.LastSelectedExit)
	}
	if err := cp.Runbook(ctx, "tenant-a", "inc-warp", "disable-warp-profile"); err != nil {
		t.Fatalf("disable warp runbook: %v", err)
	}
	profiles, err := cp.ListWarpProfiles(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("list warp profiles: %v", err)
	}
	var disabled int
	for _, profile := range profiles {
		if profile.Status == "disabled" {
			disabled++
		}
	}
	if disabled != 1 {
		t.Fatalf("disable-warp-profile disabled %d profiles, want 1", disabled)
	}

	_, token, err := cp.CreateSubscription(ctx, "tenant-a", "user-1", "sing-box", "policy-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if err := cp.Runbook(ctx, "tenant-a", "inc-sub", "enable-subscription-cache"); err != nil {
		t.Fatalf("enable subscription cache runbook: %v", err)
	}
	if err := cp.Runbook(ctx, "tenant-a", "inc-sub", "limit-subscriptions"); err != nil {
		t.Fatalf("limit subscriptions runbook: %v", err)
	}
	state, err = cp.RunbookState(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("read runbook state after subscription runbooks: %v", err)
	}
	if !state.SubscriptionCacheForced || !state.SubscriptionEmergencyLimited {
		t.Fatalf("subscription runbook state not applied: %+v", state)
	}
	if _, err := cp.RenderSubscription(token, "sing-box", "198.51.100.50"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("emergency limited subscription err=%v, want ErrRateLimited", err)
	}
}

func ruleHitChangeIncludes(changes []rulecompiler.HitChange, input string, previous, next rulecompiler.Outbound) bool {
	for _, change := range changes {
		if change.Input == input && change.PreviousOutbound == previous && change.NextOutbound == next {
			return true
		}
	}
	return false
}

func observeMaxDuration(max *int64, duration time.Duration) {
	next := duration.Nanoseconds()
	for {
		current := atomic.LoadInt64(max)
		if next <= current || atomic.CompareAndSwapInt64(max, current, next) {
			return
		}
	}
}

func waitForAtomicAtLeast(t *testing.T, value *int64, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(value) >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for counter >= %d, got %d", want, atomic.LoadInt64(value))
}

func TestRouteDecisionTraceExplainsRulesWithoutLeakingRawInput(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	trace, err := cp.TraceRouteDecision(ctx, "tenant-a", RouteTraceRequest{
		Input:    "https://scholar.google.com/search?q=token-secret",
		Protocol: "VLESS",
		ClientIP: "198.51.100.50",
		NodeID:   "node-1",
	})
	if err != nil {
		t.Fatalf("trace route decision: %v", err)
	}
	if trace.Input != "scholar.google.com" || strings.Contains(trace.Input, "token-secret") {
		t.Fatalf("trace input was not sanitized: %+v", trace)
	}
	if trace.Outbound != rulecompiler.OutboundProxy || trace.MatchedSource != "warp-exclude-google-scholar" || trace.Decision == "" {
		t.Fatalf("trace did not explain scholar exclusion: %+v", trace)
	}
	traces, err := cp.RouteDecisionTraces(ctx, "tenant-a", 10)
	if err != nil {
		t.Fatalf("list route traces: %v", err)
	}
	if len(traces) != 1 || traces[0].ID != trace.ID {
		t.Fatalf("unexpected route traces: %+v", traces)
	}
	auditLogs, err := cp.AuditLogs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("audit logs: %v", err)
	}
	found := false
	for _, log := range auditLogs {
		if log.Action == "route.trace" && log.ResourceID == trace.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("route trace did not create audit log: %+v", auditLogs)
	}

	scoped := RequestContext{User: User{ID: "scoped", TenantID: "tenant-a", Role: RoleAdmin}, Scopes: []string{"rules:read"}}
	if _, err := cp.RouteDecisionTraces(scoped, "tenant-a", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("route trace list with rules-only scope err=%v, want forbidden", err)
	}
}

func TestDependencyHealthModelsDBRedisChaosWindows(t *testing.T) {
	clock := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return clock })
	ctx := adminCtx("tenant-a")

	operator := RequestContext{User: User{ID: "op-a", TenantID: "tenant-a", Role: RoleOperator}}
	if _, err := cp.SetDependencyHealth(operator, DependencyPostgres, DependencyUnavailable, "primary restart"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("operator dependency write err=%v, want forbidden", err)
	}

	db, err := cp.SetDependencyHealth(ctx, DependencyPostgres, DependencyUnavailable, "primary restart token=secret")
	if err != nil {
		t.Fatalf("mark postgres unavailable: %v", err)
	}
	if !db.RecoveryDeadlineAt.Equal(clock.Add(60 * time.Second)) {
		t.Fatalf("postgres recovery deadline=%s, want 60s window", db.RecoveryDeadlineAt)
	}
	if strings.Contains(db.Message, "secret") {
		t.Fatalf("dependency health message leaked secret: %q", db.Message)
	}
	availability, err := cp.CoreAPIAvailability(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("availability: %v", err)
	}
	if availability.Status != "Degraded" || !availability.CoreAPIsAvailable || availability.WriteAPIsAvailable {
		t.Fatalf("postgres outage should be read-only degraded in recovery window: %+v", availability)
	}
	overview, err := cp.Overview(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.Health != "Degraded" || len(overview.DependencyRows) != 2 {
		t.Fatalf("overview did not expose dependency degradation: %+v", overview)
	}

	clock = clock.Add(61 * time.Second)
	availability, err = cp.CoreAPIAvailability(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("availability after RTO: %v", err)
	}
	if availability.Status != "Critical" || availability.CoreAPIsAvailable || availability.SubscriptionGenerationAvailable {
		t.Fatalf("postgres outage past 60s should be critical: %+v", availability)
	}
	if _, err := cp.SetDependencyHealth(ctx, DependencyPostgres, DependencyHealthy, "primary recovered"); err != nil {
		t.Fatalf("recover postgres: %v", err)
	}

	clock = time.Date(2026, 6, 3, 12, 10, 0, 0, time.UTC)
	if _, err := cp.SetDependencyHealth(ctx, DependencyRedis, DependencyUnavailable, "redis link down"); err != nil {
		t.Fatalf("mark redis unavailable: %v", err)
	}
	clock = clock.Add(5 * time.Minute)
	availability, err = cp.CoreAPIAvailability(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("redis availability: %v", err)
	}
	if availability.Status != "Degraded" || !availability.CoreAPIsAvailable || !availability.WriteAPIsAvailable || availability.RateLimitMode != "local-fallback" {
		t.Fatalf("redis 5m outage should keep core APIs degraded but available: %+v", availability)
	}
}

func TestWarpPoolFailureRemovalScholarExcludeAndScheduler(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	for i := 1; i <= 4; i++ {
		_, err := cp.AddWarpProfile(ctx, WarpProfile{ID: fmt.Sprintf("warp-%d", i), TenantID: "tenant-a", NodeID: "node-1", Name: fmt.Sprintf("warp-0%d", i), Weight: 1})
		if err != nil {
			t.Fatalf("add warp %d: %v", i, err)
		}
	}
	for i := 1; i <= 4; i++ {
		success := i > 2
		if err := cp.ProbeWarpProfile(fmt.Sprintf("warp-%d", i), WarpProbeResult{
			LatencyMs:      float64(20 * i),
			Loss:           boolToLoss(!success),
			HTTPSuccess:    success,
			ExitIP:         fmt.Sprintf("203.0.113.%d", i),
			ASN:            "AS13335",
			IPv4:           true,
			IPv6:           true,
			CPUPressure:    0.2,
			MemoryPressure: 0.2,
			Connections:    100 * i,
			At:             now,
		}); err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
	}
	decision := cp.SelectWarp("example-warp-target.com", "user-1", SchedulePerformance)
	if decision.Outbound == "warp-01" || decision.Outbound == "warp-02" || decision.Outbound == "" {
		t.Fatalf("scheduler selected failed or empty outbound: %+v", decision)
	}
	second := cp.SelectWarp("example-warp-target.com", "user-1", SchedulePerformance)
	if second.Outbound != decision.Outbound {
		t.Fatalf("sticky-by-domain drifted: first=%+v second=%+v", decision, second)
	}
	scholar := cp.SelectWarp("scholar.google.com", "user-1", SchedulePerformance)
	if scholar.Outbound != string(rulecompiler.OutboundProxy) {
		t.Fatalf("scholar routed through warp: %+v", scholar)
	}
}

func TestWarpProfileSourceDNSCooldownAndRecoveryProbe(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	if _, err := cp.AddWarpProfile(ctx, WarpProfile{ID: "bad-source", TenantID: "tenant-a", Name: "bad-source", Source: "unknown-tool", LicenseAccepted: true}); err == nil {
		t.Fatal("unsupported WARP profile source was accepted")
	}
	if _, err := cp.AddWarpProfile(ctx, WarpProfile{ID: "license-missing", TenantID: "tenant-a", Name: "license-missing", Source: "wgcf"}); err == nil {
		t.Fatal("WARP profile without accepted source license was accepted")
	}
	if _, err := cp.AddWarpProfile(ctx, WarpProfile{ID: "warp-dns", TenantID: "tenant-a", Name: "warp-dns", Source: "wgcf", LicenseAccepted: true}); err != nil {
		t.Fatalf("add compliant warp profile: %v", err)
	}
	if err := cp.ProbeWarpProfile("warp-dns", WarpProbeResult{DNSStatus: "servfail", HTTPSuccess: true, WireGuardStatus: "ok", Loss: 0, At: now}); err != nil {
		t.Fatalf("dns failure probe: %v", err)
	}
	profiles, err := cp.ListWarpProfiles(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("list profiles after dns failure: %v", err)
	}
	if len(profiles) != 1 || profiles[0].Status != "cooldown" || !profiles[0].CooldownUntil.Equal(now.Add(30*time.Second)) {
		t.Fatalf("dns failure did not enter cooldown: %+v", profiles)
	}
	early := now.Add(10 * time.Second)
	if err := cp.ProbeWarpProfile("warp-dns", WarpProbeResult{DNSStatus: "ok", HTTPSuccess: true, WireGuardStatus: "ok", Loss: 0, At: early}); err != nil {
		t.Fatalf("early recovery probe: %v", err)
	}
	profiles, _ = cp.ListWarpProfiles(ctx, "tenant-a")
	if profiles[0].Status != "cooldown" {
		t.Fatalf("early recovery probe should keep cooldown: %+v", profiles[0])
	}
	recoveredAt := now.Add(31 * time.Second)
	if err := cp.ProbeWarpProfile("warp-dns", WarpProbeResult{DNSStatus: "ok", HTTPSuccess: true, WireGuardStatus: "ok", Loss: 0, At: recoveredAt}); err != nil {
		t.Fatalf("recovery probe: %v", err)
	}
	profiles, _ = cp.ListWarpProfiles(ctx, "tenant-a")
	if profiles[0].Status != "healthy" || !profiles[0].CooldownUntil.IsZero() {
		t.Fatalf("recovery probe did not restore profile: %+v", profiles[0])
	}
}

func TestWarpWireGuardImportEncryptsPrivateKeyAndRejectsUnsafeConfig(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	config := `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32, 2606:4700:110:abcd::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
`
	profile, err := cp.ImportWarpWireGuardProfile(ctx, WarpWireGuardImport{
		ID:     "warp-wg-import",
		Name:   "wg-import",
		Config: config,
	})
	if err != nil {
		t.Fatalf("import wireguard profile: %v", err)
	}
	if profile.Source != "standard-wireguard-config" || !profile.LicenseAccepted || profile.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Fatalf("wireguard profile metadata not normalized: %+v", profile)
	}
	if profile.EncryptedPrivateKey == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" || !strings.HasPrefix(profile.EncryptedPrivateKey, "enc:") {
		t.Fatalf("wireguard private key not encrypted: %+v", profile)
	}
	if profile.PeerPublicKey == "" || len(profile.AllowedIPs) != 2 || len(profile.Addresses) != 2 || len(profile.DNS) != 2 {
		t.Fatalf("wireguard config fields not parsed: %+v", profile)
	}
	plain, err := cp.DecryptWarpPrivateKey(ctx, "warp-wg-import")
	if err != nil {
		t.Fatalf("decrypt imported wireguard key: %v", err)
	}
	if plain != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Fatalf("decrypted imported key mismatch: %q", plain)
	}
	profiles, err := cp.ListWarpProfiles(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("list warp profiles: %v", err)
	}
	if len(profiles) != 1 || profiles[0].EncryptedPrivateKey != "" {
		t.Fatalf("warp profile list leaked private key: %+v", profiles)
	}

	if _, err := cp.ImportWarpWireGuardProfile(ctx, WarpWireGuardImport{Config: strings.Replace(config, "Endpoint = engage.cloudflareclient.com:2408", "Endpoint = http://127.0.0.1:2408", 1)}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("unsafe wireguard endpoint err=%v, want bad request", err)
	}
	if _, err := cp.ImportWarpWireGuardProfile(ctx, WarpWireGuardImport{Config: strings.Replace(config, "AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = not-a-cidr", 1)}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("unsafe wireguard allowed IP err=%v, want bad request", err)
	}
}

func TestArgoTunnelRegistrationRendersSafeCloudflaredConfig(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	unconfirmed := ctx
	unconfirmed.Confirmed = false
	if _, err := cp.RegisterArgoTunnel(unconfirmed, ArgoTunnel{
		TenantID:   "tenant-a",
		Hostname:   "panel.example.com",
		ServiceURL: "http://127.0.0.1:8080",
		TunnelID:   "tunnel-01",
	}); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("unconfirmed Argo tunnel create err=%v, want confirmation", err)
	}
	if _, err := cp.RegisterArgoTunnel(ctx, ArgoTunnel{
		TenantID:   "tenant-a",
		Hostname:   "https://panel.example.com",
		ServiceURL: "http://user:secret@127.0.0.1:8080",
		TunnelID:   "tunnel-01",
	}); err == nil {
		t.Fatal("unsafe Argo tunnel input accepted")
	}

	tunnel, err := cp.RegisterArgoTunnel(ctx, ArgoTunnel{
		ID:                  "argo-1",
		TenantID:            "tenant-a",
		Name:                " Panel Tunnel ",
		Hostname:            "Panel.Example.com",
		ServiceURL:          "http://127.0.0.1:8080?token=secret#fragment",
		CloudflareAccountID: "acct-1",
		TunnelID:            "tunnel-01",
	})
	if err != nil {
		t.Fatalf("register Argo tunnel: %v", err)
	}
	if tunnel.Hostname != "panel.example.com" || tunnel.ServiceURL != "http://127.0.0.1:8080" || tunnel.Status != "configured" {
		t.Fatalf("Argo tunnel not normalized safely: %+v", tunnel)
	}
	config, err := cp.RenderArgoTunnelConfig(ctx, tunnel.ID)
	if err != nil {
		t.Fatalf("render Argo config: %v", err)
	}
	for _, want := range []string{"tunnel: tunnel-01", "credentials-file: /etc/cloudflared/tunnel-01.json", "hostname: panel.example.com", "service: http://127.0.0.1:8080", "http_status:404"} {
		if !strings.Contains(config, want) {
			t.Fatalf("Argo config missing %q: %s", want, config)
		}
	}
	if strings.Contains(config, "secret") || strings.Contains(config, "token=") || strings.Contains(config, "user:") {
		t.Fatalf("Argo config leaked secret material: %s", config)
	}
	if _, err := cp.RenderArgoTunnelConfig(adminCtx("tenant-b"), tunnel.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-tenant Argo config err=%v, want forbidden", err)
	}
}

func TestCloudflareArgoAutomationPlanIsStructuredAndTokenFree(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	req := CloudflareArgoAutomationRequest{
		TenantID:            "tenant-a",
		Name:                "panel",
		Hostname:            "Panel.Example.com",
		ServiceURL:          "http://127.0.0.1:8080?token=secret#fragment",
		CloudflareAccountID: "0123456789abcdef0123456789abcdef",
		CloudflareZoneID:    "abcdef0123456789abcdef0123456789",
	}

	noConfirm := ctx
	noConfirm.Confirmed = false
	if _, err := cp.BuildCloudflareArgoAutomationPlan(noConfirm, req); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("unconfirmed Cloudflare Argo plan err=%v, want confirmation", err)
	}
	badReq := req
	badReq.CloudflareAccountID = "acct-1"
	if _, err := cp.BuildCloudflareArgoAutomationPlan(ctx, badReq); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad Cloudflare account err=%v, want bad request", err)
	}

	plan, err := cp.BuildCloudflareArgoAutomationPlan(ctx, req)
	if err != nil {
		t.Fatalf("build Cloudflare Argo plan: %v", err)
	}
	if plan.Tunnel.Hostname != "panel.example.com" || plan.Tunnel.ServiceURL != "http://127.0.0.1:8080" || plan.Tunnel.Status != "cloudflare-api-planned" {
		t.Fatalf("Cloudflare Argo plan not normalized: %+v", plan.Tunnel)
	}
	if len(plan.Operations) != 3 || plan.Operations[0].Method != "POST" || plan.Operations[1].Method != "PUT" || plan.Operations[2].Method != "POST" {
		t.Fatalf("unexpected Cloudflare operations: %+v", plan.Operations)
	}
	if !strings.Contains(plan.Operations[0].URL, "/accounts/0123456789abcdef0123456789abcdef/cfd_tunnel") {
		t.Fatalf("create tunnel URL missing account scope: %s", plan.Operations[0].URL)
	}
	if !strings.Contains(plan.Operations[2].URL, "/zones/abcdef0123456789abcdef0123456789/dns_records") {
		t.Fatalf("DNS URL missing zone scope: %s", plan.Operations[2].URL)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal Cloudflare Argo plan: %v", err)
	}
	for _, forbidden := range []string{"secret", "token=secret", "Authorization"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("Cloudflare Argo plan leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestWarpSchedulerSupportsPlanModes(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	for _, profile := range []WarpProfile{
		{
			ID:       "warp-a-latency",
			TenantID: "tenant-a",
			Name:     "warp-a-latency",
			Status:   "healthy",
			Weight:   2,
			LastProbe: WarpProbeResult{
				LatencyMs:      10,
				Loss:           0.2,
				HTTPSuccess:    true,
				CPUPressure:    0.2,
				MemoryPressure: 0.2,
			},
		},
		{
			ID:       "warp-b-error",
			TenantID: "tenant-a",
			Name:     "warp-b-error",
			Status:   "healthy",
			Weight:   1,
			LastProbe: WarpProbeResult{
				LatencyMs:      100,
				Loss:           0,
				HTTPSuccess:    true,
				CPUPressure:    0.2,
				MemoryPressure: 0.2,
			},
		},
	} {
		if _, err := cp.AddWarpProfile(ctx, profile); err != nil {
			t.Fatalf("add profile %s: %v", profile.ID, err)
		}
	}

	if got := cp.SelectWarp("latency.example", "user-a", ScheduleLeastLatency); got.Outbound != "warp-a-latency" || got.Reason != string(ScheduleLeastLatency) {
		t.Fatalf("least-latency decision mismatch: %+v", got)
	}
	if got := cp.SelectWarp("error.example", "user-a", ScheduleLeastError); got.Outbound != "warp-b-error" || got.Reason != string(ScheduleLeastError) {
		t.Fatalf("least-error decision mismatch: %+v", got)
	}
	first := cp.SelectWarp("domain-a.example", "user-a", ScheduleStickyByDomain)
	second := cp.SelectWarp("domain-a.example", "user-b", ScheduleStickyByDomain)
	if first.Outbound != second.Outbound || second.Reason != "sticky-by-domain" {
		t.Fatalf("sticky-by-domain did not hold: first=%+v second=%+v", first, second)
	}
	userFirst := cp.SelectWarp("user-a.example", "sticky-user", ScheduleStickyByUser)
	userSecond := cp.SelectWarp("user-b.example", "sticky-user", ScheduleStickyByUser)
	if userFirst.Outbound != userSecond.Outbound || userSecond.Reason != "sticky-by-user" {
		t.Fatalf("sticky-by-user did not hold: first=%+v second=%+v", userFirst, userSecond)
	}

	rr1 := cp.SelectWarp("rr-1.example", "user-rr", ScheduleWeightedRoundRobin)
	rr2 := cp.SelectWarp("rr-2.example", "user-rr", ScheduleWeightedRoundRobin)
	rr3 := cp.SelectWarp("rr-3.example", "user-rr", ScheduleWeightedRoundRobin)
	if rr1.Outbound != "warp-a-latency" || rr2.Outbound != "warp-a-latency" || rr3.Outbound != "warp-b-error" {
		t.Fatalf("weighted round robin did not honor 2:1 weights: %+v %+v %+v", rr1, rr2, rr3)
	}
}

func TestSecurityControlsAndAuditLogs(t *testing.T) {
	cp := New(nil)
	ctx := adminCtx("tenant-a")
	if _, err := cp.PublishConfig(ctx, "tenant-a", "{}", false); err != nil {
		t.Fatalf("publish config: %v", err)
	}
	logs, err := cp.AuditLogs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("audit logs: %v", err)
	}
	if len(logs) == 0 {
		t.Fatal("security-sensitive operation missing audit log")
	}
	redacted := SanitizeLog("token=abc private_key=secret warp_private_key=wg")
	if containsSecret(redacted, "abc") || containsSecret(redacted, "secret") || containsSecret(redacted, "wg") {
		t.Fatalf("log redaction failed: %s", redacted)
	}
	if err := cp.VerifyAuditChain(ctx, "tenant-a"); err != nil {
		t.Fatalf("audit chain should verify: %v", err)
	}
	cp.mu.Lock()
	cp.auditLogs[0].Action = "tampered"
	cp.mu.Unlock()
	if err := cp.VerifyAuditChain(ctx, "tenant-a"); err == nil {
		t.Fatal("tampered audit log should break hash chain")
	}
}

func runbookCatalogHasSeverity(catalog []RunbookDefinition, severity string) bool {
	for _, item := range catalog {
		if item.Severity == severity && item.ResponseTarget != "" && len(item.RunbookNames) > 0 {
			return true
		}
	}
	return false
}

func TestAPITokenScopesIPAllowlistConfirmationAndWarpKeyEncryption(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")

	if _, _, err := cp.CreateAPIToken(RequestContext{User: ctx.User, IP: ctx.IP}, "tenant-a", RoleAdmin, []string{"rules:read"}, []string{"198.51.100.10"}, now.Add(time.Hour)); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("api token creation without confirmation err=%v, want confirmation required", err)
	}
	_, rawToken, err := cp.CreateAPIToken(ctx, "tenant-a", RoleAdmin, []string{"rules:read"}, []string{"198.51.100.10"}, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("create api token: %v", err)
	}
	tokenCtx, err := cp.AuthenticateAPIToken(rawToken, "198.51.100.10")
	if err != nil {
		t.Fatalf("authenticate api token: %v", err)
	}
	if err := requireScope(tokenCtx, "rules:read"); err != nil {
		t.Fatalf("rules:read scope rejected: %v", err)
	}
	if err := requireScope(tokenCtx, "rules:write"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("rules:write scope err=%v, want forbidden", err)
	}
	if _, err := cp.AuthenticateAPIToken(rawToken, "198.51.100.11"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("api token IP allowlist err=%v, want forbidden", err)
	}

	profile, err := cp.AddWarpProfile(ctx, WarpProfile{ID: "warp-secret", TenantID: "tenant-a", Name: "warp-secret", EncryptedPrivateKey: "plain-private-key"})
	if err != nil {
		t.Fatalf("add encrypted warp profile: %v", err)
	}
	if profile.EncryptedPrivateKey == "plain-private-key" || !strings.HasPrefix(profile.EncryptedPrivateKey, "enc:") {
		t.Fatalf("warp private key not encrypted at rest: %q", profile.EncryptedPrivateKey)
	}
	plain, err := cp.DecryptWarpPrivateKey(ctx, "warp-secret")
	if err != nil {
		t.Fatalf("decrypt warp private key: %v", err)
	}
	if plain != "plain-private-key" {
		t.Fatalf("decrypted key=%q", plain)
	}
}

func adminCtx(tenantID string) RequestContext {
	return RequestContext{
		User:      User{ID: "admin-" + tenantID, TenantID: tenantID, Role: RoleAdmin},
		IP:        net.ParseIP("198.51.100.10"),
		Confirmed: true,
	}
}

func hasAuditAction(logs []AuditLog, action string) bool {
	for _, log := range logs {
		if log.Action == action {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsSecret(input, secret string) bool {
	return secret != "" && len(secret) >= 3 && (input == secret || len(input) > len(secret) && stringContains(input, secret))
}

func stringContains(input, needle string) bool {
	for i := 0; i+len(needle) <= len(input); i++ {
		if input[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func boolToLoss(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
