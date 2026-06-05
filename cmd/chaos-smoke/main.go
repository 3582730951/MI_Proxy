package main

import (
	"encoding/json"
	"net"
	"os"
	"time"

	"sing-box-next-panel/agent"
	"sing-box-next-panel/services/controlplane"
)

type check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type report struct {
	Checks []check `json:"checks"`
	Passed bool    `json:"passed"`
	Mode   string  `json:"mode"`
}

func main() {
	clock := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := controlplane.New(func() time.Time { return clock })
	ctx := controlplane.RequestContext{
		User:      controlplane.User{ID: "admin", TenantID: "tenant-a", Role: controlplane.RoleAdmin},
		IP:        net.ParseIP("198.51.100.10"),
		Confirmed: true,
	}
	result := report{Passed: true, Mode: "local-chaos-smoke"}

	node, err := cp.RegisterNode(ctx, controlplane.NodeRegistration{TenantID: "tenant-a", ID: "node-chaos"})
	result.add("node register before outage", err == nil && node.ID == "node-chaos", "node registry")
	cp.SweepNodeStates(clock.Add(2*time.Minute + time.Second))
	overview, _ := cp.Overview(ctx, "tenant-a")
	result.add("offline alert after heartbeat loss", overview.OfflineNodes == 1 && overview.Alerts == 1, "30s offline, 2m alert")

	_, err = cp.SetDependencyHealth(ctx, controlplane.DependencyPostgres, controlplane.DependencyUnavailable, "primary restart")
	dbAvailability, _ := cp.CoreAPIAvailability(ctx, "tenant-a")
	result.add("postgres restart enters 60s degraded recovery window", err == nil && dbAvailability.Status == "Degraded" && dbAvailability.CoreAPIsAvailable && !dbAvailability.WriteAPIsAvailable, dbAvailability.Status)
	clock = clock.Add(61 * time.Second)
	dbAvailability, _ = cp.CoreAPIAvailability(ctx, "tenant-a")
	result.add("postgres outage past 60s becomes critical", dbAvailability.Status == "Critical" && !dbAvailability.CoreAPIsAvailable, dbAvailability.Status)
	_, _ = cp.SetDependencyHealth(ctx, controlplane.DependencyPostgres, controlplane.DependencyHealthy, "primary recovered")
	clock = time.Date(2026, 6, 3, 12, 10, 0, 0, time.UTC)
	_, err = cp.SetDependencyHealth(ctx, controlplane.DependencyRedis, controlplane.DependencyUnavailable, "redis disconnected")
	clock = clock.Add(5 * time.Minute)
	redisAvailability, _ := cp.CoreAPIAvailability(ctx, "tenant-a")
	result.add("redis outage keeps core APIs degraded for 5m", err == nil && redisAvailability.Status == "Degraded" && redisAvailability.CoreAPIsAvailable && redisAvailability.RateLimitMode == "local-fallback", redisAvailability.RateLimitMode)

	for i := 1; i <= 4; i++ {
		_, _ = cp.AddWarpProfile(ctx, controlplane.WarpProfile{ID: "warp-chaos-" + string(rune('0'+i)), TenantID: "tenant-a", Name: "warp-chaos-" + string(rune('0'+i))})
	}
	_ = cp.ProbeWarpProfile("warp-chaos-1", controlplane.WarpProbeResult{DNSStatus: "servfail", HTTPSuccess: false, WireGuardStatus: "failed", Loss: 1, At: clock})
	_ = cp.ProbeWarpProfile("warp-chaos-2", controlplane.WarpProbeResult{DNSStatus: "ok", HTTPSuccess: false, WireGuardStatus: "failed", Loss: 1, At: clock})
	_ = cp.ProbeWarpProfile("warp-chaos-3", controlplane.WarpProbeResult{DNSStatus: "ok", HTTPSuccess: true, WireGuardStatus: "ok", Loss: 0, LatencyMs: 50, At: clock})
	_ = cp.ProbeWarpProfile("warp-chaos-4", controlplane.WarpProbeResult{DNSStatus: "ok", HTTPSuccess: true, WireGuardStatus: "ok", Loss: 0, LatencyMs: 40, At: clock})
	decision := cp.SelectWarp("example-warp-target.com", "user-1", controlplane.SchedulePerformance)
	result.add("50 percent WARP failure remains schedulable", decision.Outbound == "warp-chaos-4" || decision.Outbound == "warp-chaos-3", decision.Outbound)
	profiles, _ := cp.ListWarpProfiles(ctx, "tenant-a")
	cooldownCount := 0
	for _, profile := range profiles {
		if profile.Status == "cooldown" {
			cooldownCount++
		}
	}
	result.add("failed WARP profiles enter cooldown", cooldownCount == 2, "cooldown profiles")

	a := agent.New(agent.SystemCapabilities{})
	_, _ = a.ApplyConfig(agent.ConfigState{Version: 1, Content: `{"route":{"final":"proxy-default"}}`}, nil)
	_, applyErr := a.ApplyConfig(agent.ConfigState{Version: 2, Content: `{"bad":true}`}, func(agent.ConfigState) error { return agent.ErrConfigRejected })
	result.add("agent invalid config rollback", applyErr == agent.ErrConfigRejected && a.CurrentConfig().Version == 1, "config apply validation")
	profile := a.ApplyLowResourceMode(0.90)
	result.add("memory pressure degrades low resource node", profile.MetricsInterval == 60*time.Second && profile.ConnectionSoftLimit <= 1024 && profile.UDPConnectionLimit <= 512, "memory pressure > 85%")
	tuningAgent := agent.New(agent.SystemCapabilities{NoFile: 1024, SomaxConn: 128, TCPFastOpen: 1, PortRangeStart: 30000, PortRangeEnd: 40000})
	tuningPlan := tuningAgent.KernelTuningPlan()
	result.add("agent structured kernel tuning plan generated", len(tuningPlan) == 4 && tuningPlan[0].Kind != "", "nofile/somaxconn/tcp_fastopen/port_range")
	watchdog := a.WatchdogHeartbeat(clock)
	result.add("systemd watchdog heartbeat deadline", watchdog.WatchdogEnabled && watchdog.NextWatchdogDeadline.After(clock), "watchdog deadline")

	write(result)
	if !result.Passed {
		os.Exit(1)
	}
}

func (r *report) add(name string, passed bool, detail string) {
	r.Checks = append(r.Checks, check{Name: name, Passed: passed, Detail: detail})
	r.Passed = r.Passed && passed
}

func write(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		panic(err)
	}
}
