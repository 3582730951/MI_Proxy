package agent

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAgentLowResourceProfileAndKernelTuning(t *testing.T) {
	a := New(SystemCapabilities{
		CongestionControls: []CongestionControl{CCCubic, CCBBR},
		QueueDisciplines:   []string{"fq"},
	})
	if got := a.PreferredCongestionControl(); got != CCBBR {
		t.Fatalf("preferred cc=%s, want bbr", got)
	}
	caps := a.Capabilities()
	if caps.NoFile < 1_048_576 || caps.SomaxConn < 4096 || caps.TCPFastOpen != 3 {
		t.Fatalf("sysctl defaults not applied: %+v", caps)
	}
	profile := a.Profile()
	if profile.TargetRSSMB >= 40 && profile.MetricsInterval != 15*time.Second && profile.LogLevel != "warn" {
		t.Fatalf("unexpected default profile: %+v", profile)
	}
	if !profile.WatchdogEnabled || profile.WatchdogInterval != 30*time.Second {
		t.Fatalf("systemd watchdog defaults not enabled: %+v", profile)
	}
	if profile.UDPConnectionLimit != 2048 || profile.UDPRateLimitPPS != 100_000 {
		t.Fatalf("UDP protection defaults not applied: %+v", profile)
	}
	profile = a.ApplyLowResourceMode(0.86)
	if profile.MetricsInterval != 60*time.Second || profile.ConnectionSoftLimit > 1024 || profile.UDPConnectionLimit > 512 || profile.UDPRateLimitPPS > 25_000 {
		t.Fatalf("memory pressure did not degrade agent profile: %+v", profile)
	}
	profile = a.ApplyLowResourceMode(0.50)
	if profile.MetricsInterval != 15*time.Second || profile.ConnectionSoftLimit < 4096 || profile.UDPConnectionLimit < 2048 || profile.UDPRateLimitPPS < 100_000 {
		t.Fatalf("agent profile did not recover: %+v", profile)
	}
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	profile = a.WatchdogHeartbeat(now)
	if !profile.LastWatchdogAt.Equal(now) || !profile.NextWatchdogDeadline.Equal(now.Add(60*time.Second)) {
		t.Fatalf("watchdog heartbeat did not set systemd deadline: %+v", profile)
	}
}

func TestAgentKernelTuningPlanUsesStructuredActions(t *testing.T) {
	a := New(SystemCapabilities{
		NoFile:         1024,
		SomaxConn:      128,
		TCPFastOpen:    1,
		PortRangeStart: 30000,
		PortRangeEnd:   40000,
	})
	plan := a.KernelTuningPlan()
	if len(plan) != 4 {
		t.Fatalf("kernel tuning plan length=%d want 4: %+v", len(plan), plan)
	}
	want := map[string]string{
		"nofile":                       "rlimit",
		"net.core.somaxconn":           "sysctl",
		"net.ipv4.tcp_fastopen":        "sysctl",
		"net.ipv4.ip_local_port_range": "sysctl",
	}
	for _, action := range plan {
		if want[action.Key] != action.Kind || action.Value == "" || action.Reason == "" {
			t.Fatalf("unexpected structured tuning action: %+v", action)
		}
		if strings.ContainsAny(action.Key+action.Value, ";&|`$") {
			t.Fatalf("tuning action contains shell metacharacters: %+v", action)
		}
	}
	applied, err := a.ApplyKernelTuningPlan(func(action KernelTuningAction) error {
		if want[action.Key] == "" {
			t.Fatalf("unexpected action applied: %+v", action)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("apply kernel tuning plan: %v", err)
	}
	if len(applied) != 4 {
		t.Fatalf("applied actions=%d want 4", len(applied))
	}
	caps := a.Capabilities()
	if caps.NoFile < 1_048_576 || caps.SomaxConn < 4096 || caps.TCPFastOpen < 3 || caps.PortRangeStart > 10000 || caps.PortRangeEnd < 65000 {
		t.Fatalf("kernel tuning did not update capabilities: %+v", caps)
	}
	if retry := a.KernelTuningPlan(); len(retry) != 0 {
		t.Fatalf("kernel tuning plan should be empty after successful apply: %+v", retry)
	}

	failing := New(SystemCapabilities{SomaxConn: 128})
	_, err = failing.ApplyKernelTuningPlan(func(KernelTuningAction) error { return errors.New("apply failed") })
	if err == nil {
		t.Fatal("kernel tuning apply failure was ignored")
	}
	if caps := failing.Capabilities(); caps.SomaxConn != 128 {
		t.Fatalf("failed kernel tuning mutated capabilities: %+v", caps)
	}
}

func TestConfigDiffApplyRollbackAndNoDuplicateDangerousTasks(t *testing.T) {
	a := New(SystemCapabilities{})
	res, err := a.ApplyConfig(ConfigState{Version: 1, Content: `{"route":{"final":"proxy-default"}}`}, nil)
	if err != nil || !res.Applied {
		t.Fatalf("apply initial config: res=%+v err=%v", res, err)
	}
	res, err = a.ApplyConfig(ConfigState{Version: 1, Content: `{"route":{"final":"proxy-default"}}`}, nil)
	if err != nil || res.Restarted {
		t.Fatalf("same config should not restart: res=%+v err=%v", res, err)
	}
	reject := errors.New("invalid sing-box config")
	res, err = a.ApplyConfig(ConfigState{Version: 2, Content: `{"bad":true}`}, func(ConfigState) error { return reject })
	if !errors.Is(err, reject) || !res.RolledBack {
		t.Fatalf("invalid config should roll back: res=%+v err=%v", res, err)
	}
	if current := a.CurrentConfig(); current.Version != 1 {
		t.Fatalf("invalid config replaced current: %+v", current)
	}
	res, err = a.ApplyConfig(ConfigState{Version: 2, Content: `{"inbounds":[],"route":{"final":"proxy-default"}}`}, nil)
	if err != nil || !res.Restarted || res.ChangedBytes == 0 {
		t.Fatalf("inbound change should apply with restart: res=%+v err=%v", res, err)
	}
	rolled := a.Rollback()
	if rolled.Version != 1 {
		t.Fatalf("rollback got version %d want 1", rolled.Version)
	}

	if !a.ClaimTask("sysctl-tune") {
		t.Fatal("first task claim failed")
	}
	if a.ClaimTask("sysctl-tune") {
		t.Fatal("duplicate task claim accepted")
	}
	if got := a.RecoverRunningTasks(); len(got) != 1 || got[0] != "sysctl-tune" {
		t.Fatalf("running task not recoverable: %v", got)
	}
	a.CompleteTask("sysctl-tune")
	if a.ClaimTask("sysctl-tune") {
		t.Fatal("completed task should not repeat")
	}
}

func TestAgentRingBufferKeepsRecentLogsAndDrainsErrors(t *testing.T) {
	a := New(SystemCapabilities{})
	for i := 0; i < 300; i++ {
		a.RecordLog("info line")
	}
	a.RecordLog("error wireguard handshake failed")
	a.RecordLog("panic recovered from probe")

	logs := a.LogSnapshot()
	if len(logs) != 256 {
		t.Fatalf("ring buffer length=%d, want 256", len(logs))
	}
	errors := a.DrainErrorLogs()
	if len(errors) != 2 {
		t.Fatalf("error log count=%d, want 2: %v", len(errors), errors)
	}
	if errors[0] != "error wireguard handshake failed" || errors[1] != "panic recovered from probe" {
		t.Fatalf("unexpected error logs: %v", errors)
	}
}
