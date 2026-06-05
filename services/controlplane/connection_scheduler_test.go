package controlplane

import (
	"net"
	"testing"
	"time"

	"sing-box-next-panel/packages/rulecompiler"
)

func TestRouteConnectionUsesClientVPSResourceSignalsAndTargetCache(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := RequestContext{User: User{ID: "admin", TenantID: "tenant-a", Role: RoleAdmin}, IP: net.ParseIP("198.51.100.10"), Confirmed: true}
	_, err := cp.AddWarpProfile(ctx, WarpProfile{
		ID:       "warp-fast",
		TenantID: "tenant-a",
		Name:     "warp-fast",
		Status:   "healthy",
		LastProbe: WarpProbeResult{
			LatencyMs:      30,
			Loss:           0,
			HTTPSuccess:    true,
			CPUPressure:    0.1,
			MemoryPressure: 0.1,
			Connections:    10,
		},
	})
	if err != nil {
		t.Fatalf("add warp profile: %v", err)
	}
	var lookups int
	lookup := func(target string) GeoInfo {
		lookups++
		return GeoInfo{IP: "203.0.113.50", Region: "GLOBAL", ASN: "AS64500", ExpiresAt: now.Add(time.Hour)}
	}
	req := ConnectionRequest{
		TenantID:    "tenant-a",
		UserID:      "user-1",
		ClientIP:    "203.0.113.20",
		VPSPublicIP: "198.51.100.30",
		Target:      "video.example",
		Protocol:    "hysteria2",
		Mode:        SchedulePerformance,
	}
	first := cp.RouteConnection(req, lookup)
	second := cp.RouteConnection(req, lookup)
	if first.Outbound != "warp-fast" || first.Reason != "bbr-plus-dynamic-scheduler" {
		t.Fatalf("unexpected first decision: %+v", first)
	}
	if second.Outbound != first.Outbound || !second.CacheHit {
		t.Fatalf("target IP cache not used: first=%+v second=%+v", first, second)
	}
	if lookups != 1 {
		t.Fatalf("target geolocation lookup count=%d, want 1", lookups)
	}
}

func TestRouteConnectionDirectsPrivateAndCNTargetsAndExcludesScholar(t *testing.T) {
	cp := New(nil)
	direct := cp.RouteConnection(ConnectionRequest{TenantID: "tenant-a", ClientIP: "203.0.113.10", VPSPublicIP: "198.51.100.10", Target: "10.0.0.1"}, nil)
	if direct.Outbound != string(rulecompiler.OutboundDirect) {
		t.Fatalf("private target routed to %s", direct.Outbound)
	}
	cn := cp.RouteConnection(ConnectionRequest{TenantID: "tenant-a", ClientIP: "203.0.113.10", VPSPublicIP: "198.51.100.10", Target: "101.6.6.6"}, nil)
	if cn.Outbound != string(rulecompiler.OutboundDirect) {
		t.Fatalf("CN target routed to %s", cn.Outbound)
	}
	scholar := cp.RouteConnection(ConnectionRequest{TenantID: "tenant-a", ClientIP: "203.0.113.10", VPSPublicIP: "198.51.100.10", Target: "scholar.google.com"}, nil)
	if scholar.Outbound != string(rulecompiler.OutboundProxy) {
		t.Fatalf("scholar target routed to %s", scholar.Outbound)
	}
}
