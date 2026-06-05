package controlplane

import (
	"net/netip"
	"strings"
	"time"

	"sing-box-next-panel/packages/rulecompiler"
)

type ConnectionRequest struct {
	TenantID    string
	UserID      string
	ClientIP    string
	VPSPublicIP string
	Target      string
	Protocol    string
	Mode        ScheduleMode
}

type GeoInfo struct {
	IP        string
	Region    string
	ASN       string
	Private   bool
	ExpiresAt time.Time
}

type ConnectionDecision struct {
	Outbound     string
	Reason       string
	ClientRegion string
	VPSRegion    string
	TargetRegion string
	CacheHit     bool
	Score        float64
}

func (cp *ControlPlane) RouteConnection(req ConnectionRequest, lookup func(string) GeoInfo) ConnectionDecision {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	now := cp.now()
	client := classifyIP(req.ClientIP, now)
	vps := classifyIP(req.VPSPublicIP, now)
	target, cacheHit := cp.targetCache[normalizeTarget(req.Target)]
	if !cacheHit || now.After(target.ExpiresAt) {
		if lookup != nil {
			target = lookup(req.Target)
		} else {
			target = classifyIP(req.Target, now)
		}
		if target.ExpiresAt.IsZero() {
			target.ExpiresAt = now.Add(10 * time.Minute)
		}
		cp.targetCache[normalizeTarget(req.Target)] = target
		cacheHit = false
	}

	if target.Private || target.Region == "CN" {
		return ConnectionDecision{
			Outbound:     string(rulecompiler.OutboundDirect),
			Reason:       "target-direct-region-or-private",
			ClientRegion: client.Region,
			VPSRegion:    vps.Region,
			TargetRegion: target.Region,
			CacheHit:     cacheHit,
		}
	}
	if isGoogleScholar(req.Target) {
		return ConnectionDecision{
			Outbound:     string(rulecompiler.OutboundProxy),
			Reason:       "warp-exclude-google-scholar",
			ClientRegion: client.Region,
			VPSRegion:    vps.Region,
			TargetRegion: target.Region,
			CacheHit:     cacheHit,
		}
	}

	bestName := string(rulecompiler.OutboundProxy)
	bestReason := "proxy-default"
	bestScore := 1e9
	for _, profile := range cp.warpProfiles {
		if profile.TenantID != req.TenantID || profile.Status != "healthy" {
			continue
		}
		score := scoreProfile(profile, req.Mode)
		if sameRegion(client.Region, vps.Region) {
			score += 0.05
		}
		if req.Protocol == "hysteria2" || req.Protocol == "tuic" {
			score += profile.LastProbe.Loss * 2
		}
		if score < bestScore {
			bestName = profile.Name
			bestReason = "bbr-plus-dynamic-scheduler"
			bestScore = score
		}
	}
	return ConnectionDecision{
		Outbound:     bestName,
		Reason:       bestReason,
		ClientRegion: client.Region,
		VPSRegion:    vps.Region,
		TargetRegion: target.Region,
		CacheHit:     cacheHit,
		Score:        bestScore,
	}
}

func classifyIP(value string, now time.Time) GeoInfo {
	value = strings.TrimSpace(strings.ToLower(value))
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return GeoInfo{IP: value, Region: "GLOBAL", ASN: "unknown", ExpiresAt: now.Add(10 * time.Minute)}
	}
	info := GeoInfo{IP: addr.String(), Region: "GLOBAL", ASN: "unknown", Private: addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast(), ExpiresAt: now.Add(10 * time.Minute)}
	if info.Private {
		info.Region = "PRIVATE"
		return info
	}
	for _, prefix := range []string{"1.0.1.0/24", "14.0.0.0/8", "27.0.0.0/8", "36.0.0.0/8", "39.0.0.0/8", "42.0.0.0/8", "49.0.0.0/8", "58.0.0.0/7", "101.0.0.0/8", "103.0.0.0/8", "106.0.0.0/8", "110.0.0.0/8", "111.0.0.0/8", "112.0.0.0/5", "120.0.0.0/6", "139.0.0.0/8", "140.0.0.0/8", "150.0.0.0/8", "171.0.0.0/8", "175.0.0.0/8", "180.0.0.0/6", "202.0.0.0/7", "211.0.0.0/8", "218.0.0.0/7"} {
		parsed, err := netip.ParsePrefix(prefix)
		if err == nil && parsed.Contains(addr) {
			info.Region = "CN"
			return info
		}
	}
	return info
}

func normalizeTarget(target string) string {
	return strings.TrimSpace(strings.ToLower(target))
}

func sameRegion(a, b string) bool {
	return a != "" && a == b
}
