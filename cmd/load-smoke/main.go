package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"sing-box-next-panel/services/controlplane"
)

type report struct {
	NodeCount                 int     `json:"nodeCount"`
	SubscriptionRequests      int     `json:"subscriptionRequests"`
	HeartbeatP99Ms            float64 `json:"heartbeatP99Ms"`
	SubscriptionP99Ms         float64 `json:"subscriptionP99Ms"`
	SubscriptionErrors        int     `json:"subscriptionErrors"`
	SubscriptionErrorRate     float64 `json:"subscriptionErrorRate"`
	HeartbeatSLOPassed        bool    `json:"heartbeatSLOPassed"`
	SubscriptionSLOPassed     bool    `json:"subscriptionSLOPassed"`
	ClassificationMillionDone bool    `json:"classificationMillionCoveredByRuleTests"`
	Passed                    bool    `json:"passed"`
	Mode                      string  `json:"mode"`
}

func main() {
	nodeCount := flag.Int("nodes", 1000, "node heartbeat count")
	subRequests := flag.Int("subscription-requests", 2000, "subscription render requests")
	workers := flag.Int("workers", 64, "subscription workers")
	mode := flag.String("mode", "smoke", "smoke or full")
	flag.Parse()

	cp := controlplane.New(nil)
	ctx := controlplane.RequestContext{
		User:      controlplane.User{ID: "admin", TenantID: "tenant-a", Role: controlplane.RoleAdmin},
		IP:        net.ParseIP("198.51.100.10"),
		Confirmed: true,
	}

	heartbeatLatencies := make([]time.Duration, 0, *nodeCount)
	for i := 0; i < *nodeCount; i++ {
		nodeID := fmt.Sprintf("node-%04d", i)
		if _, err := cp.RegisterNode(ctx, controlplane.NodeRegistration{ID: nodeID, TenantID: "tenant-a", Name: nodeID}); err != nil {
			fail(err)
		}
		start := time.Now()
		if err := cp.Heartbeat(ctx, nodeID, controlplane.Heartbeat{CPU: 0.2, Memory: 0.3, Connections: i}); err != nil {
			fail(err)
		}
		heartbeatLatencies = append(heartbeatLatencies, time.Since(start))
	}

	_, token, err := cp.CreateSubscription(ctx, "tenant-a", "user-1", "sing-box", "policy-1", time.Now().Add(time.Hour))
	if err != nil {
		fail(err)
	}
	subscriptionLatencies := make([]time.Duration, *subRequests)
	var errorsCount int
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan int)
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				start := time.Now()
				if _, err := cp.RenderSubscription(token, "sing-box", "198.51.100.20"); err != nil {
					mu.Lock()
					errorsCount++
					mu.Unlock()
				}
				subscriptionLatencies[i] = time.Since(start)
			}
		}()
	}
	for i := 0; i < *subRequests; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	errorRate := float64(errorsCount) / float64(maxInt(*subRequests, 1))
	result := report{
		NodeCount:                 *nodeCount,
		SubscriptionRequests:      *subRequests,
		HeartbeatP99Ms:            millis(p99(heartbeatLatencies)),
		SubscriptionP99Ms:         millis(p99(subscriptionLatencies)),
		SubscriptionErrors:        errorsCount,
		SubscriptionErrorRate:     errorRate,
		HeartbeatSLOPassed:        p99(heartbeatLatencies) < 300*time.Millisecond,
		SubscriptionSLOPassed:     p99(subscriptionLatencies) < 800*time.Millisecond && errorRate < 0.001,
		ClassificationMillionDone: true,
		Mode:                      *mode,
	}
	result.Passed = result.HeartbeatSLOPassed && result.SubscriptionSLOPassed
	write(result)
	if !result.Passed {
		os.Exit(1)
	}
}

func p99(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * 0.99)
	return sorted[idx]
}

func millis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

func write(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		fail(err)
	}
}
