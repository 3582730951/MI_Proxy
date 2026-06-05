package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"sing-box-next-panel/agent"
)

func main() {
	lowResource := flag.Bool("low-resource", false, "enable low resource profile")
	flag.Parse()

	a := agent.New(agent.SystemCapabilities{
		CongestionControls: []agent.CongestionControl{agent.CCCubic, agent.CCBBR},
		QueueDisciplines:   []string{"fq"},
	})
	if *lowResource {
		a.ApplyLowResourceMode(0.90)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"profile":                a.Profile(),
		"capabilities":           a.Capabilities(),
		"kernel_tuning_plan":     a.KernelTuningPlan(),
		"preferred_congestion":   a.PreferredCongestionControl(),
		"binary_runtime_runtime": "go-static-target",
	}); err != nil {
		log.Fatal(err)
	}
}
