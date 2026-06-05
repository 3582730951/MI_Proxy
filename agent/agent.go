package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

type CongestionControl string

const (
	CCBBR   CongestionControl = "bbr"
	CCBBR2  CongestionControl = "bbr2"
	CCCubic CongestionControl = "cubic"
)

type SystemCapabilities struct {
	CongestionControls []CongestionControl
	QueueDisciplines   []string
	NoFile             int
	SomaxConn          int
	TCPFastOpen        int
	PortRangeStart     int
	PortRangeEnd       int
}

type KernelTuningAction struct {
	Kind    string
	Key     string
	Value   string
	Current string
	Reason  string
}

type RuntimeProfile struct {
	TargetRSSMB              int
	MetricsInterval          time.Duration
	LogLevel                 string
	ConnectionSoftLimit      int
	UDPConnectionLimit       int
	UDPRateLimitPPS          int
	Hysteria2ConnectionLimit int
	TUICConnectionLimit      int
	WatchdogEnabled          bool
	WatchdogInterval         time.Duration
	LastWatchdogAt           time.Time
	NextWatchdogDeadline     time.Time
}

type ConfigState struct {
	Version int
	Hash    string
	Content string
}

type ConfigApplyResult struct {
	Applied      bool
	Restarted    bool
	RolledBack   bool
	OldVersion   int
	NewVersion   int
	ChangedBytes int
}

type Agent struct {
	mu          sync.Mutex
	profile     RuntimeProfile
	caps        SystemCapabilities
	current     ConfigState
	previous    ConfigState
	tasks       map[string]string
	logBuffer   []string
	logNext     int
	logFull     bool
	logCapacity int
}

var ErrConfigRejected = errors.New("config rejected by validator")

const (
	targetNoFile         = 1_048_576
	targetSomaxConn      = 4096
	targetTCPFastOpen    = 3
	targetPortRangeStart = 10000
	targetPortRangeEnd   = 65000
)

func New(caps SystemCapabilities) *Agent {
	caps = normalizeCapabilities(caps)
	return &Agent{
		caps: caps,
		profile: RuntimeProfile{
			TargetRSSMB:              40,
			MetricsInterval:          15 * time.Second,
			LogLevel:                 "warn",
			ConnectionSoftLimit:      4096,
			UDPConnectionLimit:       2048,
			UDPRateLimitPPS:          100_000,
			Hysteria2ConnectionLimit: 1024,
			TUICConnectionLimit:      1024,
			WatchdogEnabled:          true,
			WatchdogInterval:         30 * time.Second,
		},
		tasks:       map[string]string{},
		logCapacity: 256,
		logBuffer:   make([]string, 256),
	}
}

func (a *Agent) Profile() RuntimeProfile {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.profile
}

func (a *Agent) Capabilities() SystemCapabilities {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.caps
}

func (a *Agent) KernelTuningPlan() []KernelTuningAction {
	a.mu.Lock()
	defer a.mu.Unlock()
	return kernelTuningPlan(a.caps)
}

func (a *Agent) ApplyKernelTuningPlan(apply func(KernelTuningAction) error) ([]KernelTuningAction, error) {
	actions := a.KernelTuningPlan()
	if len(actions) == 0 {
		return nil, nil
	}
	if apply == nil {
		return actions, nil
	}
	for _, action := range actions {
		if err := apply(action); err != nil {
			return nil, err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.caps.NoFile = maxInt(a.caps.NoFile, targetNoFile)
	a.caps.SomaxConn = maxInt(a.caps.SomaxConn, targetSomaxConn)
	a.caps.TCPFastOpen = maxInt(a.caps.TCPFastOpen, targetTCPFastOpen)
	if a.caps.PortRangeStart == 0 || a.caps.PortRangeStart > targetPortRangeStart {
		a.caps.PortRangeStart = targetPortRangeStart
	}
	if a.caps.PortRangeEnd < targetPortRangeEnd {
		a.caps.PortRangeEnd = targetPortRangeEnd
	}
	return append([]KernelTuningAction(nil), actions...), nil
}

func (a *Agent) PreferredCongestionControl() CongestionControl {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, wanted := range []CongestionControl{CCBBR2, CCBBR, CCCubic} {
		for _, got := range a.caps.CongestionControls {
			if got == wanted {
				return wanted
			}
		}
	}
	return CCCubic
}

func (a *Agent) ApplyLowResourceMode(memoryPressure float64) RuntimeProfile {
	a.mu.Lock()
	defer a.mu.Unlock()
	if memoryPressure > 0.85 {
		a.profile.MetricsInterval = 60 * time.Second
		a.profile.ConnectionSoftLimit = 1024
		a.profile.UDPConnectionLimit = 512
		a.profile.UDPRateLimitPPS = 25_000
		a.profile.Hysteria2ConnectionLimit = 256
		a.profile.TUICConnectionLimit = 256
		a.profile.LogLevel = "warn"
	} else if a.profile.MetricsInterval > 15*time.Second {
		a.profile.MetricsInterval = 15 * time.Second
		a.profile.ConnectionSoftLimit = 4096
		a.profile.UDPConnectionLimit = 2048
		a.profile.UDPRateLimitPPS = 100_000
		a.profile.Hysteria2ConnectionLimit = 1024
		a.profile.TUICConnectionLimit = 1024
	}
	return a.profile
}

func (a *Agent) WatchdogHeartbeat(now time.Time) RuntimeProfile {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	a.profile.LastWatchdogAt = now
	if a.profile.WatchdogEnabled && a.profile.WatchdogInterval > 0 {
		a.profile.NextWatchdogDeadline = now.Add(a.profile.WatchdogInterval * 2)
	}
	return a.profile
}

func (a *Agent) ApplyConfig(next ConfigState, validate func(ConfigState) error) (ConfigApplyResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if next.Hash == "" {
		next.Hash = hash(next.Content)
	}
	if a.current.Hash == next.Hash {
		return ConfigApplyResult{
			Applied:    true,
			Restarted:  false,
			OldVersion: a.current.Version,
			NewVersion: a.current.Version,
		}, nil
	}
	old := a.current
	if validate != nil {
		if err := validate(next); err != nil {
			return ConfigApplyResult{
				Applied:    false,
				RolledBack: true,
				OldVersion: old.Version,
				NewVersion: old.Version,
			}, err
		}
	}
	a.previous = old
	a.current = next
	return ConfigApplyResult{
		Applied:      true,
		Restarted:    requiresRestart(old.Content, next.Content),
		OldVersion:   old.Version,
		NewVersion:   next.Version,
		ChangedBytes: diffBytes(old.Content, next.Content),
	}, nil
}

func (a *Agent) Rollback() ConfigState {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.previous.Hash != "" {
		a.current, a.previous = a.previous, a.current
	}
	return a.current
}

func (a *Agent) CurrentConfig() ConfigState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current
}

func (a *Agent) ClaimTask(taskID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tasks[taskID] == "running" || a.tasks[taskID] == "complete" {
		return false
	}
	a.tasks[taskID] = "running"
	return true
}

func (a *Agent) CompleteTask(taskID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tasks[taskID] = "complete"
}

func (a *Agent) RecoverRunningTasks() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var tasks []string
	for taskID, state := range a.tasks {
		if state == "running" {
			tasks = append(tasks, taskID)
		}
	}
	sort.Strings(tasks)
	return tasks
}

func (a *Agent) RecordLog(line string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.logCapacity == 0 {
		return
	}
	a.logBuffer[a.logNext] = line
	a.logNext = (a.logNext + 1) % a.logCapacity
	if a.logNext == 0 {
		a.logFull = true
	}
}

func (a *Agent) LogSnapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.logFull {
		return append([]string(nil), a.logBuffer[:a.logNext]...)
	}
	out := make([]string, 0, a.logCapacity)
	out = append(out, a.logBuffer[a.logNext:]...)
	out = append(out, a.logBuffer[:a.logNext]...)
	return out
}

func (a *Agent) DrainErrorLogs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	snapshot := []string{}
	if !a.logFull {
		snapshot = append(snapshot, a.logBuffer[:a.logNext]...)
	} else {
		snapshot = append(snapshot, a.logBuffer[a.logNext:]...)
		snapshot = append(snapshot, a.logBuffer[:a.logNext]...)
	}
	out := make([]string, 0)
	for _, line := range snapshot {
		if strings.Contains(strings.ToLower(line), "error") || strings.Contains(strings.ToLower(line), "panic") {
			out = append(out, line)
		}
	}
	return out
}

func normalizeCapabilities(caps SystemCapabilities) SystemCapabilities {
	if len(caps.CongestionControls) == 0 {
		caps.CongestionControls = []CongestionControl{CCCubic}
	}
	if len(caps.QueueDisciplines) == 0 {
		caps.QueueDisciplines = []string{"fq", "fq_codel"}
	}
	if caps.NoFile == 0 {
		caps.NoFile = targetNoFile
	}
	if caps.SomaxConn == 0 {
		caps.SomaxConn = targetSomaxConn
	}
	if caps.TCPFastOpen == 0 {
		caps.TCPFastOpen = targetTCPFastOpen
	}
	if caps.PortRangeStart == 0 {
		caps.PortRangeStart = targetPortRangeStart
	}
	if caps.PortRangeEnd == 0 {
		caps.PortRangeEnd = targetPortRangeEnd
	}
	return caps
}

func kernelTuningPlan(caps SystemCapabilities) []KernelTuningAction {
	actions := []KernelTuningAction{}
	if caps.NoFile < targetNoFile {
		actions = append(actions, KernelTuningAction{
			Kind:    "rlimit",
			Key:     "nofile",
			Value:   "1048576",
			Current: intString(caps.NoFile),
			Reason:  "nofile_below_target",
		})
	}
	if caps.SomaxConn < targetSomaxConn {
		actions = append(actions, KernelTuningAction{
			Kind:    "sysctl",
			Key:     "net.core.somaxconn",
			Value:   "4096",
			Current: intString(caps.SomaxConn),
			Reason:  "somaxconn_below_target",
		})
	}
	if caps.TCPFastOpen < targetTCPFastOpen {
		actions = append(actions, KernelTuningAction{
			Kind:    "sysctl",
			Key:     "net.ipv4.tcp_fastopen",
			Value:   "3",
			Current: intString(caps.TCPFastOpen),
			Reason:  "tcp_fastopen_disabled",
		})
	}
	if caps.PortRangeStart > targetPortRangeStart || caps.PortRangeEnd < targetPortRangeEnd {
		actions = append(actions, KernelTuningAction{
			Kind:    "sysctl",
			Key:     "net.ipv4.ip_local_port_range",
			Value:   "10000 65000",
			Current: intString(caps.PortRangeStart) + " " + intString(caps.PortRangeEnd),
			Reason:  "port_range_narrow",
		})
	}
	return actions
}

func requiresRestart(oldContent, nextContent string) bool {
	oldHasInbound := strings.Contains(oldContent, `"inbounds"`)
	nextHasInbound := strings.Contains(nextContent, `"inbounds"`)
	return oldHasInbound != nextHasInbound
}

func diffBytes(oldContent, nextContent string) int {
	if oldContent == nextContent {
		return 0
	}
	min := len(oldContent)
	if len(nextContent) < min {
		min = len(nextContent)
	}
	changed := 0
	for i := 0; i < min; i++ {
		if oldContent[i] != nextContent[i] {
			changed++
		}
	}
	return changed + abs(len(oldContent)-len(nextContent))
}

func hash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func intString(value int) string {
	if value == 0 {
		return "0"
	}
	var out []byte
	n := value
	for n > 0 {
		out = append(out, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
