package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sing-box-next-panel/packages/rulecompiler"
)

type Role string

const (
	RoleOwner     Role = "Owner"
	RoleAdmin     Role = "Admin"
	RoleOperator  Role = "Operator"
	RoleAuditor   Role = "Auditor"
	RoleDeveloper Role = "Developer"
)

type User struct {
	ID       string
	TenantID string
	Email    string
	Role     Role
}

type RequestContext struct {
	User                User
	IP                  net.IP
	Scopes              []string
	AllowedRegions      []string
	AllowedNodeTags     []string
	AllowedEnvironments []string
	Confirmed           bool
}

type NodeStatus string

const (
	NodeOnline   NodeStatus = "online"
	NodeOffline  NodeStatus = "offline"
	NodeDegraded NodeStatus = "degraded"
)

type Node struct {
	ID                 string
	TenantID           string
	Name               string
	Region             string
	Provider           string
	Tags               []string
	Environment        string
	Status             NodeStatus
	AgentVersion       string
	SingBoxVersion     string
	KernelVersion      string
	CongestionControl  string
	QueueDiscipline    string
	NoFile             int
	SomaxConn          int
	TCPFastOpen        int
	PortRangeStart     int
	PortRangeEnd       int
	CPU                float64
	Memory             float64
	Connections        int
	ProtocolStats      []ProtocolInboundStat
	PublicIP           string
	ClientIPSample     string
	LastSeenAt         time.Time
	LastConfigVersion  int
	RecoverableTaskIDs []string
}

type DependencyName string

const (
	DependencyPostgres DependencyName = "postgres"
	DependencyRedis    DependencyName = "redis"
)

type DependencyState string

const (
	DependencyHealthy     DependencyState = "healthy"
	DependencyDegraded    DependencyState = "degraded"
	DependencyUnavailable DependencyState = "unavailable"
)

type DependencyHealth struct {
	Name                  DependencyName
	State                 DependencyState
	Message               string
	LastChangedAt         time.Time
	FailureStartedAt      time.Time
	RecoveryDeadlineAt    time.Time
	RecoveredAt           time.Time
	RecoveryTargetSeconds int
	CoreAPIsAvailable     bool
}

type CoreAPIAvailability struct {
	Status                          string
	CoreAPIsAvailable               bool
	WriteAPIsAvailable              bool
	SubscriptionGenerationAvailable bool
	RateLimitMode                   string
	Dependencies                    []DependencyHealth
	Messages                        []string
}

type NodeRegistration struct {
	ID                string
	TenantID          string
	Name              string
	Region            string
	Provider          string
	Tags              []string
	Environment       string
	AgentVersion      string
	SingBoxVersion    string
	KernelVersion     string
	CongestionControl string
	QueueDiscipline   string
	NoFile            int
	SomaxConn         int
	TCPFastOpen       int
	PortRangeStart    int
	PortRangeEnd      int
	PublicIP          string
}

type Heartbeat struct {
	AgentVersion      string
	SingBoxVersion    string
	KernelVersion     string
	CongestionControl string
	QueueDiscipline   string
	NoFile            int
	SomaxConn         int
	TCPFastOpen       int
	PortRangeStart    int
	PortRangeEnd      int
	CPU               float64
	Memory            float64
	LoadAvg           float64
	Disk              float64
	FDUsage           float64
	RxBps             int64
	TxBps             int64
	RxBytes           int64
	TxBytes           int64
	NetworkPPS        float64
	Connections       int
	ProtocolStats     []ProtocolInboundStat
	ClientIP          string
	At                time.Time
}

type ProtocolInboundStat struct {
	Protocol    string
	Connections int
	RxBps       int64
	TxBps       int64
	Errors      int
}

type NodeKernelTuning struct {
	NodeID            string
	TenantID          string
	Region            string
	CongestionControl string
	QueueDiscipline   string
	NoFile            int
	SomaxConn         int
	TCPFastOpen       int
	PortRangeStart    int
	PortRangeEnd      int
	Tuned             bool
	Issues            []string
}

type NodeMetricSample struct {
	NodeID      string
	TenantID    string
	At          time.Time
	CPU         float64
	Memory      float64
	LoadAvg     float64
	Disk        float64
	FDUsage     float64
	RxBps       int64
	TxBps       int64
	RxBytes     int64
	TxBytes     int64
	NetworkPPS  float64
	Connections int
}

type Alert struct {
	ID             string
	TenantID       string
	NodeID         string
	Severity       string
	Status         string
	Message        string
	CreatedAt      time.Time
	AcknowledgedAt time.Time
	AcknowledgedBy string
}

type Config struct {
	ID        string
	TenantID  string
	Version   int
	Content   string
	Hash      string
	Status    string
	CreatedBy string
	CreatedAt time.Time
}

type Deployment struct {
	ID           string
	NodeID       string
	ConfigID     string
	PayloadHash  string
	PayloadBytes int
	Status       string
	StartedAt    time.Time
	FinishedAt   time.Time
	Error        string
}

type NodeConfigPayload struct {
	NodeID   string
	TenantID string
	Version  int
	Content  string
	Hash     string
	Bytes    int
}

type Subscription struct {
	ID             string
	TenantID       string
	UserID         string
	TokenHash      string
	TokenKind      string
	Scope          string
	IPAllowlist    []string
	UsesRemaining  int
	ClientType     string
	PolicyID       string
	DeviceID       string
	Region         string
	Protocol       string
	OutboundPolicy string
	Revoked        bool
	ExpiresAt      time.Time
	CreatedAt      time.Time
	LastAccessedAt time.Time
}

type SubscriptionConversion struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenantId"`
	Name             string    `json:"name"`
	SourceURL        string    `json:"sourceUrl"`
	SourceChecksum   string    `json:"sourceChecksum"`
	SourceClientType string    `json:"sourceClientType"`
	TargetClientType string    `json:"targetClientType"`
	DeviceID         string    `json:"deviceId"`
	Region           string    `json:"region"`
	Protocol         string    `json:"protocol"`
	OutboundPolicy   string    `json:"outboundPolicy"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"createdAt"`
}

type SubscriptionConversionRequest struct {
	ID               string `json:"id"`
	TenantID         string `json:"tenantId"`
	Name             string `json:"name"`
	SourceURL        string `json:"sourceUrl"`
	SourceChecksum   string `json:"sourceChecksum"`
	SourceClientType string `json:"sourceClientType"`
	TargetClientType string `json:"targetClientType"`
	DeviceID         string `json:"deviceId"`
	Region           string `json:"region"`
	Protocol         string `json:"protocol"`
	OutboundPolicy   string `json:"outboundPolicy"`
}

type WarpProfile struct {
	ID                  string
	TenantID            string
	NodeID              string
	Name                string
	Source              string
	LicenseAccepted     bool
	PublicKey           string
	PeerPublicKey       string
	Endpoint            string
	Addresses           []string
	DNS                 []string
	AllowedIPs          []string
	EncryptedPrivateKey string `json:"encryptedPrivateKey,omitempty"`
	Status              string
	LastProbeAt         time.Time
	FailedAt            time.Time
	RemovedAt           time.Time
	CooldownUntil       time.Time
	LastProbe           WarpProbeResult
	Weight              float64
}

type WarpWireGuardImport struct {
	ID              string
	TenantID        string
	NodeID          string
	Name            string
	Config          string
	Weight          float64
	LicenseAccepted bool
}

type WarpProbeResult struct {
	LatencyMs       float64
	Loss            float64
	DNSStatus       string
	HTTPSuccess     bool
	WireGuardStatus string
	ExitIP          string
	ASN             string
	IPv4            bool
	IPv6            bool
	CPUPressure     float64
	MemoryPressure  float64
	Connections     int
	RecentFailures  int
	At              time.Time
}

type ArgoTunnel struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenantId"`
	Name                string    `json:"name"`
	Hostname            string    `json:"hostname"`
	ServiceURL          string    `json:"serviceUrl"`
	CloudflareAccountID string    `json:"cloudflareAccountId"`
	CloudflareZoneID    string    `json:"cloudflareZoneId"`
	TunnelID            string    `json:"tunnelId"`
	Status              string    `json:"status"`
	CreatedAt           time.Time `json:"createdAt"`
}

type CloudflareArgoAutomationRequest struct {
	ID                  string `json:"id"`
	TenantID            string `json:"tenantId"`
	Name                string `json:"name"`
	Hostname            string `json:"hostname"`
	ServiceURL          string `json:"serviceUrl"`
	CloudflareAccountID string `json:"cloudflareAccountId"`
	CloudflareZoneID    string `json:"cloudflareZoneId"`
	TunnelID            string `json:"tunnelId"`
}

type CloudflareArgoAutomationPlan struct {
	Tunnel           ArgoTunnel                    `json:"tunnel"`
	Operations       []CloudflareAPIOperation      `json:"operations"`
	TokenHandling    string                        `json:"tokenHandling"`
	RequiredScopes   []string                      `json:"requiredScopes"`
	RequiredAPIToken CloudflareAPITokenRequirement `json:"requiredApiToken"`
	GeneratedAt      time.Time                     `json:"generatedAt"`
}

type CloudflareAPIOperation struct {
	Name   string         `json:"name"`
	Method string         `json:"method"`
	URL    string         `json:"url"`
	Body   map[string]any `json:"body"`
}

type CloudflareAPITokenRequirement struct {
	Storage string   `json:"storage"`
	Scopes  []string `json:"scopes"`
}

type ScheduleMode string

const (
	ScheduleStable             ScheduleMode = "stable"
	SchedulePerformance        ScheduleMode = "performance"
	ScheduleLowResource        ScheduleMode = "low-resource"
	ScheduleCostAware          ScheduleMode = "cost-aware"
	ScheduleManual             ScheduleMode = "manual"
	ScheduleLeastLatency       ScheduleMode = "least-latency"
	ScheduleLeastError         ScheduleMode = "least-error"
	ScheduleWeightedRoundRobin ScheduleMode = "weighted-round-robin"
	ScheduleStickyByDomain     ScheduleMode = "sticky-by-domain"
	ScheduleStickyByUser       ScheduleMode = "sticky-by-user"
)

type ScheduleDecision struct {
	Outbound string
	Reason   string
	Score    float64
}

type RouteTraceRequest struct {
	Input    string
	Protocol string
	ClientIP string
	NodeID   string
}

type RouteDecisionTrace struct {
	ID              string
	TenantID        string
	ActorID         string
	Input           string
	Protocol        string
	ClientIP        string
	NodeID          string
	Outbound        rulecompiler.Outbound
	Reason          string
	RuleID          string
	MatchedRule     string
	MatchedSource   string
	MatchedRuleType rulecompiler.RuleType
	Decision        string
	CreatedAt       time.Time
}

type RuleSetSource struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenantId"`
	Name      string    `json:"name"`
	SourceURL string    `json:"sourceUrl"`
	Checksum  string    `json:"checksum"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type WebhookEndpoint struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenantId"`
	Name              string    `json:"name"`
	TargetURL         string    `json:"targetUrl"`
	EventTypes        []string  `json:"eventTypes"`
	Status            string    `json:"status"`
	SigningSecretHash string    `json:"-"`
	CreatedAt         time.Time `json:"createdAt"`
}

type WebhookEndpointRegistration struct {
	ID            string   `json:"id"`
	TenantID      string   `json:"tenantId"`
	Name          string   `json:"name"`
	TargetURL     string   `json:"targetUrl"`
	EventTypes    []string `json:"eventTypes"`
	SigningSecret string   `json:"signingSecret,omitempty"`
}

type AuditLog struct {
	ID           string
	TenantID     string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	IP           string
	UserAgent    string
	CreatedAt    time.Time
	PrevHash     string
	Hash         string
}

type APIToken struct {
	ID          string
	TenantID    string
	UserID      string
	Role        Role
	TokenHash   string
	Scopes      []string
	IPAllowlist []string
	ExpiresAt   time.Time
	Revoked     bool
	CreatedAt   time.Time
}

type AgentCredential struct {
	ID              string
	TenantID        string
	NodeID          string
	FingerprintHash string
	ExpiresAt       time.Time
	Revoked         bool
	CreatedAt       time.Time
	RotatedAt       time.Time
}

type PasskeyCredential struct {
	ID         string
	TenantID   string
	UserID     string
	Role       Role
	RPID       string
	Origin     string
	PublicKey  string
	SignCount  uint32
	Revoked    bool
	CreatedAt  time.Time
	LastUsedAt time.Time
}

type PasskeyChallenge struct {
	ID            string
	Kind          string
	TenantID      string
	UserID        string
	CredentialID  string
	RPID          string
	Origin        string
	ChallengeHash string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	UsedAt        time.Time
}

type Incident struct {
	ID         string
	TenantID   string
	Severity   string
	Status     string
	Title      string
	StartedAt  time.Time
	ResolvedAt time.Time
}

type RunbookState struct {
	TenantID                     string
	ReleasePaused                bool
	NodeDeploymentsPaused        bool
	SubscriptionCacheForced      bool
	SubscriptionEmergencyLimited bool
	CredentialRotationRequired   bool
	P3TriageRecorded             bool
	LastSelectedExit             string
	LastRunbook                  string
	LastRunbookAt                time.Time
}

type RunbookDefinition struct {
	Severity        string   `json:"severity"`
	IncidentType    string   `json:"incidentType"`
	ResponseTarget  string   `json:"responseTarget"`
	RunbookNames    []string `json:"runbookNames"`
	PrimaryMitigate string   `json:"primaryMitigate"`
}

type SecurityWaiver struct {
	ID              string
	TenantID        string
	Gate            string
	Severity        string
	Owner           string
	Reason          string
	RemediationPlan string
	ExpiresAt       time.Time
	CreatedAt       time.Time
	CreatedBy       string
}

type OverviewMetrics struct {
	Health             string
	OnlineNodes        int
	OfflineNodes       int
	Alerts             int
	TotalConnections   int
	ActiveConnections  int
	NewConnectionRate  float64
	TotalTrafficBytes  int64
	UpBps              int64
	DownBps            int64
	CPU                float64
	Memory             float64
	Disk               float64
	FDUsage            float64
	NetworkPPS         float64
	API99pMs           float64
	Subscription99pMs  float64
	ConfigApply99pMs   float64
	TopExitQualityRows []WarpProfile
	DependencyRows     []DependencyHealth
}

type CapacityRecommendation struct {
	TenantID               string
	Tier                   string
	OnlineNodes            int
	OfflineNodes           int
	ActiveConnections      int
	TargetSubscriptionRPS  int
	TargetAPIRPS           int
	TargetConnections      int
	RecommendedAPIReplicas int
	ControlPlaneMode       string
	AutoscalingActions     []string
	CostActions            []string
	Reasons                []string
}

type ControlPlane struct {
	mu                sync.RWMutex
	rulePublishMu     sync.Mutex
	nodes             map[string]Node
	configs           map[string]Config
	currentConfigByT  map[string]string
	deployments       map[string]Deployment
	subscriptions     map[string]Subscription
	subConversions    map[string]SubscriptionConversion
	alerts            []Alert
	auditLogs         []AuditLog
	routeTraces       []RouteDecisionTrace
	apiTokens         map[string]APIToken
	agentCredentials  map[string]AgentCredential
	passkeys          map[string]PasskeyCredential
	passkeyChallenges map[string]PasskeyChallenge
	warpProfiles      map[string]WarpProfile
	argoTunnels       map[string]ArgoTunnel
	ruleSetSources    map[string]RuleSetSource
	webhookEndpoints  map[string]WebhookEndpoint
	nodeMetricSamples []NodeMetricSample
	stickyByDomain    map[string]string
	stickyByUser      map[string]string
	weightedCursor    map[string]int
	targetCache       map[string]GeoInfo
	taskStates        map[string]string
	runbookStates     map[string]RunbookState
	securityWaivers   map[string]SecurityWaiver
	ruleRolloutByT    map[string]int
	rateWindows       map[string]rateWindow
	dependencies      map[DependencyName]DependencyHealth
	rulePolicy        *rulecompiler.CompiledPolicy
	versionByTenant   map[string]int
	envelopeKey       [32]byte
	allowedOrigins    map[string]struct{}
	now               func() time.Time
}

type SubscriptionOptions struct {
	TokenKind      string
	Scope          string
	IPAllowlist    []string
	UsesRemaining  int
	DeviceID       string
	Region         string
	Protocol       string
	OutboundPolicy string
}

type rateWindow struct {
	start time.Time
	count int
}

type RateLimitedAction string

const (
	RateLimitLogin         RateLimitedAction = "login"
	RateLimitAgentRegister RateLimitedAction = "agent-register"
	RateLimitConfigDeploy  RateLimitedAction = "config-deploy"
)

const routeTraceLimit = 5000
const nodeMetricSampleLimit = 10000
const nodeMetricQueryDefaultLimit = 100
const nodeMetricQueryMaxLimit = 500
const alertStatusOpen = "open"
const alertStatusAcknowledged = "acknowledged"

var (
	ErrUnauthorized         = errors.New("unauthorized")
	ErrBadRequest           = errors.New("bad request")
	ErrForbidden            = errors.New("forbidden")
	ErrNotFound             = errors.New("not found")
	ErrRevoked              = errors.New("subscription revoked")
	ErrRateLimited          = errors.New("rate limited")
	ErrReleasePaused        = errors.New("release paused")
	ErrConfirmationRequired = errors.New("sensitive operation requires confirmation")
)

func New(now func() time.Time) *ControlPlane {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	policy, _ := rulecompiler.Compile(rulecompiler.CompileOptions{
		WarpInclude: []string{"example-warp-target.com"},
	})
	cp := &ControlPlane{
		nodes:             map[string]Node{},
		configs:           map[string]Config{},
		currentConfigByT:  map[string]string{},
		deployments:       map[string]Deployment{},
		subscriptions:     map[string]Subscription{},
		subConversions:    map[string]SubscriptionConversion{},
		apiTokens:         map[string]APIToken{},
		agentCredentials:  map[string]AgentCredential{},
		passkeys:          map[string]PasskeyCredential{},
		passkeyChallenges: map[string]PasskeyChallenge{},
		warpProfiles:      map[string]WarpProfile{},
		argoTunnels:       map[string]ArgoTunnel{},
		ruleSetSources:    map[string]RuleSetSource{},
		webhookEndpoints:  map[string]WebhookEndpoint{},
		stickyByDomain:    map[string]string{},
		stickyByUser:      map[string]string{},
		weightedCursor:    map[string]int{},
		targetCache:       map[string]GeoInfo{},
		taskStates:        map[string]string{},
		runbookStates:     map[string]RunbookState{},
		securityWaivers:   map[string]SecurityWaiver{},
		ruleRolloutByT:    map[string]int{},
		rateWindows:       map[string]rateWindow{},
		dependencies:      defaultDependencyHealth(now()),
		rulePolicy:        policy,
		versionByTenant:   map[string]int{},
		allowedOrigins:    map[string]struct{}{"http://127.0.0.1:8080": {}, "http://localhost:8080": {}},
		now:               now,
	}
	if _, err := rand.Read(cp.envelopeKey[:]); err != nil {
		panic(err)
	}
	return cp
}

func defaultDependencyHealth(now time.Time) map[DependencyName]DependencyHealth {
	at := now
	return map[DependencyName]DependencyHealth{
		DependencyPostgres: {
			Name:                  DependencyPostgres,
			State:                 DependencyHealthy,
			LastChangedAt:         at,
			RecoveryTargetSeconds: dependencyRecoveryTargetSeconds(DependencyPostgres),
			CoreAPIsAvailable:     true,
		},
		DependencyRedis: {
			Name:                  DependencyRedis,
			State:                 DependencyHealthy,
			LastChangedAt:         at,
			RecoveryTargetSeconds: dependencyRecoveryTargetSeconds(DependencyRedis),
			CoreAPIsAvailable:     true,
		},
	}
}

func dependencyRecoveryTargetSeconds(name DependencyName) int {
	switch name {
	case DependencyPostgres:
		return 60
	case DependencyRedis:
		return 300
	default:
		return 0
	}
}

func (cp *ControlPlane) RegisterNode(ctx RequestContext, reg NodeRegistration) (Node, error) {
	if err := authorize(ctx.User, "nodes:write", reg.TenantID); err != nil {
		return Node{}, err
	}
	if err := requireScope(ctx, "nodes:write"); err != nil {
		return Node{}, err
	}
	node := Node{
		ID:                nonEmpty(reg.ID, randomID("node")),
		TenantID:          reg.TenantID,
		Name:              reg.Name,
		Region:            reg.Region,
		Provider:          reg.Provider,
		Tags:              copyStrings(reg.Tags),
		Environment:       reg.Environment,
		Status:            NodeOnline,
		AgentVersion:      reg.AgentVersion,
		SingBoxVersion:    reg.SingBoxVersion,
		KernelVersion:     reg.KernelVersion,
		CongestionControl: reg.CongestionControl,
		QueueDiscipline:   reg.QueueDiscipline,
		NoFile:            normalizeNonNegativeInt(reg.NoFile),
		SomaxConn:         normalizeNonNegativeInt(reg.SomaxConn),
		TCPFastOpen:       normalizeNonNegativeInt(reg.TCPFastOpen),
		PortRangeStart:    normalizeNonNegativeInt(reg.PortRangeStart),
		PortRangeEnd:      normalizeNonNegativeInt(reg.PortRangeEnd),
		PublicIP:          reg.PublicIP,
		LastSeenAt:        cp.now(),
	}
	if err := authorizeNodeABAC(ctx, node); err != nil {
		return Node{}, err
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.nodes[node.ID] = node
	cp.auditLocked(ctx, reg.TenantID, "node.register", "node", node.ID)
	return copyNode(node), nil
}

func (cp *ControlPlane) CheckRateLimit(action RateLimitedAction, key string) error {
	limit, period, ok := rateLimitPolicy(action)
	if !ok {
		return errors.New("unknown rate-limited action")
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.allowRequestLocked("rl:"+string(action)+":"+key, limit, period)
}

func rateLimitPolicy(action RateLimitedAction) (int, time.Duration, bool) {
	switch action {
	case RateLimitLogin:
		return 5, time.Minute, true
	case RateLimitAgentRegister:
		return 20, time.Minute, true
	case RateLimitConfigDeploy:
		return 30, time.Minute, true
	default:
		return 0, 0, false
	}
}

func (cp *ControlPlane) RotateAgentCredential(ctx RequestContext, nodeID string, expiresAt time.Time) (AgentCredential, string, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	node, ok := cp.nodes[nodeID]
	if !ok {
		return AgentCredential{}, "", ErrNotFound
	}
	if err := authorize(ctx.User, "nodes:write", node.TenantID); err != nil {
		return AgentCredential{}, "", err
	}
	if err := requireScope(ctx, "nodes:write"); err != nil {
		return AgentCredential{}, "", err
	}
	if err := authorizeNodeABAC(ctx, node); err != nil {
		return AgentCredential{}, "", err
	}
	if err := requireConfirmation(ctx); err != nil {
		return AgentCredential{}, "", err
	}
	now := cp.now()
	for id, credential := range cp.agentCredentials {
		if credential.NodeID == nodeID && !credential.Revoked {
			credential.Revoked = true
			credential.RotatedAt = now
			cp.agentCredentials[id] = credential
		}
	}
	if expiresAt.IsZero() {
		expiresAt = now.Add(24 * time.Hour)
	}
	fingerprint := randomToken()
	credential := AgentCredential{
		ID:              randomID("agentcred"),
		TenantID:        node.TenantID,
		NodeID:          nodeID,
		FingerprintHash: HashAgentFingerprint(fingerprint),
		ExpiresAt:       expiresAt,
		CreatedAt:       now,
	}
	cp.agentCredentials[credential.ID] = credential
	cp.auditLocked(ctx, node.TenantID, "agent_credential.rotate", "node", nodeID)
	return credential, fingerprint, nil
}

func (cp *ControlPlane) AuthenticateAgent(nodeID, fingerprint, ip string) (RequestContext, error) {
	if nodeID == "" || fingerprint == "" {
		return RequestContext{}, ErrUnauthorized
	}
	hash := HashAgentFingerprint(fingerprint)
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	node, ok := cp.nodes[nodeID]
	if !ok {
		return RequestContext{}, ErrNotFound
	}
	for _, credential := range cp.agentCredentials {
		if credential.NodeID != nodeID || credential.FingerprintHash != hash {
			continue
		}
		if credential.Revoked || (!credential.ExpiresAt.IsZero() && cp.now().After(credential.ExpiresAt)) {
			return RequestContext{}, ErrRevoked
		}
		return RequestContext{
			User: User{
				ID:       "agent:" + nodeID,
				TenantID: node.TenantID,
				Role:     RoleDeveloper,
			},
			IP:     net.ParseIP(ip),
			Scopes: []string{"agent:heartbeat"},
		}, nil
	}
	return RequestContext{}, ErrUnauthorized
}

func (cp *ControlPlane) BeginPasskeyRegistration(ctx RequestContext, rpID, origin string, expiresAt time.Time) (PasskeyChallenge, string, error) {
	if err := authorize(ctx.User, "passkeys:write", ctx.User.TenantID); err != nil {
		return PasskeyChallenge{}, "", err
	}
	if err := requireScope(ctx, "passkeys:write"); err != nil {
		return PasskeyChallenge{}, "", err
	}
	if err := requireConfirmation(ctx); err != nil {
		return PasskeyChallenge{}, "", err
	}
	if err := ValidatePasskeyRPOrigin(rpID, origin); err != nil {
		return PasskeyChallenge{}, "", err
	}
	now := cp.now()
	if expiresAt.IsZero() {
		expiresAt = now.Add(5 * time.Minute)
	}
	rawChallenge := randomToken()
	challenge := PasskeyChallenge{
		ID:            randomID("passkeychal"),
		Kind:          "registration",
		TenantID:      ctx.User.TenantID,
		UserID:        ctx.User.ID,
		RPID:          strings.ToLower(strings.TrimSpace(rpID)),
		Origin:        strings.ToLower(strings.TrimSpace(origin)),
		ChallengeHash: HashPasskeyChallenge(rawChallenge),
		CreatedAt:     now,
		ExpiresAt:     expiresAt,
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.passkeyChallenges[challenge.ID] = challenge
	cp.auditLocked(ctx, ctx.User.TenantID, "passkey.registration.begin", "user", ctx.User.ID)
	return publicPasskeyChallenge(challenge), rawChallenge, nil
}

func (cp *ControlPlane) RegisterPasskey(ctx RequestContext, challengeID, rawChallenge, credentialID, encodedPublicKey string, signCount uint32) (PasskeyCredential, error) {
	if strings.TrimSpace(credentialID) == "" {
		return PasskeyCredential{}, errors.New("credential ID is required")
	}
	if _, err := DecodePasskeyPublicKey(encodedPublicKey); err != nil {
		return PasskeyCredential{}, err
	}
	if err := authorize(ctx.User, "passkeys:write", ctx.User.TenantID); err != nil {
		return PasskeyCredential{}, err
	}
	if err := requireScope(ctx, "passkeys:write"); err != nil {
		return PasskeyCredential{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return PasskeyCredential{}, err
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()
	challenge, err := cp.consumePasskeyChallengeLocked(challengeID, rawChallenge, "registration")
	if err != nil {
		return PasskeyCredential{}, err
	}
	if challenge.TenantID != ctx.User.TenantID || challenge.UserID != ctx.User.ID {
		return PasskeyCredential{}, ErrForbidden
	}
	if existing, ok := cp.passkeys[credentialID]; ok && !existing.Revoked {
		return PasskeyCredential{}, ErrForbidden
	}
	credential := PasskeyCredential{
		ID:        credentialID,
		TenantID:  ctx.User.TenantID,
		UserID:    ctx.User.ID,
		Role:      ctx.User.Role,
		RPID:      challenge.RPID,
		Origin:    challenge.Origin,
		PublicKey: encodedPublicKey,
		SignCount: signCount,
		CreatedAt: cp.now(),
	}
	cp.passkeys[credential.ID] = credential
	cp.auditLocked(ctx, ctx.User.TenantID, "passkey.register", "user", ctx.User.ID)
	return credential, nil
}

func (cp *ControlPlane) BeginPasskeyAuthentication(userID, credentialID, rpID, origin string, expiresAt time.Time) (PasskeyChallenge, string, error) {
	if err := ValidatePasskeyRPOrigin(rpID, origin); err != nil {
		return PasskeyChallenge{}, "", err
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	credential, ok := cp.passkeys[credentialID]
	if !ok || credential.Revoked || credential.UserID != userID {
		return PasskeyChallenge{}, "", ErrUnauthorized
	}
	if credential.RPID != strings.ToLower(strings.TrimSpace(rpID)) || credential.Origin != strings.ToLower(strings.TrimSpace(origin)) {
		return PasskeyChallenge{}, "", ErrForbidden
	}
	now := cp.now()
	if expiresAt.IsZero() {
		expiresAt = now.Add(5 * time.Minute)
	}
	rawChallenge := randomToken()
	challenge := PasskeyChallenge{
		ID:            randomID("passkeychal"),
		Kind:          "authentication",
		TenantID:      credential.TenantID,
		UserID:        credential.UserID,
		CredentialID:  credential.ID,
		RPID:          credential.RPID,
		Origin:        credential.Origin,
		ChallengeHash: HashPasskeyChallenge(rawChallenge),
		CreatedAt:     now,
		ExpiresAt:     expiresAt,
	}
	cp.passkeyChallenges[challenge.ID] = challenge
	return publicPasskeyChallenge(challenge), rawChallenge, nil
}

func (cp *ControlPlane) VerifyPasskeyAuthentication(challengeID, rawChallenge string, signature []byte, signCount uint32, ip string) (RequestContext, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	challenge, err := cp.consumePasskeyChallengeLocked(challengeID, rawChallenge, "authentication")
	if err != nil {
		return RequestContext{}, err
	}
	credential, ok := cp.passkeys[challenge.CredentialID]
	if !ok || credential.Revoked {
		return RequestContext{}, ErrUnauthorized
	}
	if signCount <= credential.SignCount {
		return RequestContext{}, ErrForbidden
	}
	if !VerifyPasskeyAssertion(credential.PublicKey, rawChallenge, credential.RPID, credential.Origin, credential.UserID, credential.ID, signCount, signature) {
		return RequestContext{}, ErrUnauthorized
	}
	credential.SignCount = signCount
	credential.LastUsedAt = cp.now()
	cp.passkeys[credential.ID] = credential
	ctx := RequestContext{
		User: User{
			ID:       credential.UserID,
			TenantID: credential.TenantID,
			Role:     credential.Role,
		},
		IP:        net.ParseIP(ip),
		Confirmed: true,
	}
	cp.auditLocked(ctx, credential.TenantID, "passkey.authenticate", "user", credential.UserID)
	return ctx, nil
}

func (cp *ControlPlane) consumePasskeyChallengeLocked(challengeID, rawChallenge, kind string) (PasskeyChallenge, error) {
	challenge, ok := cp.passkeyChallenges[challengeID]
	if !ok {
		return PasskeyChallenge{}, ErrNotFound
	}
	if challenge.Kind != kind || !challenge.UsedAt.IsZero() {
		return PasskeyChallenge{}, ErrForbidden
	}
	if cp.now().After(challenge.ExpiresAt) {
		return PasskeyChallenge{}, ErrRevoked
	}
	if challenge.ChallengeHash != HashPasskeyChallenge(rawChallenge) {
		return PasskeyChallenge{}, ErrUnauthorized
	}
	challenge.UsedAt = cp.now()
	cp.passkeyChallenges[challengeID] = challenge
	return challenge, nil
}

func publicPasskeyChallenge(challenge PasskeyChallenge) PasskeyChallenge {
	challenge.ChallengeHash = ""
	return challenge
}

func (cp *ControlPlane) Heartbeat(ctx RequestContext, nodeID string, hb Heartbeat) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	node, ok := cp.nodes[nodeID]
	if !ok {
		return ErrNotFound
	}
	if ctx.User.ID == "agent:"+nodeID && ctx.User.TenantID == node.TenantID && explicitScopeAllows(ctx, "agent:heartbeat") {
		// Agent mTLS credentials are limited to heartbeat updates.
	} else {
		if err := authorize(ctx.User, "nodes:write", node.TenantID); err != nil {
			return err
		}
		if err := requireScope(ctx, "nodes:write"); err != nil {
			return err
		}
		if err := authorizeNodeABAC(ctx, node); err != nil {
			return err
		}
	}
	if hb.At.IsZero() {
		hb.At = cp.now()
	}
	node.Status = NodeOnline
	node.LastSeenAt = hb.At
	node.AgentVersion = nonEmpty(hb.AgentVersion, node.AgentVersion)
	node.SingBoxVersion = nonEmpty(hb.SingBoxVersion, node.SingBoxVersion)
	node.KernelVersion = nonEmpty(hb.KernelVersion, node.KernelVersion)
	node.CongestionControl = nonEmpty(hb.CongestionControl, node.CongestionControl)
	node.QueueDiscipline = nonEmpty(hb.QueueDiscipline, node.QueueDiscipline)
	node.NoFile = retainOrUpdateNonNegative(node.NoFile, hb.NoFile)
	node.SomaxConn = retainOrUpdateNonNegative(node.SomaxConn, hb.SomaxConn)
	node.TCPFastOpen = retainOrUpdateNonNegative(node.TCPFastOpen, hb.TCPFastOpen)
	node.PortRangeStart = retainOrUpdateNonNegative(node.PortRangeStart, hb.PortRangeStart)
	node.PortRangeEnd = retainOrUpdateNonNegative(node.PortRangeEnd, hb.PortRangeEnd)
	node.CPU = hb.CPU
	node.Memory = hb.Memory
	node.Connections = hb.Connections
	node.ProtocolStats = normalizeProtocolStats(hb.ProtocolStats)
	node.ClientIPSample = hb.ClientIP
	cp.nodes[nodeID] = node
	cp.recordNodeMetricLocked(NodeMetricSample{
		NodeID:      nodeID,
		TenantID:    node.TenantID,
		At:          hb.At,
		CPU:         hb.CPU,
		Memory:      hb.Memory,
		LoadAvg:     hb.LoadAvg,
		Disk:        hb.Disk,
		FDUsage:     hb.FDUsage,
		RxBps:       hb.RxBps,
		TxBps:       hb.TxBps,
		RxBytes:     hb.RxBytes,
		TxBytes:     hb.TxBytes,
		NetworkPPS:  hb.NetworkPPS,
		Connections: hb.Connections,
	})
	return nil
}

func (cp *ControlPlane) ListNodes(ctx RequestContext, tenantID string) ([]Node, error) {
	if err := authorize(ctx.User, "nodes:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "nodes:read"); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	nodes := make([]Node, 0)
	for _, node := range cp.nodes {
		if node.TenantID != tenantID {
			continue
		}
		if err := authorizeNodeABAC(ctx, node); err != nil {
			continue
		}
		nodes = append(nodes, copyNode(node))
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return nodes, nil
}

func (cp *ControlPlane) GetNode(ctx RequestContext, nodeID string) (Node, error) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	node, ok := cp.nodes[nodeID]
	if !ok {
		return Node{}, ErrNotFound
	}
	if err := authorize(ctx.User, "nodes:read", node.TenantID); err != nil {
		return Node{}, err
	}
	if err := requireScope(ctx, "nodes:read"); err != nil {
		return Node{}, err
	}
	if err := authorizeNodeABAC(ctx, node); err != nil {
		return Node{}, err
	}
	return copyNode(node), nil
}

func (cp *ControlPlane) KernelTuning(ctx RequestContext, tenantID string) ([]NodeKernelTuning, error) {
	if err := authorize(ctx.User, "nodes:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "nodes:read"); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	rows := []NodeKernelTuning{}
	for _, node := range cp.nodes {
		if node.TenantID != tenantID {
			continue
		}
		if err := authorizeNodeABAC(ctx, node); err != nil {
			continue
		}
		rows = append(rows, kernelTuningStatus(node))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].NodeID < rows[j].NodeID })
	return rows, nil
}

func (cp *ControlPlane) DeployConfig(ctx RequestContext, nodeID, content string, simulateFailure bool) (Deployment, error) {
	cp.mu.RLock()
	node, ok := cp.nodes[nodeID]
	cp.mu.RUnlock()
	if !ok {
		return Deployment{}, ErrNotFound
	}
	if err := authorize(ctx.User, "nodes:write", node.TenantID); err != nil {
		return Deployment{}, err
	}
	if err := requireScope(ctx, "nodes:write"); err != nil {
		return Deployment{}, err
	}
	if err := authorizeNodeABAC(ctx, node); err != nil {
		return Deployment{}, err
	}
	payload, payloadErr := buildNodeConfigPayload(node, content, 0)
	if payloadErr != nil {
		return Deployment{}, payloadErr
	}
	cfg, err := cp.PublishConfig(ctx, node.TenantID, content, simulateFailure)
	if err == nil {
		payload.Version = cfg.Version
	}
	deployment := Deployment{
		ID:           randomID("deploy"),
		NodeID:       nodeID,
		ConfigID:     cfg.ID,
		PayloadHash:  payload.Hash,
		PayloadBytes: payload.Bytes,
		Status:       "succeeded",
		StartedAt:    cp.now(),
	}
	if err != nil {
		deployment.Status = "failed"
		deployment.Error = err.Error()
	}
	deployment.FinishedAt = cp.now()
	cp.mu.Lock()
	cp.deployments[deployment.ID] = deployment
	if err == nil {
		node.LastConfigVersion = cfg.Version
		cp.nodes[nodeID] = node
		cp.auditLocked(ctx, node.TenantID, "node.deploy_config", "node", nodeID)
	}
	cp.mu.Unlock()
	return deployment, err
}

func (cp *ControlPlane) BuildNodeConfigPayload(ctx RequestContext, nodeID, content string) (NodeConfigPayload, error) {
	cp.mu.RLock()
	node, ok := cp.nodes[nodeID]
	version := 1
	if ok {
		version = cp.versionByTenant[node.TenantID] + 1
	}
	cp.mu.RUnlock()
	if !ok {
		return NodeConfigPayload{}, ErrNotFound
	}
	if err := authorize(ctx.User, "nodes:write", node.TenantID); err != nil {
		return NodeConfigPayload{}, err
	}
	if err := requireScope(ctx, "nodes:write"); err != nil {
		return NodeConfigPayload{}, err
	}
	if err := authorizeNodeABAC(ctx, node); err != nil {
		return NodeConfigPayload{}, err
	}
	return buildNodeConfigPayload(node, content, version)
}

func buildNodeConfigPayload(node Node, content string, version int) (NodeConfigPayload, error) {
	rendered := content
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &root); err == nil {
		if subset, ok := renderNodeScopedConfig(node, root); ok {
			encoded, err := json.Marshal(subset)
			if err != nil {
				return NodeConfigPayload{}, err
			}
			rendered = string(encoded)
		}
	}
	return NodeConfigPayload{
		NodeID:   node.ID,
		TenantID: node.TenantID,
		Version:  version,
		Content:  rendered,
		Hash:     shortHash(rendered),
		Bytes:    len(rendered),
	}, nil
}

type nodeScopedConfig struct {
	NodeID      string          `json:"nodeId"`
	TenantID    string          `json:"tenantId"`
	Region      string          `json:"region,omitempty"`
	Environment string          `json:"environment,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Global      json.RawMessage `json:"global,omitempty"`
	Node        json.RawMessage `json:"node,omitempty"`
}

func renderNodeScopedConfig(node Node, root map[string]json.RawMessage) (nodeScopedConfig, bool) {
	var scoped nodeScopedConfig
	var matched bool
	if global, ok := root["global"]; ok && len(global) > 0 {
		scoped.Global = copyRawJSON(global)
		matched = true
	}
	if nodesRaw, ok := root["nodes"]; ok && len(nodesRaw) > 0 {
		var nodes map[string]json.RawMessage
		if err := json.Unmarshal(nodesRaw, &nodes); err == nil {
			if nodeRaw, ok := nodes[node.ID]; ok && len(nodeRaw) > 0 {
				scoped.Node = copyRawJSON(nodeRaw)
				matched = true
			}
		}
	}
	if !matched {
		return nodeScopedConfig{}, false
	}
	scoped.NodeID = node.ID
	scoped.TenantID = node.TenantID
	scoped.Region = node.Region
	scoped.Environment = node.Environment
	scoped.Tags = copyStrings(node.Tags)
	return scoped, true
}

func copyRawJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	copied := make([]byte, len(raw))
	copy(copied, raw)
	return copied
}

func (cp *ControlPlane) SweepNodeStates(now time.Time) []Alert {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	var newAlerts []Alert
	for id, node := range cp.nodes {
		age := now.Sub(node.LastSeenAt)
		if age >= 30*time.Second && node.Status != NodeOffline {
			node.Status = NodeOffline
			cp.nodes[id] = node
		}
		if age >= 2*time.Minute && !cp.alertExistsLocked(node.TenantID, node.ID, "node.offline") {
			alert := Alert{
				ID:        randomID("alert"),
				TenantID:  node.TenantID,
				NodeID:    node.ID,
				Severity:  "P2",
				Status:    alertStatusOpen,
				Message:   "node.offline",
				CreatedAt: now,
			}
			cp.alerts = append(cp.alerts, alert)
			newAlerts = append(newAlerts, alert)
		}
	}
	return newAlerts
}

func (cp *ControlPlane) ClaimDangerousTask(nodeID, taskID string) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	key := nodeID + ":" + taskID
	switch cp.taskStates[key] {
	case "running", "complete":
		return false
	default:
		cp.taskStates[key] = "running"
		return true
	}
}

func (cp *ControlPlane) CompleteDangerousTask(nodeID, taskID string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.taskStates[nodeID+":"+taskID] = "complete"
}

func (cp *ControlPlane) RecoverRunningTasks(nodeID string) []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	var tasks []string
	prefix := nodeID + ":"
	for key, state := range cp.taskStates {
		if strings.HasPrefix(key, prefix) && state == "running" {
			tasks = append(tasks, strings.TrimPrefix(key, prefix))
		}
	}
	sort.Strings(tasks)
	return tasks
}

func (cp *ControlPlane) PublishConfig(ctx RequestContext, tenantID, content string, simulateFailure bool) (Config, error) {
	if err := authorize(ctx.User, "configs:write", tenantID); err != nil {
		return Config{}, err
	}
	if err := requireScope(ctx, "configs:write"); err != nil {
		return Config{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return Config{}, err
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.runbookStates[tenantID].ReleasePaused {
		return Config{}, ErrReleasePaused
	}
	version := cp.versionByTenant[tenantID] + 1
	cfg := Config{
		ID:        randomID("cfg"),
		TenantID:  tenantID,
		Version:   version,
		Content:   content,
		Hash:      shortHash(content),
		Status:    "pending",
		CreatedBy: ctx.User.ID,
		CreatedAt: cp.now(),
	}
	if simulateFailure {
		cfg.Status = "failed"
		cp.configs[cfg.ID] = cfg
		cp.auditLocked(ctx, tenantID, "config.publish.failed", "config", cfg.ID)
		return cfg, errors.New("simulated publish failure")
	}
	cfg.Status = "active"
	cp.configs[cfg.ID] = cfg
	cp.currentConfigByT[tenantID] = cfg.ID
	cp.versionByTenant[tenantID] = version
	cp.auditLocked(ctx, tenantID, "config.publish", "config", cfg.ID)
	return cfg, nil
}

func (cp *ControlPlane) CurrentConfig(tenantID string) (Config, bool) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	id, ok := cp.currentConfigByT[tenantID]
	if !ok {
		return Config{}, false
	}
	cfg, ok := cp.configs[id]
	return cfg, ok
}

func (cp *ControlPlane) RollbackConfig(ctx RequestContext, tenantID string, version int) (Config, error) {
	if err := authorize(ctx.User, "configs:write", tenantID); err != nil {
		return Config{}, err
	}
	if err := requireScope(ctx, "configs:write"); err != nil {
		return Config{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return Config{}, err
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for id, cfg := range cp.configs {
		if cfg.TenantID == tenantID && cfg.Version == version && cfg.Status == "active" {
			cp.currentConfigByT[tenantID] = id
			cp.auditLocked(ctx, tenantID, "config.rollback", "config", id)
			return cfg, nil
		}
	}
	return Config{}, ErrNotFound
}

func (cp *ControlPlane) CreateSubscription(ctx RequestContext, tenantID, userID, clientType, policyID string, expiresAt time.Time) (Subscription, string, error) {
	return cp.CreateSubscriptionWithOptions(ctx, tenantID, userID, clientType, policyID, expiresAt, SubscriptionOptions{TokenKind: "long", Scope: "read"})
}

func (cp *ControlPlane) CreateSubscriptionWithOptions(ctx RequestContext, tenantID, userID, clientType, policyID string, expiresAt time.Time, opts SubscriptionOptions) (Subscription, string, error) {
	if err := authorize(ctx.User, "subscriptions:write", tenantID); err != nil {
		return Subscription{}, "", err
	}
	if err := requireScope(ctx, "subscriptions:write"); err != nil {
		return Subscription{}, "", err
	}
	if err := requireConfirmation(ctx); err != nil {
		return Subscription{}, "", err
	}
	if opts.TokenKind == "" {
		opts.TokenKind = "long"
	}
	if opts.Scope == "" {
		opts.Scope = "read"
	}
	token := randomToken()
	sub := Subscription{
		ID:             randomID("sub"),
		TenantID:       tenantID,
		UserID:         userID,
		TokenHash:      HashToken(token),
		TokenKind:      opts.TokenKind,
		Scope:          opts.Scope,
		IPAllowlist:    append([]string(nil), opts.IPAllowlist...),
		UsesRemaining:  opts.UsesRemaining,
		ClientType:     clientType,
		PolicyID:       policyID,
		DeviceID:       sanitizeSubscriptionField(opts.DeviceID, 64),
		Region:         sanitizeSubscriptionField(opts.Region, 32),
		Protocol:       normalizeSubscriptionProtocol(opts.Protocol),
		OutboundPolicy: normalizeSubscriptionOutboundPolicy(opts.OutboundPolicy),
		ExpiresAt:      expiresAt,
		CreatedAt:      cp.now(),
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.subscriptions[sub.ID] = sub
	cp.auditLocked(ctx, tenantID, "subscription.create", "subscription", sub.ID)
	return sub, token, nil
}

func (cp *ControlPlane) ListSubscriptions(ctx RequestContext, tenantID string) ([]Subscription, error) {
	if err := authorize(ctx.User, "subscriptions:read", tenantID); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	subs := make([]Subscription, 0)
	for _, sub := range cp.subscriptions {
		if sub.TenantID == tenantID {
			sub.TokenHash = ""
			subs = append(subs, sub)
		}
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].ID < subs[j].ID })
	return subs, nil
}

func (cp *ControlPlane) RegisterSubscriptionConversion(ctx RequestContext, req SubscriptionConversionRequest) (SubscriptionConversion, error) {
	tenantID := nonEmpty(strings.TrimSpace(req.TenantID), ctx.User.TenantID)
	if err := authorize(ctx.User, "subscriptions:write", tenantID); err != nil {
		return SubscriptionConversion{}, err
	}
	if err := requireScope(ctx, "subscriptions:write"); err != nil {
		return SubscriptionConversion{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return SubscriptionConversion{}, err
	}
	sourceClientType := normalizeSubscriptionClientType(req.SourceClientType)
	if sourceClientType == "" {
		sourceClientType = "sing-box"
	}
	targetClientType := normalizeSubscriptionClientType(req.TargetClientType)
	conversion := SubscriptionConversion{
		ID:               nonEmpty(strings.TrimSpace(req.ID), randomID("subconv")),
		TenantID:         tenantID,
		Name:             sanitizeSubscriptionField(req.Name, 80),
		SourceURL:        normalizeRuleSetSourceURL(req.SourceURL),
		SourceChecksum:   strings.ToLower(strings.TrimSpace(req.SourceChecksum)),
		SourceClientType: sourceClientType,
		TargetClientType: targetClientType,
		DeviceID:         sanitizeSubscriptionField(req.DeviceID, 64),
		Region:           sanitizeSubscriptionField(req.Region, 32),
		Protocol:         normalizeSubscriptionProtocol(req.Protocol),
		OutboundPolicy:   normalizeSubscriptionOutboundPolicy(req.OutboundPolicy),
		Status:           "queued",
		CreatedAt:        cp.now(),
	}
	if conversion.Name == "" {
		conversion.Name = "subscription-conversion"
	}
	if conversion.SourceURL == "" || conversion.TargetClientType == "" || !validSHA256Hex(conversion.SourceChecksum) {
		return SubscriptionConversion{}, fmt.Errorf("%w: subscription conversion requires public HTTPS source URL, sha256 source checksum, and supported target client type", ErrBadRequest)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.subConversions[conversion.ID] = conversion
	cp.auditLocked(ctx, tenantID, "subscription.conversion.create", "subscription_conversion", conversion.ID)
	return conversion, nil
}

func (cp *ControlPlane) ListSubscriptionConversions(ctx RequestContext, tenantID string) ([]SubscriptionConversion, error) {
	if err := authorize(ctx.User, "subscriptions:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "subscriptions:read"); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	conversions := make([]SubscriptionConversion, 0)
	for _, conversion := range cp.subConversions {
		if conversion.TenantID == tenantID {
			conversions = append(conversions, conversion)
		}
	}
	sort.Slice(conversions, func(i, j int) bool { return conversions[i].ID < conversions[j].ID })
	return conversions, nil
}

func (cp *ControlPlane) RevokeSubscription(ctx RequestContext, subscriptionID string) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	sub, ok := cp.subscriptions[subscriptionID]
	if !ok {
		return ErrNotFound
	}
	if err := authorize(ctx.User, "subscriptions:write", sub.TenantID); err != nil {
		return err
	}
	if err := requireScope(ctx, "subscriptions:write"); err != nil {
		return err
	}
	if err := requireConfirmation(ctx); err != nil {
		return err
	}
	sub.Revoked = true
	cp.subscriptions[subscriptionID] = sub
	cp.auditLocked(ctx, sub.TenantID, "subscription.revoke", "subscription", subscriptionID)
	return nil
}

func (cp *ControlPlane) RenderSubscription(token, clientType, ip string) (string, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if err := cp.allowRequestLocked("sub:"+ip, 2000, time.Second); err != nil {
		return "", err
	}
	hash := HashToken(token)
	for _, sub := range cp.subscriptions {
		if sub.TokenHash != hash {
			continue
		}
		if sub.Revoked {
			return "", ErrRevoked
		}
		if !sub.ExpiresAt.IsZero() && cp.now().After(sub.ExpiresAt) {
			return "", ErrRevoked
		}
		if cp.runbookStates[sub.TenantID].SubscriptionEmergencyLimited {
			return "", ErrRateLimited
		}
		if sub.Scope != "" && sub.Scope != "read" {
			return "", ErrForbidden
		}
		if len(sub.IPAllowlist) > 0 && !ipAllowed(ip, sub.IPAllowlist) {
			return "", ErrForbidden
		}
		if sub.TokenKind == "one-time" {
			if sub.UsesRemaining <= 0 {
				sub.Revoked = true
				cp.subscriptions[sub.ID] = sub
				return "", ErrRevoked
			}
			sub.UsesRemaining--
			if sub.UsesRemaining == 0 {
				sub.Revoked = true
			}
		}
		sub.LastAccessedAt = cp.now()
		cp.subscriptions[sub.ID] = sub
		cp.auditLocked(subscriptionAccessContext(sub.TenantID, ip), sub.TenantID, "subscription.access", "subscription", sub.ID)
		return renderClientSubscription(clientType, sub), nil
	}
	return "", ErrNotFound
}

func (cp *ControlPlane) AddWarpProfile(ctx RequestContext, profile WarpProfile) (WarpProfile, error) {
	if err := authorize(ctx.User, "warp:write", profile.TenantID); err != nil {
		return WarpProfile{}, err
	}
	if err := requireScope(ctx, "warp:write"); err != nil {
		return WarpProfile{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return WarpProfile{}, err
	}
	profile.ID = nonEmpty(profile.ID, randomID("warp"))
	profile.Status = nonEmpty(profile.Status, "healthy")
	if err := normalizeWarpProfileSource(&profile); err != nil {
		return WarpProfile{}, err
	}
	if profile.Weight == 0 {
		profile.Weight = 1
	}
	profile.Addresses = copyStrings(profile.Addresses)
	profile.DNS = copyStrings(profile.DNS)
	profile.AllowedIPs = copyStrings(profile.AllowedIPs)
	if profile.EncryptedPrivateKey != "" && !strings.HasPrefix(profile.EncryptedPrivateKey, "enc:") {
		encrypted, err := cp.encryptString(profile.EncryptedPrivateKey)
		if err != nil {
			return WarpProfile{}, err
		}
		profile.EncryptedPrivateKey = encrypted
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.warpProfiles[profile.ID] = profile
	cp.auditLocked(ctx, profile.TenantID, "warp.profile.create", "warp_profile", profile.ID)
	return profile, nil
}

func (cp *ControlPlane) ImportWarpWireGuardProfile(ctx RequestContext, req WarpWireGuardImport) (WarpProfile, error) {
	tenantID := nonEmpty(req.TenantID, ctx.User.TenantID)
	if tenantID == "" {
		return WarpProfile{}, ErrBadRequest
	}
	profile, err := parseWarpWireGuardConfig(req.Config)
	if err != nil {
		return WarpProfile{}, err
	}
	profile.ID = strings.TrimSpace(req.ID)
	profile.TenantID = tenantID
	profile.NodeID = strings.TrimSpace(req.NodeID)
	profile.Name = nonEmpty(strings.TrimSpace(req.Name), "wireguard-"+shortID(profile.PublicKey))
	profile.Source = "standard-wireguard-config"
	profile.LicenseAccepted = true
	profile.Weight = req.Weight
	return cp.AddWarpProfile(ctx, profile)
}

func (cp *ControlPlane) ProbeWarpProfile(profileID string, result WarpProbeResult) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	profile, ok := cp.warpProfiles[profileID]
	if !ok {
		return ErrNotFound
	}
	if result.At.IsZero() {
		result.At = cp.now()
	}
	profile.LastProbe = result
	profile.LastProbeAt = result.At
	if warpProbeHealthy(result) {
		if profile.Status == "cooldown" && !profile.CooldownUntil.IsZero() && result.At.Before(profile.CooldownUntil) {
			cp.warpProfiles[profileID] = profile
			return nil
		}
		profile.Status = "healthy"
		profile.FailedAt = time.Time{}
		profile.RemovedAt = time.Time{}
		profile.CooldownUntil = time.Time{}
	} else {
		profile.Status = "cooldown"
		profile.FailedAt = result.At
		profile.RemovedAt = result.At
		profile.CooldownUntil = result.At.Add(30 * time.Second)
	}
	cp.warpProfiles[profileID] = profile
	return nil
}

func normalizeWarpProfileSource(profile *WarpProfile) error {
	source := strings.ToLower(strings.TrimSpace(profile.Source))
	if source == "" {
		profile.Source = "standard-wireguard-config"
		profile.LicenseAccepted = true
		return nil
	}
	switch source {
	case "standard-wireguard-config", "open-source-tool", "wgcf", "cloudflare-api":
		profile.Source = source
	default:
		return errors.New("unsupported WARP profile source")
	}
	if !profile.LicenseAccepted {
		return errors.New("WARP profile source license must be accepted")
	}
	return nil
}

func parseWarpWireGuardConfig(config string) (WarpProfile, error) {
	if strings.TrimSpace(config) == "" || len(config) > 32*1024 {
		return WarpProfile{}, ErrBadRequest
	}
	section := ""
	interfaceFields := map[string]string{}
	peerFields := map[string]string{}
	for _, rawLine := range strings.Split(config, "\n") {
		line := stripWireGuardComment(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")))
			if section != "interface" && section != "peer" {
				return WarpProfile{}, ErrBadRequest
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return WarpProfile{}, ErrBadRequest
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			return WarpProfile{}, ErrBadRequest
		}
		switch section {
		case "interface":
			switch key {
			case "privatekey", "address", "dns":
				interfaceFields[key] = value
			default:
				return WarpProfile{}, ErrBadRequest
			}
		case "peer":
			switch key {
			case "publickey", "endpoint", "allowedips":
				peerFields[key] = value
			default:
				return WarpProfile{}, ErrBadRequest
			}
		}
	}

	privateKey := interfaceFields["privatekey"]
	peerPublicKey := peerFields["publickey"]
	endpoint := peerFields["endpoint"]
	allowedIPs := peerFields["allowedips"]
	if !safeWireGuardToken(privateKey) || !safeWireGuardToken(peerPublicKey) || endpoint == "" || allowedIPs == "" {
		return WarpProfile{}, ErrBadRequest
	}
	endpoint, err := normalizeWireGuardEndpoint(endpoint)
	if err != nil {
		return WarpProfile{}, err
	}
	addresses, err := normalizeCIDRList(interfaceFields["address"], true)
	if err != nil {
		return WarpProfile{}, err
	}
	allowed, err := normalizeCIDRList(allowedIPs, false)
	if err != nil {
		return WarpProfile{}, err
	}
	dns, err := normalizeWireGuardDNS(interfaceFields["dns"])
	if err != nil {
		return WarpProfile{}, err
	}

	return WarpProfile{
		Source:              "standard-wireguard-config",
		LicenseAccepted:     true,
		PublicKey:           peerPublicKey,
		PeerPublicKey:       peerPublicKey,
		Endpoint:            endpoint,
		Addresses:           addresses,
		DNS:                 dns,
		AllowedIPs:          allowed,
		EncryptedPrivateKey: privateKey,
		Status:              "healthy",
	}, nil
}

func stripWireGuardComment(line string) string {
	line = strings.TrimSpace(line)
	for _, marker := range []string{"#", ";"} {
		if idx := strings.Index(line, marker); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
	}
	return line
}

func safeWireGuardToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func normalizeWireGuardEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", ErrBadRequest
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", ErrBadRequest
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.ContainsAny(host, "/\\@?&=#") || host == "." || strings.Contains(host, "..") {
		return "", ErrBadRequest
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func normalizeCIDRList(value string, allowEmpty bool) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		if allowEmpty {
			return nil, nil
		}
		return nil, ErrBadRequest
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, ErrBadRequest
		}
		_, network, err := net.ParseCIDR(part)
		if err != nil {
			return nil, ErrBadRequest
		}
		normalized := network.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}

func normalizeWireGuardDNS(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, ErrBadRequest
		}
		normalized := ip.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}

func shortID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:4])
}

func warpProbeHealthy(result WarpProbeResult) bool {
	dnsOK := result.DNSStatus == "" || strings.EqualFold(result.DNSStatus, "ok")
	wireGuardOK := result.WireGuardStatus == "" || strings.EqualFold(result.WireGuardStatus, "ok")
	return dnsOK && wireGuardOK && result.HTTPSuccess && result.Loss < 0.20
}

func (cp *ControlPlane) ListWarpProfiles(ctx RequestContext, tenantID string) ([]WarpProfile, error) {
	if err := authorize(ctx.User, "warp:read", tenantID); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	profiles := make([]WarpProfile, 0)
	for _, profile := range cp.warpProfiles {
		if profile.TenantID == tenantID {
			profiles = append(profiles, redactWarpProfile(profile))
		}
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	return profiles, nil
}

func redactWarpProfile(profile WarpProfile) WarpProfile {
	profile.EncryptedPrivateKey = ""
	profile.Addresses = copyStrings(profile.Addresses)
	profile.DNS = copyStrings(profile.DNS)
	profile.AllowedIPs = copyStrings(profile.AllowedIPs)
	return profile
}

func (cp *ControlPlane) DisableWarpProfile(ctx RequestContext, profileID string) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	profile, ok := cp.warpProfiles[profileID]
	if !ok {
		return ErrNotFound
	}
	if err := authorize(ctx.User, "warp:write", profile.TenantID); err != nil {
		return err
	}
	if err := requireScope(ctx, "warp:write"); err != nil {
		return err
	}
	if err := requireConfirmation(ctx); err != nil {
		return err
	}
	profile.Status = "disabled"
	cp.warpProfiles[profileID] = profile
	cp.auditLocked(ctx, profile.TenantID, "warp.profile.disable", "warp_profile", profileID)
	return nil
}

func (cp *ControlPlane) RegisterArgoTunnel(ctx RequestContext, tunnel ArgoTunnel) (ArgoTunnel, error) {
	if err := authorize(ctx.User, "argo:write", tunnel.TenantID); err != nil {
		return ArgoTunnel{}, err
	}
	if err := requireScope(ctx, "argo:write"); err != nil {
		return ArgoTunnel{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return ArgoTunnel{}, err
	}
	if err := normalizeArgoTunnel(&tunnel); err != nil {
		return ArgoTunnel{}, err
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	tunnel.ID = nonEmpty(tunnel.ID, randomID("argo"))
	tunnel.Status = nonEmpty(tunnel.Status, "configured")
	tunnel.CreatedAt = nonZeroTime(tunnel.CreatedAt, cp.now())
	cp.argoTunnels[tunnel.ID] = tunnel
	cp.auditLocked(ctx, tunnel.TenantID, "argo.tunnel.create", "argo_tunnel", tunnel.ID)
	return tunnel, nil
}

func (cp *ControlPlane) BuildCloudflareArgoAutomationPlan(ctx RequestContext, req CloudflareArgoAutomationRequest) (CloudflareArgoAutomationPlan, error) {
	tunnel := ArgoTunnel{
		ID:                  req.ID,
		TenantID:            req.TenantID,
		Name:                req.Name,
		Hostname:            req.Hostname,
		ServiceURL:          req.ServiceURL,
		CloudflareAccountID: req.CloudflareAccountID,
		CloudflareZoneID:    req.CloudflareZoneID,
		TunnelID:            req.TunnelID,
	}
	if err := authorize(ctx.User, "argo:write", tunnel.TenantID); err != nil {
		return CloudflareArgoAutomationPlan{}, err
	}
	if err := requireScope(ctx, "argo:write"); err != nil {
		return CloudflareArgoAutomationPlan{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return CloudflareArgoAutomationPlan{}, err
	}
	if err := normalizeArgoTunnelForMode(&tunnel, false); err != nil {
		return CloudflareArgoAutomationPlan{}, err
	}
	tunnel.CloudflareAccountID = normalizeCloudflareResourceID(tunnel.CloudflareAccountID)
	tunnel.CloudflareZoneID = normalizeCloudflareResourceID(tunnel.CloudflareZoneID)
	if tunnel.CloudflareAccountID == "" || tunnel.CloudflareZoneID == "" {
		return CloudflareArgoAutomationPlan{}, fmt.Errorf("%w: Cloudflare account and zone IDs must be 32-character hex IDs", ErrBadRequest)
	}
	tunnelID := normalizeCloudflareTunnelReference(tunnel.TunnelID)
	if tunnel.TunnelID != "" && tunnelID == "" {
		return CloudflareArgoAutomationPlan{}, fmt.Errorf("%w: invalid Cloudflare tunnel ID", ErrBadRequest)
	}
	if tunnelID == "" {
		tunnelID = "${TUNNEL_ID}"
	}

	now := cp.now()
	tunnel.ID = nonEmpty(tunnel.ID, randomID("argo-cf"))
	tunnel.Status = "cloudflare-api-planned"
	tunnel.CreatedAt = now
	baseAccountURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/cfd_tunnel", tunnel.CloudflareAccountID)
	configurationURL := fmt.Sprintf("%s/%s/configurations", baseAccountURL, tunnelID)
	dnsURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", tunnel.CloudflareZoneID)
	plan := CloudflareArgoAutomationPlan{
		Tunnel: tunnel,
		Operations: []CloudflareAPIOperation{
			{
				Name:   "create-cloudflared-tunnel",
				Method: "POST",
				URL:    baseAccountURL,
				Body: map[string]any{
					"name":       tunnel.Name,
					"config_src": "cloudflare",
				},
			},
			{
				Name:   "configure-cloudflared-ingress",
				Method: "PUT",
				URL:    configurationURL,
				Body: map[string]any{
					"config": map[string]any{
						"ingress": []map[string]any{
							{
								"hostname": tunnel.Hostname,
								"service":  tunnel.ServiceURL,
							},
							{
								"service": "http_status:404",
							},
						},
					},
				},
			},
			{
				Name:   "create-cloudflare-dns-cname",
				Method: "POST",
				URL:    dnsURL,
				Body: map[string]any{
					"type":    "CNAME",
					"name":    tunnel.Hostname,
					"content": fmt.Sprintf("%s.cfargotunnel.com", tunnelID),
					"proxied": true,
				},
			},
		},
		TokenHandling:  "Cloudflare API token must be injected by the execution environment and must never be stored or returned by the control plane.",
		RequiredScopes: []string{"argo:write"},
		RequiredAPIToken: CloudflareAPITokenRequirement{
			Storage: "external-executor-only",
			Scopes:  []string{"Account.Cloudflare Tunnel:Edit", "Zone.DNS:Edit"},
		},
		GeneratedAt: now,
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.auditLocked(ctx, tunnel.TenantID, "argo.cloudflare.plan", "argo_tunnel", tunnel.ID)
	return plan, nil
}

func (cp *ControlPlane) ListArgoTunnels(ctx RequestContext, tenantID string) ([]ArgoTunnel, error) {
	if err := authorize(ctx.User, "argo:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "argo:read"); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	tunnels := make([]ArgoTunnel, 0)
	for _, tunnel := range cp.argoTunnels {
		if tunnel.TenantID == tenantID {
			tunnels = append(tunnels, tunnel)
		}
	}
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].ID < tunnels[j].ID })
	return tunnels, nil
}

func (cp *ControlPlane) RenderArgoTunnelConfig(ctx RequestContext, tunnelID string) (string, error) {
	cp.mu.RLock()
	tunnel, ok := cp.argoTunnels[tunnelID]
	cp.mu.RUnlock()
	if !ok {
		return "", ErrNotFound
	}
	if err := authorize(ctx.User, "argo:read", tunnel.TenantID); err != nil {
		return "", err
	}
	if err := requireScope(ctx, "argo:read"); err != nil {
		return "", err
	}
	return renderArgoTunnelConfig(tunnel), nil
}

func normalizeArgoTunnel(tunnel *ArgoTunnel) error {
	return normalizeArgoTunnelForMode(tunnel, true)
}

func normalizeArgoTunnelForMode(tunnel *ArgoTunnel, requireTunnelID bool) error {
	tunnel.TenantID = strings.TrimSpace(tunnel.TenantID)
	tunnel.Name = sanitizeSubscriptionField(tunnel.Name, 80)
	tunnel.Hostname = normalizeArgoHostname(tunnel.Hostname)
	tunnel.ServiceURL = normalizeArgoServiceURL(tunnel.ServiceURL)
	tunnel.CloudflareAccountID = sanitizeSubscriptionField(tunnel.CloudflareAccountID, 80)
	tunnel.CloudflareZoneID = sanitizeSubscriptionField(tunnel.CloudflareZoneID, 80)
	tunnel.TunnelID = sanitizeSubscriptionField(tunnel.TunnelID, 80)
	if tunnel.TenantID == "" || tunnel.Hostname == "" || tunnel.ServiceURL == "" || requireTunnelID && tunnel.TunnelID == "" {
		return fmt.Errorf("%w: Argo tunnel requires tenant, hostname, service URL, and tunnel ID", ErrBadRequest)
	}
	if tunnel.Name == "" {
		tunnel.Name = tunnel.Hostname
	}
	return nil
}

func normalizeCloudflareResourceID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 32 {
		return ""
	}
	for _, r := range value {
		if r >= 'a' && r <= 'f' || r >= '0' && r <= '9' {
			continue
		}
		return ""
	}
	return value
}

func normalizeCloudflareTunnelReference(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) > 80 {
		return ""
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			continue
		}
		return ""
	}
	return value
}

func normalizeArgoHostname(hostname string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" || strings.ContainsAny(hostname, `/\:`) || !strings.Contains(hostname, ".") {
		return ""
	}
	parts := strings.Split(hostname, ".")
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return ""
		}
		for _, r := range part {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return ""
		}
	}
	return hostname
}

func normalizeArgoServiceURL(serviceURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(serviceURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func renderArgoTunnelConfig(tunnel ArgoTunnel) string {
	return fmt.Sprintf("tunnel: %s\ncredentials-file: /etc/cloudflared/%s.json\ningress:\n  - hostname: %s\n    service: %s\n  - service: http_status:404\n", tunnel.TunnelID, tunnel.TunnelID, tunnel.Hostname, tunnel.ServiceURL)
}

func (cp *ControlPlane) SelectWarp(site, userID string, mode ScheduleMode) ScheduleDecision {
	if isGoogleScholar(site) {
		return ScheduleDecision{Outbound: string(rulecompiler.OutboundProxy), Reason: "warp-exclude-google-scholar"}
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if mode == "" {
		mode = ScheduleStable
	}
	stickyKey := strings.ToLower(site)
	if selectedID, ok := cp.stickyByDomain[stickyKey]; ok && (mode == ScheduleStable || mode == SchedulePerformance || mode == ScheduleStickyByDomain) {
		if profile, ok := cp.warpProfiles[selectedID]; ok && profile.Status == "healthy" {
			return ScheduleDecision{Outbound: profile.Name, Reason: "sticky-by-domain", Score: scoreProfile(profile, mode)}
		}
	}
	userStickyKey := strings.TrimSpace(userID)
	if userStickyKey != "" && mode == ScheduleStickyByUser {
		if selectedID, ok := cp.stickyByUser[userStickyKey]; ok {
			if profile, ok := cp.warpProfiles[selectedID]; ok && profile.Status == "healthy" {
				return ScheduleDecision{Outbound: profile.Name, Reason: "sticky-by-user", Score: scoreProfile(profile, mode)}
			}
		}
	}

	profiles := cp.healthyWarpProfilesLocked()
	if len(profiles) == 0 {
		return ScheduleDecision{Outbound: string(rulecompiler.OutboundProxy), Reason: "warp-pool-empty"}
	}
	var best WarpProfile
	var bestScore float64
	switch mode {
	case ScheduleWeightedRoundRobin:
		best = cp.weightedRoundRobinLocked(profiles)
		bestScore = scoreProfile(best, mode)
	case ScheduleLeastLatency:
		best, bestScore = bestProfileByScore(profiles, func(profile WarpProfile) float64 {
			return profile.LastProbe.LatencyMs
		})
	case ScheduleLeastError:
		best, bestScore = bestProfileByScore(profiles, func(profile WarpProfile) float64 {
			return profile.LastProbe.Loss*1000 + boolPenalty(!profile.LastProbe.HTTPSuccess)*100 + float64(profile.LastProbe.RecentFailures)
		})
	default:
		best, bestScore = bestProfileByScore(profiles, func(profile WarpProfile) float64 {
			return scoreProfile(profile, mode)
		})
	}
	if mode == ScheduleStable || mode == SchedulePerformance || mode == ScheduleStickyByDomain {
		cp.stickyByDomain[stickyKey] = best.ID
	}
	if userStickyKey != "" && mode == ScheduleStickyByUser {
		cp.stickyByUser[userStickyKey] = best.ID
	}
	return ScheduleDecision{Outbound: best.Name, Reason: string(mode), Score: bestScore}
}

func (cp *ControlPlane) healthyWarpProfilesLocked() []WarpProfile {
	profiles := make([]WarpProfile, 0, len(cp.warpProfiles))
	for _, profile := range cp.warpProfiles {
		if profile.Status == "healthy" {
			profiles = append(profiles, profile)
		}
	}
	sort.SliceStable(profiles, func(i, j int) bool {
		return profiles[i].ID < profiles[j].ID
	})
	return profiles
}

func bestProfileByScore(profiles []WarpProfile, scoreFn func(WarpProfile) float64) (WarpProfile, float64) {
	best := profiles[0]
	bestScore := scoreFn(best)
	for _, profile := range profiles[1:] {
		score := scoreFn(profile)
		if score < bestScore {
			best = profile
			bestScore = score
		}
	}
	return best, bestScore
}

func (cp *ControlPlane) weightedRoundRobinLocked(profiles []WarpProfile) WarpProfile {
	totalWeight := 0
	for _, profile := range profiles {
		totalWeight += profileWeightSlots(profile.Weight)
	}
	if totalWeight <= 0 {
		return profiles[0]
	}
	cursor := cp.weightedCursor["warp"]
	slot := cursor % totalWeight
	cp.weightedCursor["warp"] = cursor + 1
	for _, profile := range profiles {
		weight := profileWeightSlots(profile.Weight)
		if slot < weight {
			return profile
		}
		slot -= weight
	}
	return profiles[len(profiles)-1]
}

func profileWeightSlots(weight float64) int {
	if weight < 1 {
		return 1
	}
	return int(weight)
}

func (cp *ControlPlane) TestDomain(input string) rulecompiler.Classification {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.rulePolicy.Classify(input)
}

func (cp *ControlPlane) TraceRouteDecision(ctx RequestContext, tenantID string, req RouteTraceRequest) (RouteDecisionTrace, error) {
	if err := authorize(ctx.User, "rules:read", tenantID); err != nil {
		return RouteDecisionTrace{}, err
	}
	if err := requireScope(ctx, "rules:read"); err != nil {
		return RouteDecisionTrace{}, err
	}
	input := sanitizeRouteTraceInput(req.Input)
	if input == "" {
		return RouteDecisionTrace{}, errors.New("route trace input is required")
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	classification := cp.rulePolicy.Classify(req.Input)
	trace := RouteDecisionTrace{
		ID:              randomID("route"),
		TenantID:        tenantID,
		ActorID:         ctx.User.ID,
		Input:           input,
		Protocol:        strings.ToLower(strings.TrimSpace(req.Protocol)),
		ClientIP:        strings.TrimSpace(req.ClientIP),
		NodeID:          strings.TrimSpace(req.NodeID),
		Outbound:        classification.Outbound,
		Reason:          classification.Reason,
		RuleID:          classification.RuleID,
		MatchedRule:     classification.MatchedRule,
		MatchedSource:   classification.MatchedSource,
		MatchedRuleType: classification.MatchedRuleTyp,
		Decision:        routeDecisionText(classification),
		CreatedAt:       cp.now(),
	}
	cp.routeTraces = append(cp.routeTraces, trace)
	if len(cp.routeTraces) > routeTraceLimit {
		cp.routeTraces = cp.routeTraces[len(cp.routeTraces)-routeTraceLimit:]
	}
	cp.auditLocked(ctx, tenantID, "route.trace", "route_decision", trace.ID)
	return trace, nil
}

func (cp *ControlPlane) RouteDecisionTraces(ctx RequestContext, tenantID string, limit int) ([]RouteDecisionTrace, error) {
	if err := authorize(ctx.User, "logs:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "logs:read"); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	traces := make([]RouteDecisionTrace, 0, limit)
	for i := len(cp.routeTraces) - 1; i >= 0 && len(traces) < limit; i-- {
		trace := cp.routeTraces[i]
		if trace.TenantID == tenantID {
			traces = append(traces, trace)
		}
	}
	return traces, nil
}

func (cp *ControlPlane) PublishRules(ctx RequestContext, tenantID string, opts rulecompiler.CompileOptions) (rulecompiler.DiffReport, error) {
	cp.rulePublishMu.Lock()
	defer cp.rulePublishMu.Unlock()
	if err := authorize(ctx.User, "rules:write", tenantID); err != nil {
		return rulecompiler.DiffReport{}, err
	}
	if err := requireScope(ctx, "rules:write"); err != nil {
		return rulecompiler.DiffReport{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return rulecompiler.DiffReport{}, err
	}
	rollout, err := normalizeRuleRolloutPercent(opts.RolloutPercent)
	if err != nil {
		return rulecompiler.DiffReport{}, err
	}
	next, err := rulecompiler.Compile(opts)
	if err != nil {
		return rulecompiler.DiffReport{}, err
	}
	cp.mu.RLock()
	if cp.runbookStates[tenantID].ReleasePaused {
		cp.mu.RUnlock()
		return rulecompiler.DiffReport{}, ErrReleasePaused
	}
	oldRules := cp.rulePolicy.Rules()
	cp.mu.RUnlock()
	report := rulecompiler.Diff(oldRules, next.Rules())
	report.Coverage = rulecompiler.AnalyzeCoverage(next, rulecompiler.CoverageSamplesForRules(next.Rules()))
	report.RolloutPercent = rollout
	if len(report.Conflicts) > 0 {
		return report, errors.New("rule conflict")
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.runbookStates[tenantID].ReleasePaused {
		return rulecompiler.DiffReport{}, ErrReleasePaused
	}
	cp.rulePolicy = next
	cp.ruleRolloutByT[tenantID] = rollout
	cp.auditLocked(ctx, tenantID, "rules.publish", "rules", "active")
	return report, nil
}

func (cp *ControlPlane) CurrentRuleRollout(tenantID string) int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	if rollout := cp.ruleRolloutByT[tenantID]; rollout != 0 {
		return rollout
	}
	return 100
}

func (cp *ControlPlane) RegisterRuleSetSource(ctx RequestContext, source RuleSetSource) (RuleSetSource, error) {
	if err := authorize(ctx.User, "rules:write", source.TenantID); err != nil {
		return RuleSetSource{}, err
	}
	if err := requireScope(ctx, "rules:write"); err != nil {
		return RuleSetSource{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return RuleSetSource{}, err
	}
	if err := normalizeRuleSetSource(&source); err != nil {
		return RuleSetSource{}, err
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	source.ID = nonEmpty(source.ID, randomID("ruleset"))
	source.UpdatedAt = nonZeroTime(source.UpdatedAt, cp.now())
	cp.ruleSetSources[source.ID] = source
	cp.auditLocked(ctx, source.TenantID, "ruleset.source.register", "rule_set", source.ID)
	return source, nil
}

func (cp *ControlPlane) ListRuleSetSources(ctx RequestContext, tenantID string) ([]RuleSetSource, error) {
	if err := authorize(ctx.User, "rules:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "rules:read"); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	sources := make([]RuleSetSource, 0)
	for _, source := range cp.ruleSetSources {
		if source.TenantID == tenantID {
			sources = append(sources, source)
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	return sources, nil
}

func (cp *ControlPlane) RegisterWebhookEndpoint(ctx RequestContext, req WebhookEndpointRegistration) (WebhookEndpoint, error) {
	tenantID := nonEmpty(strings.TrimSpace(req.TenantID), ctx.User.TenantID)
	if err := authorize(ctx.User, "webhooks:write", tenantID); err != nil {
		return WebhookEndpoint{}, err
	}
	if err := requireScope(ctx, "webhooks:write"); err != nil {
		return WebhookEndpoint{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return WebhookEndpoint{}, err
	}
	eventTypes, err := normalizeWebhookEventTypes(req.EventTypes)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	now := cp.now()
	endpoint := WebhookEndpoint{
		ID:         nonEmpty(strings.TrimSpace(req.ID), randomID("webhook")),
		TenantID:   tenantID,
		Name:       sanitizeSubscriptionField(req.Name, 80),
		TargetURL:  normalizeRuleSetSourceURL(req.TargetURL),
		EventTypes: eventTypes,
		Status:     "active",
		CreatedAt:  now,
	}
	if endpoint.Name == "" || endpoint.TargetURL == "" || len(endpoint.EventTypes) == 0 {
		return WebhookEndpoint{}, ErrBadRequest
	}
	if secret := strings.TrimSpace(req.SigningSecret); secret != "" {
		if len(secret) < 16 {
			return WebhookEndpoint{}, fmt.Errorf("%w: webhook signing secret must be at least 16 bytes", ErrBadRequest)
		}
		endpoint.SigningSecretHash = HashWebhookSecret(secret)
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.webhookEndpoints[endpoint.ID] = endpoint
	cp.auditLocked(ctx, tenantID, "webhook.endpoint.create", "webhook_endpoint", endpoint.ID)
	return endpoint, nil
}

func (cp *ControlPlane) ListWebhookEndpoints(ctx RequestContext, tenantID string) ([]WebhookEndpoint, error) {
	if err := authorize(ctx.User, "webhooks:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "webhooks:read"); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	endpoints := make([]WebhookEndpoint, 0)
	for _, endpoint := range cp.webhookEndpoints {
		if endpoint.TenantID == tenantID {
			endpoint.SigningSecretHash = ""
			endpoint.EventTypes = copyStrings(endpoint.EventTypes)
			endpoints = append(endpoints, endpoint)
		}
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ID < endpoints[j].ID })
	return endpoints, nil
}

func normalizeWebhookEventTypes(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 20 {
		return nil, ErrBadRequest
	}
	seen := map[string]struct{}{}
	events := make([]string, 0, len(values))
	for _, value := range values {
		event := strings.ToLower(strings.TrimSpace(value))
		if event == "" || len(event) > 64 {
			return nil, ErrBadRequest
		}
		for _, r := range event {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == ':' || r == '_' || r == '-' {
				continue
			}
			return nil, ErrBadRequest
		}
		if _, ok := seen[event]; ok {
			continue
		}
		seen[event] = struct{}{}
		events = append(events, event)
	}
	sort.Strings(events)
	return events, nil
}

func normalizeRuleSetSource(source *RuleSetSource) error {
	source.TenantID = strings.TrimSpace(source.TenantID)
	source.Name = sanitizeSubscriptionField(source.Name, 80)
	source.SourceURL = normalizeRuleSetSourceURL(source.SourceURL)
	source.Checksum = strings.ToLower(strings.TrimSpace(source.Checksum))
	if source.TenantID == "" || source.Name == "" || source.SourceURL == "" {
		return fmt.Errorf("%w: rule set source requires tenant, name, and public HTTPS source URL", ErrBadRequest)
	}
	if !validSHA256Hex(source.Checksum) {
		return fmt.Errorf("%w: rule set source checksum must be sha256 hex", ErrBadRequest)
	}
	return nil
}

func HashWebhookSecret(secret string) string {
	sum := sha256.Sum256([]byte("webhook-secret-v1:" + secret))
	return hex.EncodeToString(sum[:])
}

func normalizeRuleSetSourceURL(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return ""
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || isBlockedRuleSetHost(host) {
		return ""
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return ""
	}
	parsed.Scheme = "https"
	parsed.Host = host
	if parsed.Port() == "443" {
		parsed.Host = host + ":443"
	}
	return parsed.String()
}

func isBlockedRuleSetHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
	}
	if !strings.Contains(host, ".") {
		return true
	}
	parts := strings.Split(host, ".")
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return true
		}
		for _, r := range part {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return true
		}
	}
	return false
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (cp *ControlPlane) SetDependencyHealth(ctx RequestContext, name DependencyName, state DependencyState, message string) (DependencyHealth, error) {
	if err := authorize(ctx.User, "metrics:write", ctx.User.TenantID); err != nil {
		return DependencyHealth{}, err
	}
	if err := requireScope(ctx, "metrics:write"); err != nil {
		return DependencyHealth{}, err
	}
	if dependencyRecoveryTargetSeconds(name) == 0 {
		return DependencyHealth{}, errors.New("unknown dependency")
	}
	switch state {
	case DependencyHealthy, DependencyDegraded, DependencyUnavailable:
	default:
		return DependencyHealth{}, errors.New("unknown dependency state")
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()
	now := cp.now()
	prev := cp.dependencies[name]
	next := prev
	next.Name = name
	next.State = state
	next.Message = SanitizeLog(message)
	next.RecoveryTargetSeconds = dependencyRecoveryTargetSeconds(name)
	next.LastChangedAt = now
	if state == DependencyHealthy {
		next.FailureStartedAt = time.Time{}
		next.RecoveryDeadlineAt = time.Time{}
		next.RecoveredAt = now
		next.CoreAPIsAvailable = true
	} else {
		if prev.State == DependencyHealthy || prev.FailureStartedAt.IsZero() {
			next.FailureStartedAt = now
		}
		next.RecoveredAt = time.Time{}
		next.RecoveryDeadlineAt = next.FailureStartedAt.Add(time.Duration(next.RecoveryTargetSeconds) * time.Second)
		next.CoreAPIsAvailable = dependencyCoreAPIsAvailable(next, now)
	}
	cp.dependencies[name] = next
	cp.auditLocked(ctx, ctx.User.TenantID, "dependency."+string(state), "dependency", string(name))
	return next, nil
}

func (cp *ControlPlane) Dependencies(ctx RequestContext, tenantID string) ([]DependencyHealth, error) {
	if err := authorize(ctx.User, "metrics:read", tenantID); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.dependencySnapshotLocked(cp.now()), nil
}

func (cp *ControlPlane) CoreAPIAvailability(ctx RequestContext, tenantID string) (CoreAPIAvailability, error) {
	if err := authorize(ctx.User, "metrics:read", tenantID); err != nil {
		return CoreAPIAvailability{}, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.coreAPIAvailabilityLocked(cp.now()), nil
}

func (cp *ControlPlane) RecordNodeMetric(ctx RequestContext, sample NodeMetricSample) (NodeMetricSample, error) {
	sample.NodeID = strings.TrimSpace(sample.NodeID)
	if sample.NodeID == "" {
		return NodeMetricSample{}, ErrBadRequest
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()
	node, ok := cp.nodes[sample.NodeID]
	if !ok {
		return NodeMetricSample{}, ErrNotFound
	}
	if sample.TenantID != "" && sample.TenantID != node.TenantID {
		return NodeMetricSample{}, ErrBadRequest
	}
	if err := authorize(ctx.User, "metrics:write", node.TenantID); err != nil {
		return NodeMetricSample{}, err
	}
	if err := requireScope(ctx, "metrics:write"); err != nil {
		return NodeMetricSample{}, err
	}
	if err := authorizeNodeABAC(ctx, node); err != nil {
		return NodeMetricSample{}, err
	}
	sample.TenantID = node.TenantID
	if sample.At.IsZero() {
		sample.At = cp.now()
	}
	return cp.recordNodeMetricLocked(sample), nil
}

func (cp *ControlPlane) QueryNodeMetrics(ctx RequestContext, tenantID, nodeID string, limit int) ([]NodeMetricSample, error) {
	if err := authorize(ctx.User, "metrics:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "metrics:read"); err != nil {
		return nil, err
	}
	nodeID = strings.TrimSpace(nodeID)
	if limit <= 0 {
		limit = nodeMetricQueryDefaultLimit
	}
	if limit > nodeMetricQueryMaxLimit {
		limit = nodeMetricQueryMaxLimit
	}

	cp.mu.RLock()
	defer cp.mu.RUnlock()
	if nodeID != "" {
		node, ok := cp.nodes[nodeID]
		if !ok {
			return nil, ErrNotFound
		}
		if node.TenantID != tenantID {
			return nil, ErrForbidden
		}
		if err := authorizeNodeABAC(ctx, node); err != nil {
			return nil, err
		}
	}

	samples := make([]NodeMetricSample, 0, limit)
	for i := len(cp.nodeMetricSamples) - 1; i >= 0 && len(samples) < limit; i-- {
		sample := cp.nodeMetricSamples[i]
		if sample.TenantID != tenantID {
			continue
		}
		if nodeID != "" {
			if sample.NodeID != nodeID {
				continue
			}
		} else {
			node, ok := cp.nodes[sample.NodeID]
			if !ok {
				continue
			}
			if err := authorizeNodeABAC(ctx, node); err != nil {
				continue
			}
		}
		samples = append(samples, sample)
	}
	for i, j := 0, len(samples)-1; i < j; i, j = i+1, j-1 {
		samples[i], samples[j] = samples[j], samples[i]
	}
	return samples, nil
}

func (cp *ControlPlane) ProtocolStats(ctx RequestContext, tenantID string) ([]ProtocolInboundStat, error) {
	if err := authorize(ctx.User, "metrics:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "metrics:read"); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	totals := map[string]ProtocolInboundStat{}
	for _, node := range cp.nodes {
		if node.TenantID != tenantID {
			continue
		}
		if err := authorizeNodeABAC(ctx, node); err != nil {
			continue
		}
		for _, stat := range node.ProtocolStats {
			addProtocolStat(totals, stat)
		}
	}
	return orderedProtocolStats(totals), nil
}

func (cp *ControlPlane) recordNodeMetricLocked(sample NodeMetricSample) NodeMetricSample {
	sample = normalizeNodeMetricSample(sample)
	cp.nodeMetricSamples = append(cp.nodeMetricSamples, sample)
	if len(cp.nodeMetricSamples) > nodeMetricSampleLimit {
		excess := len(cp.nodeMetricSamples) - nodeMetricSampleLimit
		cp.nodeMetricSamples = append([]NodeMetricSample(nil), cp.nodeMetricSamples[excess:]...)
	}
	return sample
}

func (cp *ControlPlane) latestNodeMetricsLocked(tenantID string, allowedNodeIDs map[string]struct{}) map[string]NodeMetricSample {
	latest := map[string]NodeMetricSample{}
	for i := len(cp.nodeMetricSamples) - 1; i >= 0; i-- {
		sample := cp.nodeMetricSamples[i]
		if sample.TenantID != tenantID {
			continue
		}
		if _, ok := allowedNodeIDs[sample.NodeID]; !ok {
			continue
		}
		if _, exists := latest[sample.NodeID]; exists {
			continue
		}
		latest[sample.NodeID] = sample
		if len(latest) == len(allowedNodeIDs) {
			break
		}
	}
	return latest
}

func normalizeNodeMetricSample(sample NodeMetricSample) NodeMetricSample {
	sample.NodeID = strings.TrimSpace(sample.NodeID)
	sample.TenantID = strings.TrimSpace(sample.TenantID)
	sample.CPU = normalizeRatio(sample.CPU)
	sample.Memory = normalizeRatio(sample.Memory)
	sample.LoadAvg = normalizeNonNegativeFloat(sample.LoadAvg)
	sample.Disk = normalizeRatio(sample.Disk)
	sample.FDUsage = normalizeRatio(sample.FDUsage)
	sample.RxBps = normalizeNonNegativeInt64(sample.RxBps)
	sample.TxBps = normalizeNonNegativeInt64(sample.TxBps)
	sample.RxBytes = normalizeNonNegativeInt64(sample.RxBytes)
	sample.TxBytes = normalizeNonNegativeInt64(sample.TxBytes)
	sample.NetworkPPS = normalizeNonNegativeFloat(sample.NetworkPPS)
	if sample.Connections < 0 {
		sample.Connections = 0
	}
	return sample
}

func normalizeRatio(value float64) float64 {
	value = normalizeNonNegativeFloat(value)
	if value > 1 {
		return 1
	}
	return value
}

func normalizeNonNegativeFloat(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0
	}
	return value
}

func normalizeNonNegativeInt64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func normalizeNonNegativeInt(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func retainOrUpdateNonNegative(current, next int) int {
	if next < 0 {
		return current
	}
	if next == 0 {
		return current
	}
	return next
}

func normalizeProtocolStats(stats []ProtocolInboundStat) []ProtocolInboundStat {
	totals := map[string]ProtocolInboundStat{}
	for _, stat := range stats {
		addProtocolStat(totals, stat)
	}
	return orderedProtocolStats(totals)
}

func addProtocolStat(totals map[string]ProtocolInboundStat, stat ProtocolInboundStat) {
	protocol := normalizeInboundProtocol(stat.Protocol)
	if protocol == "" {
		return
	}
	current := totals[protocol]
	current.Protocol = protocol
	if stat.Connections > 0 {
		current.Connections += stat.Connections
	}
	current.RxBps += normalizeNonNegativeInt64(stat.RxBps)
	current.TxBps += normalizeNonNegativeInt64(stat.TxBps)
	if stat.Errors > 0 {
		current.Errors += stat.Errors
	}
	totals[protocol] = current
}

func orderedProtocolStats(totals map[string]ProtocolInboundStat) []ProtocolInboundStat {
	order := []string{"vless", "vmess", "hysteria2", "tuic", "trojan"}
	stats := make([]ProtocolInboundStat, 0, len(totals))
	for _, protocol := range order {
		if stat, ok := totals[protocol]; ok {
			stats = append(stats, stat)
		}
	}
	return stats
}

func normalizeInboundProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vless":
		return "vless"
	case "vmess":
		return "vmess"
	case "hysteria2", "hy2":
		return "hysteria2"
	case "tuic":
		return "tuic"
	case "trojan":
		return "trojan"
	default:
		return ""
	}
}

func kernelTuningStatus(node Node) NodeKernelTuning {
	row := NodeKernelTuning{
		NodeID:            node.ID,
		TenantID:          node.TenantID,
		Region:            node.Region,
		CongestionControl: strings.ToLower(strings.TrimSpace(node.CongestionControl)),
		QueueDiscipline:   strings.ToLower(strings.TrimSpace(node.QueueDiscipline)),
		NoFile:            normalizeNonNegativeInt(node.NoFile),
		SomaxConn:         normalizeNonNegativeInt(node.SomaxConn),
		TCPFastOpen:       normalizeNonNegativeInt(node.TCPFastOpen),
		PortRangeStart:    normalizeNonNegativeInt(node.PortRangeStart),
		PortRangeEnd:      normalizeNonNegativeInt(node.PortRangeEnd),
	}
	if row.CongestionControl != "bbr" && row.CongestionControl != "bbr2" {
		row.Issues = append(row.Issues, "congestion_control_not_bbr")
	}
	if row.QueueDiscipline == "" {
		row.Issues = append(row.Issues, "queue_discipline_missing")
	}
	if row.NoFile < 1_048_576 {
		row.Issues = append(row.Issues, "nofile_below_target")
	}
	if row.SomaxConn < 4096 {
		row.Issues = append(row.Issues, "somaxconn_below_target")
	}
	if row.TCPFastOpen <= 0 {
		row.Issues = append(row.Issues, "tcp_fastopen_disabled")
	}
	if row.PortRangeStart == 0 || row.PortRangeEnd == 0 || row.PortRangeStart > row.PortRangeEnd || row.PortRangeStart > 10000 || row.PortRangeEnd < 65000 {
		row.Issues = append(row.Issues, "port_range_narrow")
	}
	row.Tuned = len(row.Issues) == 0
	row.Issues = copyStrings(row.Issues)
	return row
}

func (cp *ControlPlane) dependencySnapshotLocked(now time.Time) []DependencyHealth {
	dependencies := make([]DependencyHealth, 0, len(cp.dependencies))
	for _, dependency := range cp.dependencies {
		dependencies = append(dependencies, dependencyWithRuntimeState(dependency, now))
	}
	sort.Slice(dependencies, func(i, j int) bool {
		return dependencies[i].Name < dependencies[j].Name
	})
	return dependencies
}

func dependencyWithRuntimeState(dependency DependencyHealth, now time.Time) DependencyHealth {
	if dependency.State == DependencyHealthy {
		dependency.CoreAPIsAvailable = true
		dependency.RecoveryDeadlineAt = time.Time{}
		return dependency
	}
	if dependency.FailureStartedAt.IsZero() {
		dependency.FailureStartedAt = dependency.LastChangedAt
	}
	if dependency.RecoveryTargetSeconds == 0 {
		dependency.RecoveryTargetSeconds = dependencyRecoveryTargetSeconds(dependency.Name)
	}
	dependency.RecoveryDeadlineAt = dependency.FailureStartedAt.Add(time.Duration(dependency.RecoveryTargetSeconds) * time.Second)
	dependency.CoreAPIsAvailable = dependencyCoreAPIsAvailable(dependency, now)
	return dependency
}

func dependencyCoreAPIsAvailable(dependency DependencyHealth, now time.Time) bool {
	if dependency.State == DependencyHealthy || dependency.State == DependencyDegraded {
		return true
	}
	if dependency.RecoveryTargetSeconds == 0 || dependency.FailureStartedAt.IsZero() {
		return false
	}
	return !now.After(dependency.FailureStartedAt.Add(time.Duration(dependency.RecoveryTargetSeconds) * time.Second))
}

func (cp *ControlPlane) coreAPIAvailabilityLocked(now time.Time) CoreAPIAvailability {
	availability := CoreAPIAvailability{
		Status:                          "Healthy",
		CoreAPIsAvailable:               true,
		WriteAPIsAvailable:              true,
		SubscriptionGenerationAvailable: true,
		RateLimitMode:                   "redis",
		Dependencies:                    cp.dependencySnapshotLocked(now),
	}
	for _, dependency := range availability.Dependencies {
		if dependency.State == DependencyHealthy {
			continue
		}
		switch dependency.Name {
		case DependencyPostgres:
			availability.WriteAPIsAvailable = false
			if dependency.CoreAPIsAvailable {
				availability.Status = maxHealthStatus(availability.Status, "Degraded")
				availability.Messages = append(availability.Messages, "postgres unavailable: serving cached read paths during 60s recovery window")
			} else {
				availability.Status = maxHealthStatus(availability.Status, "Critical")
				availability.CoreAPIsAvailable = false
				availability.SubscriptionGenerationAvailable = false
				availability.Messages = append(availability.Messages, "postgres recovery window exceeded")
			}
		case DependencyRedis:
			availability.RateLimitMode = "local-fallback"
			if dependency.CoreAPIsAvailable {
				availability.Status = maxHealthStatus(availability.Status, "Degraded")
				availability.Messages = append(availability.Messages, "redis unavailable: using local rate windows and cached node state")
			} else {
				availability.Status = maxHealthStatus(availability.Status, "Critical")
				availability.CoreAPIsAvailable = false
				availability.Messages = append(availability.Messages, "redis fallback window exceeded")
			}
		}
	}
	return availability
}

func maxHealthStatus(current, next string) string {
	if healthStatusRank(next) > healthStatusRank(current) {
		return next
	}
	return current
}

func healthStatusRank(status string) int {
	switch status {
	case "Critical":
		return 3
	case "Degraded":
		return 2
	case "Healthy":
		return 1
	default:
		return 0
	}
}

func (cp *ControlPlane) Overview(ctx RequestContext, tenantID string) (OverviewMetrics, error) {
	if err := authorize(ctx.User, "metrics:read", tenantID); err != nil {
		return OverviewMetrics{}, err
	}
	if err := requireScope(ctx, "metrics:read"); err != nil {
		return OverviewMetrics{}, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	availability := cp.coreAPIAvailabilityLocked(cp.now())
	metrics := OverviewMetrics{Health: availability.Status, API99pMs: 120, Subscription99pMs: 180, ConfigApply99pMs: 250, DependencyRows: availability.Dependencies}
	allowedNodeIDs := map[string]struct{}{}
	allowedNodes := []Node{}
	for _, node := range cp.nodes {
		if node.TenantID != tenantID {
			continue
		}
		if err := authorizeNodeABAC(ctx, node); err != nil {
			continue
		}
		allowedNodeIDs[node.ID] = struct{}{}
		allowedNodes = append(allowedNodes, node)
		if node.Status == NodeOffline {
			metrics.OfflineNodes++
			metrics.Health = maxHealthStatus(metrics.Health, "Degraded")
		} else {
			metrics.OnlineNodes++
		}
	}
	latestMetrics := cp.latestNodeMetricsLocked(tenantID, allowedNodeIDs)
	for _, node := range allowedNodes {
		if sample, ok := latestMetrics[node.ID]; ok {
			metrics.TotalConnections += sample.Connections
			metrics.ActiveConnections += sample.Connections
			metrics.TotalTrafficBytes += sample.RxBytes + sample.TxBytes
			metrics.UpBps += sample.TxBps
			metrics.DownBps += sample.RxBps
			metrics.CPU += sample.CPU
			metrics.Memory += sample.Memory
			metrics.Disk += sample.Disk
			metrics.FDUsage += sample.FDUsage
			metrics.NetworkPPS += sample.NetworkPPS
			continue
		}
		metrics.TotalConnections += node.Connections
		metrics.ActiveConnections += node.Connections
		metrics.CPU += normalizeRatio(node.CPU)
		metrics.Memory += normalizeRatio(node.Memory)
	}
	for _, alert := range cp.alerts {
		if alert.TenantID != tenantID {
			continue
		}
		if hasNodeABAC(ctx) && alert.NodeID != "" {
			if _, ok := allowedNodeIDs[alert.NodeID]; !ok {
				continue
			}
		}
		if sanitizeAlert(alert).Status == alertStatusAcknowledged {
			continue
		}
		metrics.Alerts++
	}
	for _, profile := range cp.warpProfiles {
		if profile.TenantID != tenantID {
			continue
		}
		if hasNodeABAC(ctx) && profile.NodeID != "" {
			if _, ok := allowedNodeIDs[profile.NodeID]; !ok {
				continue
			}
		}
		metrics.TopExitQualityRows = append(metrics.TopExitQualityRows, profile)
	}
	return metrics, nil
}

func (cp *ControlPlane) CapacityPlan(ctx RequestContext, tenantID string) (CapacityRecommendation, error) {
	overview, err := cp.Overview(ctx, tenantID)
	if err != nil {
		return CapacityRecommendation{}, err
	}
	totalNodes := overview.OnlineNodes + overview.OfflineNodes
	tier, subRPS, apiRPS, targetConnections, mode := capacityTier(totalNodes, overview.ActiveConnections)
	replicas := recommendedAPIReplicas(tier, overview)
	actions := []string{}
	reasons := []string{
		fmt.Sprintf("%d nodes and %d active connections map to %s capacity", totalNodes, overview.ActiveConnections, tier),
	}
	if overview.OfflineNodes > 0 {
		actions = append(actions, "replace or recover offline nodes before scaling traffic")
		reasons = append(reasons, "offline nodes reduce usable capacity")
	}
	if targetConnections > 0 && overview.ActiveConnections >= int(float64(targetConnections)*0.8) {
		actions = append(actions, "add API replicas and partition subscription generation before the next traffic step")
		reasons = append(reasons, "active connections are above 80% of the tier target")
	}
	if overview.CPU >= 0.75 || overview.Memory >= 0.75 || overview.FDUsage >= 0.75 {
		actions = append(actions, "scale control-plane replicas or move hot nodes to a larger tier")
		reasons = append(reasons, "resource pressure is above 75%")
	}
	if len(actions) == 0 {
		actions = append(actions, "hold current replica count and keep monitoring p99 latency/error rate")
	}
	costActions := []string{"prefer direct routes for mainland China traffic", "use cost-aware scheduling for non-latency-sensitive flows"}
	if tier == "Large" {
		costActions = append(costActions, "split tenants or regions before adding high-cost global capacity")
	}
	return CapacityRecommendation{
		TenantID:               tenantID,
		Tier:                   tier,
		OnlineNodes:            overview.OnlineNodes,
		OfflineNodes:           overview.OfflineNodes,
		ActiveConnections:      overview.ActiveConnections,
		TargetSubscriptionRPS:  subRPS,
		TargetAPIRPS:           apiRPS,
		TargetConnections:      targetConnections,
		RecommendedAPIReplicas: replicas,
		ControlPlaneMode:       mode,
		AutoscalingActions:     actions,
		CostActions:            costActions,
		Reasons:                reasons,
	}, nil
}

func capacityTier(nodes, activeConnections int) (tier string, subscriptionRPS, apiRPS, targetConnections int, mode string) {
	switch {
	case nodes > 100 || activeConnections > 200_000:
		return "Large", 2_000, 5_000, 2_000_000, "partitioned multi-replica"
	case nodes > 10 || activeConnections > 10_000:
		return "Medium", 500, 1_000, 200_000, "horizontal control-plane replicas"
	default:
		return "Small", 50, 100, 10_000, "single control-plane"
	}
}

func recommendedAPIReplicas(tier string, overview OverviewMetrics) int {
	switch tier {
	case "Large":
		if overview.CPU >= 0.75 || overview.Memory >= 0.75 || overview.FDUsage >= 0.75 {
			return 8
		}
		return 6
	case "Medium":
		if overview.CPU >= 0.75 || overview.Memory >= 0.75 || overview.FDUsage >= 0.75 {
			return 4
		}
		return 3
	default:
		if overview.CPU >= 0.75 || overview.Memory >= 0.75 || overview.FDUsage >= 0.75 {
			return 2
		}
		return 1
	}
}

func (cp *ControlPlane) Runbook(ctx RequestContext, tenantID, incidentID, name string) error {
	if err := authorize(ctx.User, "incidents:runbook", tenantID); err != nil {
		return err
	}
	if err := requireScope(ctx, "incidents:runbook"); err != nil {
		return err
	}
	if err := requireConfirmation(ctx); err != nil {
		return err
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	state := cp.runbookStates[tenantID]
	state.TenantID = tenantID
	state.LastRunbook = name
	state.LastRunbookAt = cp.now()
	resourceType := "incident"
	resourceID := incidentID
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "rollback-config":
		if cfg, ok := cp.rollbackLatestConfigLocked(tenantID); ok {
			resourceType = "config"
			resourceID = cfg.ID
		}
	case "pause-release":
		state.ReleasePaused = true
	case "resume-release":
		state.ReleasePaused = false
	case "pause-node-deployments":
		state.NodeDeploymentsPaused = true
	case "require-credential-rotation", "rotate-secrets":
		state.CredentialRotationRequired = true
	case "limit-subscription", "limit-subscriptions":
		state.SubscriptionEmergencyLimited = true
	case "enable-subscription-cache", "subscription-cache-mode":
		state.SubscriptionCacheForced = true
	case "resume-subscriptions":
		state.SubscriptionEmergencyLimited = false
	case "switch-exit":
		if profile, ok := cp.bestHealthyWarpProfileLocked(tenantID, SchedulePerformance); ok {
			state.LastSelectedExit = profile.Name
			resourceType = "warp_profile"
			resourceID = profile.ID
		} else {
			state.LastSelectedExit = string(rulecompiler.OutboundProxy)
		}
	case "disable-warp-profile":
		if profile, ok := cp.disableFirstWarpProfileLocked(tenantID); ok {
			resourceType = "warp_profile"
			resourceID = profile.ID
		}
	case "p3-triage", "open-runbook":
		state.P3TriageRecorded = true
	default:
		// Unknown runbook names are still audited so incident responders have a trace.
	}
	cp.runbookStates[tenantID] = state
	cp.auditLocked(ctx, tenantID, "incident.runbook."+name, resourceType, resourceID)
	return nil
}

func (cp *ControlPlane) RunbookCatalog(ctx RequestContext, tenantID string) ([]RunbookDefinition, error) {
	if err := authorize(ctx.User, "incidents:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "incidents:read"); err != nil {
		return nil, err
	}
	return []RunbookDefinition{
		{
			Severity:        "P0",
			IncidentType:    "secret-leakage-or-critical-compromise",
			ResponseTarget:  "15m",
			RunbookNames:    []string{"pause-release", "pause-node-deployments", "require-credential-rotation", "limit-subscriptions"},
			PrimaryMitigate: "pause release and deployment, require credential rotation, and restrict subscription access",
		},
		{
			Severity:        "P1",
			IncidentType:    "bad-route-rules-or-subscription-outage",
			ResponseTarget:  "30m",
			RunbookNames:    []string{"pause-release", "rollback-config", "enable-subscription-cache", "limit-subscriptions"},
			PrimaryMitigate: "rollback bad config or serve cached subscriptions while limiting abusive access",
		},
		{
			Severity:        "P2",
			IncidentType:    "single-region-node-or-warp-degradation",
			ResponseTarget:  "2h",
			RunbookNames:    []string{"switch-exit", "disable-warp-profile", "rollback-config"},
			PrimaryMitigate: "move traffic away from degraded WARP or node config and keep service available",
		},
		{
			Severity:        "P3",
			IncidentType:    "ui-or-metric-display-issue",
			ResponseTarget:  "1 business day",
			RunbookNames:    []string{"p3-triage"},
			PrimaryMitigate: "record triage and verify no operational action was affected",
		},
	}, nil
}

func (cp *ControlPlane) RunbookState(ctx RequestContext, tenantID string) (RunbookState, error) {
	if err := authorize(ctx.User, "incidents:read", tenantID); err != nil {
		return RunbookState{}, err
	}
	if err := requireScope(ctx, "incidents:read"); err != nil {
		return RunbookState{}, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	state := cp.runbookStates[tenantID]
	state.TenantID = tenantID
	return state, nil
}

func (cp *ControlPlane) rollbackLatestConfigLocked(tenantID string) (Config, bool) {
	currentID, ok := cp.currentConfigByT[tenantID]
	if !ok {
		return Config{}, false
	}
	current := cp.configs[currentID]
	var previous Config
	var previousID string
	for id, cfg := range cp.configs {
		if cfg.TenantID != tenantID || cfg.Status != "active" || cfg.Version >= current.Version {
			continue
		}
		if previous.ID == "" || cfg.Version > previous.Version {
			previous = cfg
			previousID = id
		}
	}
	if previousID == "" {
		return Config{}, false
	}
	cp.currentConfigByT[tenantID] = previousID
	return previous, true
}

func (cp *ControlPlane) bestHealthyWarpProfileLocked(tenantID string, mode ScheduleMode) (WarpProfile, bool) {
	var best WarpProfile
	bestScore := 1e9
	for _, profile := range cp.warpProfiles {
		if profile.TenantID != tenantID || profile.Status != "healthy" {
			continue
		}
		score := scoreProfile(profile, mode)
		if best.ID == "" || score < bestScore {
			best = profile
			bestScore = score
		}
	}
	return best, best.ID != ""
}

func (cp *ControlPlane) disableFirstWarpProfileLocked(tenantID string) (WarpProfile, bool) {
	var ids []string
	for id, profile := range cp.warpProfiles {
		if profile.TenantID == tenantID && profile.Status != "disabled" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return WarpProfile{}, false
	}
	profile := cp.warpProfiles[ids[0]]
	profile.Status = "disabled"
	cp.warpProfiles[ids[0]] = profile
	return profile, true
}

func normalizeRuleRolloutPercent(percent int) (int, error) {
	if percent == 0 {
		return 100, nil
	}
	switch percent {
	case 1, 5, 20, 50, 100:
		return percent, nil
	default:
		return 0, errors.New("unsupported rule rollout percent")
	}
}

func (cp *ControlPlane) CreateAPIToken(ctx RequestContext, tenantID string, role Role, scopes, ipAllowlist []string, expiresAt time.Time) (APIToken, string, error) {
	if err := authorize(ctx.User, "tokens:write", tenantID); err != nil {
		return APIToken{}, "", err
	}
	if err := requireConfirmation(ctx); err != nil {
		return APIToken{}, "", err
	}
	token := randomToken()
	apiToken := APIToken{
		ID:          randomID("api"),
		TenantID:    tenantID,
		UserID:      ctx.User.ID,
		Role:        role,
		TokenHash:   HashToken(token),
		Scopes:      append([]string(nil), scopes...),
		IPAllowlist: append([]string(nil), ipAllowlist...),
		ExpiresAt:   expiresAt,
		CreatedAt:   cp.now(),
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.apiTokens[apiToken.ID] = apiToken
	cp.auditLocked(ctx, tenantID, "api_token.create", "api_token", apiToken.ID)
	return apiToken, token, nil
}

func (cp *ControlPlane) AuthenticateAPIToken(token, ip string) (RequestContext, error) {
	hash := HashToken(token)
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	for _, apiToken := range cp.apiTokens {
		if apiToken.TokenHash != hash {
			continue
		}
		if apiToken.Revoked || (!apiToken.ExpiresAt.IsZero() && cp.now().After(apiToken.ExpiresAt)) {
			return RequestContext{}, ErrRevoked
		}
		if len(apiToken.IPAllowlist) > 0 && !ipAllowed(ip, apiToken.IPAllowlist) {
			return RequestContext{}, ErrForbidden
		}
		return RequestContext{
			User: User{
				ID:       apiToken.UserID,
				TenantID: apiToken.TenantID,
				Role:     apiToken.Role,
			},
			IP:        net.ParseIP(ip),
			Scopes:    append([]string(nil), apiToken.Scopes...),
			Confirmed: true,
		}, nil
	}
	return RequestContext{}, ErrUnauthorized
}

func (cp *ControlPlane) DecryptWarpPrivateKey(ctx RequestContext, profileID string) (string, error) {
	cp.mu.RLock()
	profile, ok := cp.warpProfiles[profileID]
	cp.mu.RUnlock()
	if !ok {
		return "", ErrNotFound
	}
	if err := authorize(ctx.User, "warp:write", profile.TenantID); err != nil {
		return "", err
	}
	if err := requireScope(ctx, "warp:write"); err != nil {
		return "", err
	}
	if err := requireConfirmation(ctx); err != nil {
		return "", err
	}
	return cp.decryptString(profile.EncryptedPrivateKey)
}

func (cp *ControlPlane) VerifyAuditChain(ctx RequestContext, tenantID string) error {
	if err := authorize(ctx.User, "audit:read", tenantID); err != nil {
		return err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	prev := ""
	for _, log := range cp.auditLogs {
		if log.TenantID != tenantID {
			continue
		}
		if log.PrevHash != prev {
			return fmt.Errorf("audit chain broken at %s", log.ID)
		}
		if computeAuditHash(log, log.PrevHash) != log.Hash {
			return fmt.Errorf("audit hash mismatch at %s", log.ID)
		}
		prev = log.Hash
	}
	return nil
}

func (cp *ControlPlane) AuditLogs(ctx RequestContext, tenantID string) ([]AuditLog, error) {
	if err := authorize(ctx.User, "audit:read", tenantID); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	var logs []AuditLog
	for _, log := range cp.auditLogs {
		if log.TenantID == tenantID {
			logs = append(logs, log)
		}
	}
	return logs, nil
}

func (cp *ControlPlane) Logs(ctx RequestContext, tenantID string) ([]string, error) {
	if err := authorize(ctx.User, "logs:read", tenantID); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	lines := make([]string, 0)
	for _, log := range cp.auditLogs {
		if log.TenantID == tenantID {
			lines = append(lines, SanitizeLog(log.Action+" resource="+log.ResourceType+" id="+log.ResourceID))
		}
	}
	return lines, nil
}

func (cp *ControlPlane) Alerts(ctx RequestContext, tenantID string) ([]Alert, error) {
	if err := authorize(ctx.User, "alerts:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "alerts:read"); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	alerts := []Alert{}
	for _, alert := range cp.alerts {
		if alert.TenantID != tenantID {
			continue
		}
		if alert.NodeID != "" {
			node, ok := cp.nodes[alert.NodeID]
			if hasNodeABAC(ctx) && (!ok || authorizeNodeABAC(ctx, node) != nil) {
				continue
			}
		}
		alerts = append(alerts, sanitizeAlert(alert))
	}
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].CreatedAt.After(alerts[j].CreatedAt)
	})
	return alerts, nil
}

func (cp *ControlPlane) AcknowledgeAlert(ctx RequestContext, tenantID, alertID string) (Alert, error) {
	if err := authorize(ctx.User, "alerts:write", tenantID); err != nil {
		return Alert{}, err
	}
	if err := requireScope(ctx, "alerts:write"); err != nil {
		return Alert{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return Alert{}, err
	}
	alertID = strings.TrimSpace(alertID)
	if alertID == "" {
		return Alert{}, ErrBadRequest
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for i, alert := range cp.alerts {
		if alert.ID != alertID {
			continue
		}
		if alert.TenantID != tenantID {
			return Alert{}, ErrForbidden
		}
		if alert.NodeID != "" {
			node, ok := cp.nodes[alert.NodeID]
			if hasNodeABAC(ctx) && (!ok || authorizeNodeABAC(ctx, node) != nil) {
				return Alert{}, ErrForbidden
			}
		}
		alert.Status = alertStatusAcknowledged
		alert.AcknowledgedAt = cp.now()
		alert.AcknowledgedBy = ctx.User.ID
		cp.alerts[i] = alert
		cp.auditLocked(ctx, tenantID, "alert.acknowledge", "alert", alert.ID)
		return sanitizeAlert(alert), nil
	}
	return Alert{}, ErrNotFound
}

func (cp *ControlPlane) CreateSecurityWaiver(ctx RequestContext, waiver SecurityWaiver) (SecurityWaiver, error) {
	tenantID := nonEmpty(waiver.TenantID, ctx.User.TenantID)
	if err := authorize(ctx.User, "security:write", tenantID); err != nil {
		return SecurityWaiver{}, err
	}
	if err := requireScope(ctx, "security:write"); err != nil {
		return SecurityWaiver{}, err
	}
	if err := requireConfirmation(ctx); err != nil {
		return SecurityWaiver{}, err
	}
	now := cp.now()
	waiver.ID = nonEmpty(strings.TrimSpace(waiver.ID), randomID("waiver"))
	waiver.TenantID = tenantID
	waiver.Gate = sanitizeWaiverText(waiver.Gate, 80)
	waiver.Severity = sanitizeWaiverText(nonEmpty(waiver.Severity, "P2"), 16)
	waiver.Owner = sanitizeWaiverText(waiver.Owner, 120)
	waiver.Reason = sanitizeWaiverText(waiver.Reason, 240)
	waiver.RemediationPlan = sanitizeWaiverText(waiver.RemediationPlan, 500)
	waiver.CreatedAt = now
	waiver.CreatedBy = ctx.User.ID
	if waiver.Gate == "" || waiver.Owner == "" || waiver.RemediationPlan == "" || waiver.ExpiresAt.IsZero() || !waiver.ExpiresAt.After(now) {
		return SecurityWaiver{}, ErrBadRequest
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.securityWaivers[waiver.ID] = waiver
	cp.auditLocked(ctx, tenantID, "security.waiver.create", "security_waiver", waiver.ID)
	return waiver, nil
}

func (cp *ControlPlane) ListSecurityWaivers(ctx RequestContext, tenantID string) ([]SecurityWaiver, error) {
	if err := authorize(ctx.User, "security:read", tenantID); err != nil {
		return nil, err
	}
	if err := requireScope(ctx, "security:read"); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	waivers := []SecurityWaiver{}
	for _, waiver := range cp.securityWaivers {
		if waiver.TenantID == tenantID {
			waivers = append(waivers, waiver)
		}
	}
	sort.Slice(waivers, func(i, j int) bool {
		if waivers[i].ExpiresAt.Equal(waivers[j].ExpiresAt) {
			return waivers[i].ID < waivers[j].ID
		}
		return waivers[i].ExpiresAt.Before(waivers[j].ExpiresAt)
	})
	return waivers, nil
}

func (cp *ControlPlane) Incidents(ctx RequestContext, tenantID string) ([]Incident, error) {
	if err := authorize(ctx.User, "incidents:read", tenantID); err != nil {
		return nil, err
	}
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	incidents := []Incident{}
	for _, alert := range cp.alerts {
		if alert.TenantID == tenantID {
			alert = sanitizeAlert(alert)
			incidents = append(incidents, Incident{
				ID:        "incident-" + alert.ID,
				TenantID:  tenantID,
				Severity:  alert.Severity,
				Status:    alert.Status,
				Title:     alert.Message,
				StartedAt: alert.CreatedAt,
			})
		}
	}
	return incidents, nil
}

func authorizeNodeABAC(ctx RequestContext, node Node) error {
	if len(ctx.AllowedRegions) > 0 && !matchesABACValue(ctx.AllowedRegions, node.Region) {
		return ErrForbidden
	}
	if len(ctx.AllowedEnvironments) > 0 && !matchesABACValue(ctx.AllowedEnvironments, node.Environment) {
		return ErrForbidden
	}
	if len(ctx.AllowedNodeTags) > 0 && !matchesABACTag(ctx.AllowedNodeTags, node.Tags) {
		return ErrForbidden
	}
	return nil
}

func hasNodeABAC(ctx RequestContext) bool {
	return len(ctx.AllowedRegions) > 0 || len(ctx.AllowedNodeTags) > 0 || len(ctx.AllowedEnvironments) > 0
}

func matchesABACValue(allowed []string, value string) bool {
	value = normalizeABACValue(value)
	for _, candidate := range allowed {
		candidate = normalizeABACValue(candidate)
		if candidate == "" {
			continue
		}
		if candidate == "*" || candidate == value {
			return true
		}
	}
	return false
}

func matchesABACTag(allowed, tags []string) bool {
	normalizedTags := map[string]struct{}{}
	for _, tag := range tags {
		tag = normalizeABACValue(tag)
		if tag != "" {
			normalizedTags[tag] = struct{}{}
		}
	}
	for _, candidate := range allowed {
		candidate = normalizeABACValue(candidate)
		if candidate == "" {
			continue
		}
		if candidate == "*" {
			return true
		}
		if _, ok := normalizedTags[candidate]; ok {
			return true
		}
	}
	return false
}

func normalizeABACValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func sanitizeRouteTraceInput(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")
	if idx := strings.IndexAny(input, "?#"); idx >= 0 {
		input = input[:idx]
	}
	input = strings.TrimRight(input, ".")
	if slash := strings.Index(input, "/"); slash > 0 {
		path := input[slash:]
		host := input[:slash]
		if host == "google.com" && strings.HasPrefix(path, "/scholar") {
			return "google.com/scholar"
		}
		return strings.TrimRight(host, ".")
	}
	return input
}

func routeDecisionText(classification rulecompiler.Classification) string {
	if classification.RuleID == "" {
		return fmt.Sprintf("%s via %s", classification.Outbound, classification.Reason)
	}
	return fmt.Sprintf("%s via %s rule=%s matcher=%s", classification.Outbound, classification.Reason, classification.RuleID, classification.MatchedRule)
}

func copyNode(node Node) Node {
	node.Tags = copyStrings(node.Tags)
	node.RecoverableTaskIDs = copyStrings(node.RecoverableTaskIDs)
	node.ProtocolStats = copyProtocolStats(node.ProtocolStats)
	return node
}

func copyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	copied := make([]string, len(values))
	copy(copied, values)
	return copied
}

func copyProtocolStats(values []ProtocolInboundStat) []ProtocolInboundStat {
	if len(values) == 0 {
		return nil
	}
	copied := make([]ProtocolInboundStat, len(values))
	copy(copied, values)
	return copied
}

func authorize(user User, action, tenantID string) error {
	if user.ID == "" {
		return ErrUnauthorized
	}
	if user.TenantID != tenantID {
		return ErrForbidden
	}
	switch user.Role {
	case RoleOwner:
		return nil
	case RoleAdmin:
		if strings.HasSuffix(action, ":read") || strings.HasSuffix(action, ":write") || action == "configs:write" || action == "rules:write" || action == "warp:write" || action == "incidents:runbook" {
			return nil
		}
	case RoleOperator:
		if strings.HasSuffix(action, ":read") || action == "incidents:runbook" {
			return nil
		}
	case RoleAuditor:
		if strings.HasSuffix(action, ":read") || action == "audit:read" {
			return nil
		}
	case RoleDeveloper:
		if strings.HasPrefix(action, "dev:") || strings.HasSuffix(action, ":read") {
			return nil
		}
	}
	return ErrForbidden
}

func requireScope(ctx RequestContext, action string) error {
	if len(ctx.Scopes) == 0 {
		return nil
	}
	for _, scope := range ctx.Scopes {
		scope = strings.TrimSpace(scope)
		if scope == "*" || scope == action {
			return nil
		}
		if strings.HasSuffix(scope, ":*") {
			prefix := strings.TrimSuffix(scope, "*")
			if strings.HasPrefix(action, prefix) {
				return nil
			}
		}
	}
	return ErrForbidden
}

func explicitScopeAllows(ctx RequestContext, action string) bool {
	if len(ctx.Scopes) == 0 {
		return false
	}
	return requireScope(ctx, action) == nil
}

func requireConfirmation(ctx RequestContext) error {
	if !ctx.Confirmed {
		return ErrConfirmationRequired
	}
	return nil
}

func ConfirmationToken(userID string) string {
	sum := sha256.Sum256([]byte("confirm-v1:" + userID))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte("sub-token-v1:" + token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func HashAgentFingerprint(fingerprint string) string {
	sum := sha256.Sum256([]byte("agent-mtls-v1:" + fingerprint))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func SanitizeLog(input string) string {
	secretKeys := map[string]struct{}{
		"private_key":      {},
		"token":            {},
		"warp_private_key": {},
		"api_key":          {},
		"password":         {},
	}
	fields := strings.Fields(input)
	for i, field := range fields {
		key, _, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		if _, sensitive := secretKeys[strings.ToLower(key)]; sensitive {
			fields[i] = key + "=REDACTED"
		}
	}
	return strings.Join(fields, " ")
}

func sanitizeAlert(alert Alert) Alert {
	if alert.Status == "" {
		alert.Status = alertStatusOpen
	}
	alert.Message = html.EscapeString(SanitizeLog(alert.Message))
	alert.AcknowledgedBy = html.EscapeString(SanitizeLog(alert.AcknowledgedBy))
	return alert
}

func sanitizeWaiverText(value string, maxLen int) string {
	value = html.EscapeString(SanitizeLog(strings.TrimSpace(value)))
	if maxLen > 0 && len(value) > maxLen {
		value = value[:maxLen]
	}
	return value
}

func subscriptionAccessContext(tenantID, ip string) RequestContext {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		parsed = net.IPv4zero
	}
	return RequestContext{
		User: User{
			ID:       "subscription-client",
			TenantID: tenantID,
			Role:     RoleAuditor,
		},
		IP: parsed,
	}
}

func (cp *ControlPlane) allowRequestLocked(key string, limit int, period time.Duration) error {
	now := cp.now()
	window := cp.rateWindows[key]
	if window.start.IsZero() || now.Sub(window.start) >= period {
		window = rateWindow{start: now}
	}
	window.count++
	cp.rateWindows[key] = window
	if window.count > limit {
		return ErrRateLimited
	}
	return nil
}

func (cp *ControlPlane) alertExistsLocked(tenantID, nodeID, message string) bool {
	for _, alert := range cp.alerts {
		if alert.TenantID == tenantID && alert.NodeID == nodeID && alert.Message == message {
			return true
		}
	}
	return false
}

func (cp *ControlPlane) auditLocked(ctx RequestContext, tenantID, action, resourceType, resourceID string) {
	prevHash := ""
	if len(cp.auditLogs) > 0 {
		prevHash = cp.auditLogs[len(cp.auditLogs)-1].Hash
	}
	log := AuditLog{
		ID:           randomID("audit"),
		TenantID:     tenantID,
		ActorID:      ctx.User.ID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IP:           ctx.IP.String(),
		CreatedAt:    cp.now(),
		PrevHash:     prevHash,
	}
	log.Hash = computeAuditHash(log, prevHash)
	cp.auditLogs = append(cp.auditLogs, log)
}

func computeAuditHash(log AuditLog, prevHash string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		prevHash,
		log.ID,
		log.TenantID,
		log.ActorID,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		log.IP,
		log.CreatedAt.UTC().Format(time.RFC3339Nano),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func renderClientSubscription(clientType string, sub Subscription) string {
	deviceID := sanitizeSubscriptionField(sub.DeviceID, 64)
	region := sanitizeSubscriptionField(sub.Region, 32)
	protocol := normalizeSubscriptionProtocol(sub.Protocol)
	outboundPolicy := normalizeSubscriptionOutboundPolicy(sub.OutboundPolicy)
	if deviceID == "" {
		deviceID = "any-device"
	}
	if region == "" {
		region = "global"
	}
	switch strings.ToLower(clientType) {
	case "sing-box":
		payload := struct {
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
		}{}
		payload.Metadata.UserID = sanitizeSubscriptionField(sub.UserID, 64)
		payload.Metadata.DeviceID = deviceID
		payload.Metadata.Region = region
		payload.Metadata.Protocol = protocol
		payload.Metadata.OutboundPolicy = outboundPolicy
		payload.Metadata.PolicyID = sanitizeSubscriptionField(sub.PolicyID, 64)
		payload.Outbounds = append(payload.Outbounds, struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}{Type: "direct", Tag: "direct"})
		payload.Outbounds = append(payload.Outbounds, struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}{Type: "selector", Tag: "proxy-default"})
		payload.Outbounds = append(payload.Outbounds, struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}{Type: protocol, Tag: outboundPolicy})
		payload.DNS.Servers = append(payload.DNS.Servers, struct {
			Tag     string `json:"tag"`
			Address string `json:"address"`
			Detour  string `json:"detour"`
		}{Tag: "dns-cn", Address: "https://223.5.5.5/dns-query", Detour: "direct"})
		payload.DNS.Servers = append(payload.DNS.Servers, struct {
			Tag     string `json:"tag"`
			Address string `json:"address"`
			Detour  string `json:"detour"`
		}{Tag: "dns-global", Address: "https://1.1.1.1/dns-query", Detour: "proxy-default"})
		payload.DNS.Rules = append(payload.DNS.Rules, struct {
			RuleSet []string `json:"rule_set,omitempty"`
			Domain  []string `json:"domain,omitempty"`
			Server  string   `json:"server"`
		}{RuleSet: []string{"geosite-cn", "geoip-cn", "cn-cdn", "cn-bank", "cn-gov"}, Server: "dns-cn"})
		payload.DNS.Rules = append(payload.DNS.Rules, struct {
			RuleSet []string `json:"rule_set,omitempty"`
			Domain  []string `json:"domain,omitempty"`
			Server  string   `json:"server"`
		}{Domain: []string{"scholar.google.com", "scholar.googleusercontent.com", "citations.google.com", "academic.google.com"}, Server: "dns-global"})
		payload.DNS.Final = "dns-global"
		payload.Route.Rules = append(payload.Route.Rules, struct {
			IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
			RuleSet      []string `json:"rule_set,omitempty"`
			DomainSuffix []string `json:"domain_suffix,omitempty"`
			Outbound     string   `json:"outbound"`
		}{IPIsPrivate: true, Outbound: "direct"})
		payload.Route.Rules = append(payload.Route.Rules, struct {
			IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
			RuleSet      []string `json:"rule_set,omitempty"`
			DomainSuffix []string `json:"domain_suffix,omitempty"`
			Outbound     string   `json:"outbound"`
		}{RuleSet: []string{"geoip-cn", "geosite-cn", "cn-cdn", "cn-bank", "cn-gov"}, Outbound: "direct"})
		payload.Route.Rules = append(payload.Route.Rules, struct {
			IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
			RuleSet      []string `json:"rule_set,omitempty"`
			DomainSuffix []string `json:"domain_suffix,omitempty"`
			Outbound     string   `json:"outbound"`
		}{DomainSuffix: []string{"scholar.google.com", "scholar.googleusercontent.com", "citations.google.com", "academic.google.com"}, Outbound: "proxy-default"})
		payload.Route.Rules = append(payload.Route.Rules, struct {
			IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
			RuleSet      []string `json:"rule_set,omitempty"`
			DomainSuffix []string `json:"domain_suffix,omitempty"`
			Outbound     string   `json:"outbound"`
		}{RuleSet: []string{"warp-include"}, Outbound: outboundPolicy})
		payload.Route.Final = outboundPolicy
		data, _ := json.Marshal(payload)
		return string(data)
	case "clash", "clash-meta":
		return fmt.Sprintf("proxies:\n- name: %s\n  type: %s\n  region: %s\n  device: %s\nproxy-groups:\n- name: AUTO\n  type: select\n  proxies: [%s]\nrules:\n- IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n- GEOSITE,cn,DIRECT\n- GEOIP,CN,DIRECT\n- DOMAIN-SUFFIX,scholar.google.com,proxy-default\n- RULE-SET,warp-include,%s\n- MATCH,%s\n", outboundPolicy, protocol, region, deviceID, outboundPolicy, outboundPolicy, outboundPolicy)
	case "shadowrocket":
		return fmt.Sprintf("%s://%s@example.invalid:443?security=tls&region=%s&device=%s#%s", protocol, outboundPolicy, region, deviceID, outboundPolicy)
	case "v2rayn":
		label := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s/%s/%s/%s", outboundPolicy, protocol, region, deviceID)))
		return "vmess://" + label
	case "nekobox":
		return fmt.Sprintf("nekobox://profile/%s?protocol=%s&region=%s&device=%s", outboundPolicy, protocol, region, deviceID)
	default:
		return outboundPolicy
	}
}

func normalizeSubscriptionProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vless", "vmess", "hysteria2", "tuic", "trojan":
		return strings.ToLower(strings.TrimSpace(protocol))
	default:
		return "vless"
	}
}

func normalizeSubscriptionClientType(clientType string) string {
	switch strings.ToLower(strings.TrimSpace(clientType)) {
	case "sing-box", "clash", "clash-meta", "shadowrocket", "v2rayn", "nekobox":
		return strings.ToLower(strings.TrimSpace(clientType))
	default:
		return ""
	}
}

func normalizeSubscriptionOutboundPolicy(outboundPolicy string) string {
	value := sanitizeSubscriptionField(outboundPolicy, 64)
	if value == "" {
		return "proxy-default"
	}
	return value
}

func sanitizeSubscriptionField(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		if maxLen > 0 && b.Len() >= maxLen {
			break
		}
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == '@':
			b.WriteRune(r)
		}
	}
	return b.String()
}

func ipAllowed(ip string, allowlist []string) bool {
	for _, allowed := range allowlist {
		if strings.TrimSpace(allowed) == ip {
			return true
		}
	}
	return false
}

func (cp *ControlPlane) encryptString(plaintext string) (string, error) {
	block, err := aes.NewCipher(cp.envelopeKey[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return "enc:" + base64.RawURLEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func (cp *ControlPlane) decryptString(value string) (string, error) {
	if !strings.HasPrefix(value, "enc:") {
		return "", errors.New("value is not encrypted")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "enc:"))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(cp.envelopeKey[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("encrypted value too short")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func scoreProfile(profile WarpProfile, mode ScheduleMode) float64 {
	p := profile.LastProbe
	score := p.LatencyMs/1000 +
		p.Loss*10 +
		boolPenalty(!p.HTTPSuccess)*5 +
		p.CPUPressure*2 +
		p.MemoryPressure*2 +
		float64(p.Connections)/10_000 +
		float64(p.RecentFailures)
	switch mode {
	case SchedulePerformance:
		score -= 0.25 / max(profile.Weight, 0.1)
	case ScheduleLowResource:
		score += p.CPUPressure*3 + p.MemoryPressure*3
	case ScheduleCostAware:
		score -= profile.Weight * 0.1
	}
	return score
}

func isGoogleScholar(site string) bool {
	site = strings.ToLower(strings.TrimSpace(site))
	return site == "google.com/scholar" ||
		site == "scholar.google.com" ||
		strings.HasSuffix(site, ".scholar.google.com") ||
		site == "scholar.googleusercontent.com" ||
		strings.HasSuffix(site, ".scholar.googleusercontent.com") ||
		site == "citations.google.com" ||
		site == "academic.google.com"
}

func shortHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func randomID(prefix string) string {
	return prefix + "-" + randomTokenN(9)
}

func randomToken() string {
	return randomTokenN(32)
}

func randomTokenN(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func nonZeroTime(value, fallback time.Time) time.Time {
	if value.IsZero() {
		return fallback
	}
	return value
}

func boolPenalty(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func DeadlineContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
