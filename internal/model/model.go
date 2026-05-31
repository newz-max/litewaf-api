package model

import "time"

type Site struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	Upstream  string    `json:"upstream"`
	Mode      string    `json:"mode"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Rule struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Target     string    `json:"target"`
	Action     string    `json:"action"`
	Expression string    `json:"expression"`
	Score      int       `json:"score"`
	Enabled    bool      `json:"enabled"`
	Module     string    `json:"module"`
	Category   string    `json:"category"`
	AttackType string    `json:"attack_type"`
	Group      string    `json:"group"`
	Priority   int       `json:"priority"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Policy struct {
	ID                         int64     `json:"id"`
	Name                       string    `json:"name"`
	RiskThreshold              int       `json:"risk_threshold"`
	DefaultAction              string    `json:"default_action"`
	NormalizationEnabled       bool      `json:"normalization_enabled"`
	NormalizationDecodePasses  int       `json:"normalization_decode_passes"`
	NormalizationMaxValueBytes int       `json:"normalization_max_value_bytes"`
	BodyInspectionEnabled      bool      `json:"body_inspection_enabled"`
	BodyInspectionContentTypes []string  `json:"body_inspection_content_types"`
	BodyInspectionPathPrefixes []string  `json:"body_inspection_path_prefixes"`
	BodyInspectionMaxBytes     int       `json:"body_inspection_max_bytes"`
	OversizedBodyAction        string    `json:"oversized_body_action"`
	UploadInspectionEnabled    bool      `json:"upload_inspection_enabled"`
	UploadMaxBytes             int       `json:"upload_max_bytes"`
	UploadSizeAction           string    `json:"upload_size_action"`
	DynamicBanEnabled          bool      `json:"dynamic_ban_enabled"`
	DynamicBanDurationSec      int       `json:"dynamic_ban_duration_sec"`
	DynamicBanScoreThreshold   int       `json:"dynamic_ban_score_threshold"`
	DynamicBanTriggerCount     int       `json:"dynamic_ban_trigger_count"`
	DynamicBanWindowSec        int       `json:"dynamic_ban_window_sec"`
	Enabled                    bool      `json:"enabled"`
	SiteIDs                    []int64   `json:"site_ids"`
	RuleIDs                    []int64   `json:"rule_ids"`
	CreatedAt                  time.Time `json:"created_at"`
	UpdatedAt                  time.Time `json:"updated_at"`
}

type PublishRecord struct {
	ID         int64     `json:"id"`
	Version    string    `json:"version"`
	Operator   string    `json:"operator"`
	Status     string    `json:"status"`
	ConfigPath string    `json:"config_path"`
	Checksum   string    `json:"checksum"`
	Note       string    `json:"note"`
	ConfigJSON string    `json:"-"`
	CreatedAt  time.Time `json:"created_at"`
	Time       string    `json:"time"`
}

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type AuditLog struct {
	ID           int64     `json:"id"`
	Actor        string    `json:"actor"`
	Role         string    `json:"role"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Result       string    `json:"result"`
	RemoteAddr   string    `json:"remote_addr"`
	UserAgent    string    `json:"user_agent"`
	Message      string    `json:"message"`
	CreatedAt    time.Time `json:"created_at"`
	Time         string    `json:"time"`
}

type AuditLogFilter struct {
	Actor        string
	Action       string
	ResourceType string
	Result       string
	Since        time.Time
	Until        time.Time
}

type Pagination struct {
	Limit  int
	Offset int
}

type AccessLog struct {
	Event          string    `json:"event,omitempty"`
	ID             int64     `json:"id"`
	RequestID      string    `json:"request_id"`
	SiteID         int64     `json:"site_id"`
	Host           string    `json:"host"`
	Method         string    `json:"method"`
	URI            string    `json:"uri"`
	Status         int       `json:"status"`
	UpstreamStatus int       `json:"upstream_status"`
	DurationMS     int64     `json:"duration_ms"`
	ClientIP       string    `json:"client_ip"`
	UserAgent      string    `json:"user_agent"`
	Disposition    string    `json:"disposition"`
	CreatedAt      time.Time `json:"created_at"`
	Time           string    `json:"time"`
}

type AccessLogFilter struct {
	SiteID      int64
	Host        string
	ClientIP    string
	Method      string
	URI         string
	Status      int
	Disposition string
	Since       time.Time
	Until       time.Time
	Pagination  Pagination
}

type WAFEvent struct {
	Event           string    `json:"event,omitempty"`
	ID              int64     `json:"id"`
	RequestID       string    `json:"request_id"`
	SiteID          int64     `json:"site_id"`
	EventType       string    `json:"event_type"`
	RuleID          int64     `json:"rule_id"`
	RuleType        string    `json:"rule_type"`
	Target          string    `json:"target"`
	Action          string    `json:"action"`
	Disposition     string    `json:"disposition"`
	ClientIP        string    `json:"client_ip"`
	Method          string    `json:"method"`
	URI             string    `json:"uri"`
	Summary         string    `json:"summary"`
	AccessListID    int64     `json:"access_list_id"`
	RateLimitID     int64     `json:"rate_limit_id"`
	Module          string    `json:"module"`
	Category        string    `json:"category"`
	RuleName        string    `json:"rule_name"`
	AttackType      string    `json:"attack_type"`
	GroupName       string    `json:"group_name"`
	Counter         string    `json:"counter"`
	WindowSec       int       `json:"window_sec"`
	AdvancedTarget  string    `json:"advanced_target"`
	NormalizedValue string    `json:"normalized_value"`
	Score           int       `json:"score"`
	Threshold       int       `json:"threshold"`
	MatchedRuleIDs  string    `json:"matched_rule_ids"`
	BodyMetadata    string    `json:"body_metadata"`
	UploadMetadata  string    `json:"upload_metadata"`
	BanReason       string    `json:"ban_reason"`
	BanDurationSec  int       `json:"ban_duration_sec"`
	BanRemainingSec int       `json:"ban_remaining_sec"`
	ChallengeMode   string    `json:"challenge_mode"`
	ChallengeResult string    `json:"challenge_result"`
	CreatedAt       time.Time `json:"created_at"`
	Time            string    `json:"time"`
}

type WAFEventFilter struct {
	SiteID          int64
	ClientIP        string
	RuleID          int64
	Action          string
	Disposition     string
	EventType       string
	Module          string
	AttackType      string
	AdvancedTarget  string
	ChallengeResult string
	MinScore        int
	Since           time.Time
	Until           time.Time
	Pagination      Pagination
}

type ObservabilitySummary struct {
	Requests         int64          `json:"requests"`
	BlockedRequests  int64          `json:"blocked_requests"`
	WAFMatches       int64          `json:"waf_matches"`
	RateLimited      int64          `json:"rate_limited"`
	ScoreBlocks      int64          `json:"score_blocks"`
	BodyDetections   int64          `json:"body_detections"`
	UploadDetections int64          `json:"upload_detections"`
	DynamicBans      int64          `json:"dynamic_bans"`
	AccessControl    []SummaryCount `json:"access_control"`
	TopIPs           []SummaryCount `json:"top_ips"`
	TopURIs          []SummaryCount `json:"top_uris"`
	TopRules         []SummaryCount `json:"top_rules"`
	AttackTypes      []SummaryCount `json:"attack_types"`
	AttackProtection []SummaryCount `json:"attack_protection"`
	UploadProtection []SummaryCount `json:"upload_protection"`
	BotProtection    []SummaryCount `json:"bot_protection"`
}

type AttackProtectionGroup struct {
	ID               string                    `json:"id"`
	Name             string                    `json:"name"`
	Module           string                    `json:"module"`
	Category         string                    `json:"category"`
	AttackType       string                    `json:"attack_type"`
	Action           string                    `json:"action"`
	Enabled          bool                      `json:"enabled"`
	Priority         int                       `json:"priority"`
	RuleCount        int                       `json:"rule_count"`
	EnabledRuleCount int                       `json:"enabled_rule_count"`
	Rules            []AttackProtectionRuleRef `json:"rules"`
	UpdatedAt        time.Time                 `json:"updated_at"`
}

type AttackProtectionRuleRef struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Target     string `json:"target"`
	Action     string `json:"action"`
	Score      int    `json:"score"`
	Enabled    bool   `json:"enabled"`
	AttackType string `json:"attack_type"`
	Group      string `json:"group"`
}

type SummaryCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type ObservabilitySummaryFilter struct {
	Since time.Time
	Until time.Time
	Limit int
}

type AccessListEntry struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	Target        string    `json:"target"`
	Value         string    `json:"value"`
	MatchOperator string    `json:"match_operator"`
	HeaderName    string    `json:"header_name"`
	Action        string    `json:"action"`
	SiteID        int64     `json:"site_id"`
	Enabled       bool      `json:"enabled"`
	Priority      int       `json:"priority"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type RateLimitRule struct {
	ID                 int64     `json:"id"`
	Name               string    `json:"name"`
	Scope              string    `json:"scope"`
	MatchValue         string    `json:"match_value"`
	PathMatch          string    `json:"path_match"`
	Methods            []string  `json:"methods"`
	Threshold          int       `json:"threshold"`
	WindowSec          int       `json:"window_sec"`
	Action             string    `json:"action"`
	CCAction           string    `json:"cc_action"`
	BanDuration        int       `json:"ban_duration_sec"`
	ViolationThreshold int       `json:"violation_threshold"`
	ViolationWindowSec int       `json:"violation_window_sec"`
	SiteID             int64     `json:"site_id"`
	Enabled            bool      `json:"enabled"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type ProtectionRule struct {
	ID        int64                    `json:"id"`
	Name      string                   `json:"name"`
	Module    string                   `json:"module"`
	Category  string                   `json:"category"`
	SiteID    int64                    `json:"site_id"`
	Enabled   bool                     `json:"enabled"`
	Priority  int                      `json:"priority"`
	Match     ProtectionRuleMatch      `json:"match"`
	Limit     ProtectionRuleLimit      `json:"limit"`
	Upload    *ProtectionRuleUpload    `json:"upload,omitempty"`
	Challenge *ProtectionRuleChallenge `json:"challenge,omitempty"`
	Action    ProtectionRuleAction     `json:"action"`
	CreatedAt time.Time                `json:"created_at"`
	UpdatedAt time.Time                `json:"updated_at"`
}

type ProtectionRuleMatch struct {
	Path       string   `json:"path"`
	PathMatch  string   `json:"path_match"`
	Methods    []string `json:"methods"`
	Target     string   `json:"target"`
	Value      string   `json:"value"`
	Operator   string   `json:"operator"`
	HeaderName string   `json:"header_name"`
	Host       string   `json:"host"`
}

type ProtectionRuleLimit struct {
	Counter        string `json:"counter"`
	Threshold      int    `json:"threshold"`
	WindowSec      int    `json:"window_sec"`
	BanDurationSec int    `json:"ban_duration_sec"`
}

type ProtectionRuleUpload struct {
	Extensions []string `json:"extensions"`
	MaxBytes   int      `json:"max_bytes"`
}

type ProtectionRuleChallenge struct {
	Mode          string `json:"mode"`
	VerifyTTL     int    `json:"verify_ttl_sec"`
	FailureAction string `json:"failure_action"`
}

type ProtectionRuleAction struct {
	Type string `json:"type"`
}

type UploadProtectionRule struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	PathMatch  string    `json:"path_match"`
	Methods    []string  `json:"methods"`
	Extensions []string  `json:"extensions"`
	MaxBytes   int       `json:"max_bytes"`
	Action     string    `json:"action"`
	SiteID     int64     `json:"site_id"`
	Enabled    bool      `json:"enabled"`
	Priority   int       `json:"priority"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type BotProtectionRule struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	Path          string    `json:"path"`
	PathMatch     string    `json:"path_match"`
	Methods       []string  `json:"methods"`
	ChallengeMode string    `json:"challenge_mode"`
	VerifyTTL     int       `json:"verify_ttl_sec"`
	FailureAction string    `json:"failure_action"`
	SiteID        int64     `json:"site_id"`
	Enabled       bool      `json:"enabled"`
	Priority      int       `json:"priority"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
