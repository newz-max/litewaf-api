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
	ID                      int64     `json:"id"`
	Name                    string    `json:"name"`
	Type                    string    `json:"type"`
	Target                  string    `json:"target"`
	Action                  string    `json:"action"`
	Expression              string    `json:"expression"`
	Score                   int       `json:"score"`
	Enabled                 bool      `json:"enabled"`
	Module                  string    `json:"module"`
	Category                string    `json:"category"`
	AttackType              string    `json:"attack_type"`
	Group                   string    `json:"group"`
	Priority                int       `json:"priority"`
	PackageID               string    `json:"package_id"`
	PackageVersion          string    `json:"package_version"`
	PackageRuleID           string    `json:"package_rule_id"`
	SourceChecksum          string    `json:"source_checksum"`
	SignatureStatus         string    `json:"signature_status"`
	ReviewStatus            string    `json:"review_status"`
	LastTestStatus          string    `json:"last_test_status"`
	RemoteCatalogID         string    `json:"remote_catalog_id"`
	ProviderID              int64     `json:"provider_id,omitempty"`
	ProviderName            string    `json:"provider_name,omitempty"`
	ProviderPackageRef      string    `json:"provider_package_ref,omitempty"`
	LastSyncedVersion       string    `json:"last_synced_version"`
	PendingUpdateState      string    `json:"pending_update_state"`
	LocalOverrideState      string    `json:"local_override_state"`
	ExportEligible          bool      `json:"export_eligible"`
	ExportIneligibleReasons []string  `json:"export_ineligible_reasons,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
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
	IPAccessListID  int64     `json:"ip_access_list_id"`
	IPListKind      string    `json:"ip_list_kind"`
	IPListTarget    string    `json:"ip_list_target"`
	BanReason       string    `json:"ban_reason"`
	BanDurationSec  int       `json:"ban_duration_sec"`
	BanRemainingSec int       `json:"ban_remaining_sec"`
	ChallengeMode   string    `json:"challenge_mode"`
	ChallengeResult string    `json:"challenge_result"`
	BotResult       string    `json:"bot_result"`
	BotReason       string    `json:"bot_reason"`
	DeviceSignal    string    `json:"device_signal"`
	PackageID       string    `json:"package_id"`
	PackageVersion  string    `json:"package_version"`
	PackageRuleID   string    `json:"package_rule_id"`
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
	BotResult       string
	DynamicResult   string
	MinScore        int
	Since           time.Time
	Until           time.Time
	Pagination      Pagination
}

type DynamicBan struct {
	ID              int64     `json:"id"`
	SiteID          int64     `json:"site_id"`
	ClientIP        string    `json:"client_ip"`
	BanReason       string    `json:"ban_reason"`
	Source          string    `json:"source"`
	SourceEventID   int64     `json:"source_event_id"`
	BanDurationSec  int       `json:"ban_duration_sec"`
	BanRemainingSec int       `json:"ban_remaining_sec"`
	Status          string    `json:"status"`
	Revision        int64     `json:"revision"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	ClearedAt       time.Time `json:"cleared_at,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
	Time            string    `json:"time"`
}

type DynamicBanFilter struct {
	SiteID      int64
	ClientIP    string
	Status      string
	MinRevision int64
	Pagination  Pagination
}

type DynamicBanClearRequest struct {
	SiteID   int64  `json:"site_id"`
	ClientIP string `json:"client_ip"`
	Actor    string `json:"actor,omitempty"`
}

type DynamicBanClearResult struct {
	SiteID    int64     `json:"site_id"`
	ClientIP  string    `json:"client_ip"`
	Status    string    `json:"status"`
	Revision  int64     `json:"revision"`
	ClearedAt time.Time `json:"cleared_at"`
	Message   string    `json:"message"`
}

type ObservabilitySummary struct {
	Requests          int64          `json:"requests"`
	BlockedRequests   int64          `json:"blocked_requests"`
	WAFMatches        int64          `json:"waf_matches"`
	RateLimited       int64          `json:"rate_limited"`
	ScoreBlocks       int64          `json:"score_blocks"`
	BodyDetections    int64          `json:"body_detections"`
	UploadDetections  int64          `json:"upload_detections"`
	DynamicBans       int64          `json:"dynamic_bans"`
	AccessControl     []SummaryCount `json:"access_control"`
	IPAccessList      []SummaryCount `json:"ip_access_list"`
	TopIPs            []SummaryCount `json:"top_ips"`
	TopURIs           []SummaryCount `json:"top_uris"`
	TopRules          []SummaryCount `json:"top_rules"`
	AttackTypes       []SummaryCount `json:"attack_types"`
	AttackProtection  []SummaryCount `json:"attack_protection"`
	UploadProtection  []SummaryCount `json:"upload_protection"`
	BotProtection     []SummaryCount `json:"bot_protection"`
	DynamicProtection []SummaryCount `json:"dynamic_protection"`
}

type ProtectionOverview struct {
	Modules []ProtectionModuleOverview `json:"modules"`
	Risks   []ProtectionModuleRisk     `json:"risks"`
}

type ProtectionModuleOverview struct {
	Key                 string                 `json:"key"`
	Label               string                 `json:"label"`
	Category            string                 `json:"category"`
	Route               string                 `json:"route"`
	LogModule           string                 `json:"log_module,omitempty"`
	Rules               int                    `json:"rules"`
	Enabled             int                    `json:"enabled"`
	Observe             int                    `json:"observe"`
	Block               int                    `json:"block"`
	Allow               int                    `json:"allow,omitempty"`
	CompatibilitySource string                 `json:"compatibility_source,omitempty"`
	Warnings            []string               `json:"warnings"`
	RiskDetails         []ProtectionModuleRisk `json:"risk_details,omitempty"`
	Evidence            []SummaryCount         `json:"evidence"`
}

type ProtectionModuleRisk struct {
	Module         string `json:"module"`
	Label          string `json:"label"`
	RuleName       string `json:"rule_name,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Action         string `json:"action,omitempty"`
	Impact         string `json:"impact,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	Message        string `json:"message"`
}

type ProtectionRuleMigrationHealth struct {
	GeneratedAt      time.Time                    `json:"generated_at"`
	ProtectionRules  ProtectionRuleHealthSummary  `json:"protection_rules"`
	LegacyStores     []LegacyProtectionStoreState `json:"legacy_stores"`
	Issues           []ProtectionRuleHealthIssue  `json:"issues"`
	Backfill         BackfillHealthState          `json:"backfill"`
	RemediationHints []string                     `json:"remediation_hints"`
}

type ProtectionRuleHealthSummary struct {
	Total             int            `json:"total"`
	Enabled           int            `json:"enabled"`
	Disabled          int            `json:"disabled"`
	ByModule          map[string]int `json:"by_module"`
	ByCategory        map[string]int `json:"by_category"`
	BySource          map[string]int `json:"by_source"`
	ByMigrationStatus map[string]int `json:"by_migration_status"`
	BySite            map[string]int `json:"by_site"`
}

type LegacyProtectionStoreState struct {
	Store          string   `json:"store"`
	Module         string   `json:"module"`
	Category       string   `json:"category"`
	Total          int      `json:"total"`
	Enabled        int      `json:"enabled"`
	Migrated       int      `json:"migrated"`
	Missing        int      `json:"missing"`
	Orphaned       int      `json:"orphaned"`
	Duplicates     int      `json:"duplicates"`
	Conflicts      int      `json:"conflicts"`
	MissingSamples []string `json:"missing_samples"`
	OrphanSamples  []string `json:"orphan_samples"`
}

type ProtectionRuleHealthIssue struct {
	Type           string   `json:"type"`
	Severity       string   `json:"severity"`
	Store          string   `json:"store,omitempty"`
	Module         string   `json:"module,omitempty"`
	Count          int      `json:"count"`
	Samples        []string `json:"samples"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation"`
}

type BackfillHealthState struct {
	Status         string `json:"status"`
	LastRunAt      string `json:"last_run_at,omitempty"`
	Created        int    `json:"created"`
	Updated        int    `json:"updated"`
	Skipped        int    `json:"skipped"`
	Failed         int    `json:"failed"`
	Command        string `json:"command"`
	Recommendation string `json:"recommendation"`
}

type PublishCompatibilityDiagnostics struct {
	ProtectionRules int                            `json:"protection_rules"`
	RateLimits      int                            `json:"rate_limits"`
	LegacyModules   map[string]int                 `json:"legacy_modules"`
	ByModule        map[string]CompatibilityCounts `json:"by_module"`
	Deduplicated    int                            `json:"deduplicated"`
	Warnings        []string                       `json:"warnings"`
}

type CompatibilityCounts struct {
	ProtectionRules int `json:"protection_rules"`
	Native          int `json:"native"`
	Migrated        int `json:"migrated"`
	LegacyFallback  int `json:"legacy_fallback"`
	LegacyStore     int `json:"legacy_store"`
	Deduplicated    int `json:"deduplicated"`
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
	Source           string                    `json:"source,omitempty"`
	MigrationStatus  string                    `json:"migration_status,omitempty"`
	LegacyRef        string                    `json:"legacy_ref,omitempty"`
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

type IPAccessListEntry struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Kind            string    `json:"kind"`
	Target          string    `json:"target"`
	Value           string    `json:"value"`
	NormalizedValue string    `json:"normalized_value"`
	IPFamily        string    `json:"ip_family"`
	PrefixLength    int       `json:"prefix_length"`
	SiteID          int64     `json:"site_id"`
	Enabled         bool      `json:"enabled"`
	Priority        int       `json:"priority"`
	ConflictKey     string    `json:"conflict_key"`
	Description     string    `json:"description"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
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
	ID              int64                    `json:"id"`
	Name            string                   `json:"name"`
	Module          string                   `json:"module"`
	Category        string                   `json:"category"`
	SiteID          int64                    `json:"site_id"`
	Enabled         bool                     `json:"enabled"`
	Priority        int                      `json:"priority"`
	Match           ProtectionRuleMatch      `json:"match"`
	Limit           ProtectionRuleLimit      `json:"limit"`
	Upload          *ProtectionRuleUpload    `json:"upload,omitempty"`
	Challenge       *ProtectionRuleChallenge `json:"challenge,omitempty"`
	Dynamic         *ProtectionRuleDynamic   `json:"dynamic,omitempty"`
	Action          ProtectionRuleAction     `json:"action"`
	Source          string                   `json:"source,omitempty"`
	MigrationStatus string                   `json:"migration_status,omitempty"`
	LegacyRef       string                   `json:"legacy_ref,omitempty"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
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
	SessionSource  string `json:"session_source,omitempty"`
	SessionName    string `json:"session_name,omitempty"`
	DeviceStrategy string `json:"device_strategy,omitempty"`
}

type ProtectionRuleUpload struct {
	Extensions []string `json:"extensions"`
	MaxBytes   int      `json:"max_bytes"`
}

type ProtectionRuleChallenge struct {
	Mode               string `json:"mode"`
	VerifyTTL          int    `json:"verify_ttl_sec"`
	FailureAction      string `json:"failure_action"`
	BehaviorEnabled    bool   `json:"behavior_enabled"`
	BehaviorThreshold  int    `json:"behavior_threshold"`
	DeviceBinding      bool   `json:"device_binding"`
	SearchEngineBypass bool   `json:"search_engine_bypass"`
	FailureMessage     string `json:"failure_message"`
	PrivacyNotice      string `json:"privacy_notice"`
}

type ProtectionRuleDynamic struct {
	Mode             string `json:"mode"`
	TokenTTL         int    `json:"token_ttl_sec"`
	TokenPlacement   string `json:"token_placement"`
	FailureAction    string `json:"failure_action"`
	MutationMarker   string `json:"mutation_marker"`
	MutationMaxBytes int    `json:"mutation_max_bytes"`
	QueueCapacity    int    `json:"queue_capacity"`
	AdmissionTTL     int    `json:"admission_ttl_sec"`
	RetryInterval    int    `json:"retry_interval_sec"`
	OverflowAction   string `json:"overflow_action"`
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

type DynamicProtectionRule struct {
	ID               int64     `json:"id"`
	Name             string    `json:"name"`
	Category         string    `json:"category"`
	Path             string    `json:"path"`
	PathMatch        string    `json:"path_match"`
	Methods          []string  `json:"methods"`
	TokenTTL         int       `json:"token_ttl_sec"`
	TokenPlacement   string    `json:"token_placement"`
	FailureAction    string    `json:"failure_action"`
	MutationMarker   string    `json:"mutation_marker"`
	MutationMaxBytes int       `json:"mutation_max_bytes"`
	QueueCapacity    int       `json:"queue_capacity"`
	AdmissionTTL     int       `json:"admission_ttl_sec"`
	RetryInterval    int       `json:"retry_interval_sec"`
	OverflowAction   string    `json:"overflow_action"`
	SiteID           int64     `json:"site_id"`
	Enabled          bool      `json:"enabled"`
	Priority         int       `json:"priority"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type RulePackageSignature struct {
	KeyID     string `json:"key_id"`
	Checksum  string `json:"checksum"`
	Signature string `json:"signature"`
	ExpiresAt string `json:"expires_at"`
}

type RulePackageMetadata struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	Version         string               `json:"version"`
	Author          string               `json:"author"`
	License         string               `json:"license"`
	Compatibility   string               `json:"compatibility"`
	Checksum        string               `json:"checksum"`
	Signature       RulePackageSignature `json:"signature"`
	SignatureStatus string               `json:"signature_status"`
	RuleCount       int                  `json:"rule_count"`
	Warnings        []string             `json:"warnings"`
	CreatedAt       time.Time            `json:"created_at,omitempty"`
	UpdatedAt       time.Time            `json:"updated_at,omitempty"`
}

type RulePackage struct {
	Metadata RulePackageMetadata `json:"metadata"`
	Defaults RulePackageDefaults `json:"defaults"`
	Rules    []Rule              `json:"rules"`
}

type RulePackageDefaults struct {
	Enabled      bool   `json:"enabled"`
	ReviewStatus string `json:"review_status"`
}

type RulePackagePreview struct {
	Package             RulePackageMetadata `json:"package"`
	Added               []Rule              `json:"added"`
	Changed             []Rule              `json:"changed"`
	Skipped             []Rule              `json:"skipped"`
	Invalid             []RulePackageError  `json:"invalid"`
	DefaultState        bool                `json:"default_enabled"`
	Warnings            []string            `json:"warnings"`
	CompatibilityStatus string              `json:"compatibility_status"`
	SourceCatalogID     string              `json:"source_catalog_id,omitempty"`
	ProviderID          int64               `json:"provider_id,omitempty"`
	ProviderName        string              `json:"provider_name,omitempty"`
	ProviderPackageRef  string              `json:"provider_package_ref,omitempty"`
	EntitlementWarnings []string            `json:"entitlement_warnings,omitempty"`
	RetryState          string              `json:"retry_state,omitempty"`
	TrustStatus         string              `json:"trust_status,omitempty"`
	Blocked             bool                `json:"blocked,omitempty"`
	BlockReason         string              `json:"block_reason,omitempty"`
}

type RulePackageError struct {
	RuleID  string `json:"rule_id"`
	Message string `json:"message"`
}

type RulePackageImportResult struct {
	Package  RulePackageMetadata `json:"package"`
	Imported []Rule              `json:"imported"`
	Changed  []Rule              `json:"changed"`
	Skipped  []Rule              `json:"skipped"`
	Invalid  []RulePackageError  `json:"invalid"`
}

type RuleCatalogSource struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Source         string    `json:"source"`
	ProviderID     int64     `json:"provider_id,omitempty"`
	ProviderName   string    `json:"provider_name,omitempty"`
	ProviderHealth string    `json:"provider_health,omitempty"`
	Enabled        bool      `json:"enabled"`
	TimeoutSec     int       `json:"timeout_sec"`
	Status         string    `json:"status"`
	LastSyncAt     time.Time `json:"last_sync_at,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	PackageCount   int       `json:"package_count"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type RuleCatalogPackage struct {
	ID                 int64                `json:"id"`
	CatalogID          int64                `json:"catalog_id"`
	ProviderID         int64                `json:"provider_id,omitempty"`
	ProviderName       string               `json:"provider_name,omitempty"`
	ProviderPackageRef string               `json:"provider_package_ref,omitempty"`
	EntitlementState   string               `json:"entitlement_state,omitempty"`
	PackageID          string               `json:"package_id"`
	Name               string               `json:"name"`
	Version            string               `json:"version"`
	Compatibility      string               `json:"compatibility"`
	Checksum           string               `json:"checksum"`
	Signature          RulePackageSignature `json:"signature"`
	SignatureStatus    string               `json:"signature_status"`
	UpdatedAtText      string               `json:"updated_at_text"`
	ManifestURL        string               `json:"manifest_url"`
	PackageJSON        string               `json:"-"`
	SourceIdentity     string               `json:"source_identity"`
	SyncStatus         string               `json:"sync_status"`
	Stale              bool                 `json:"stale"`
	LastSyncedAt       time.Time            `json:"last_synced_at,omitempty"`
	CreatedAt          time.Time            `json:"created_at"`
	UpdatedAt          time.Time            `json:"updated_at"`
}

type RuleTrustKey struct {
	ID        int64     `json:"id"`
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	Owner     string    `json:"owner"`
	PublicKey string    `json:"public_key,omitempty"`
	Enabled   bool      `json:"enabled"`
	Revoked   bool      `json:"revoked"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RulePackageUpdatePreview struct {
	Package           RulePackageMetadata `json:"package"`
	CurrentVersion    string              `json:"current_version"`
	CandidateVersion  string              `json:"candidate_version"`
	CurrentChecksum   string              `json:"current_checksum"`
	CandidateChecksum string              `json:"candidate_checksum"`
	SourceCatalogID   int64               `json:"source_catalog_id"`
	Added             []Rule              `json:"added"`
	Changed           []Rule              `json:"changed"`
	Removed           []Rule              `json:"removed"`
	Unchanged         []Rule              `json:"unchanged"`
	Skipped           []Rule              `json:"skipped"`
	Invalid           []RulePackageError  `json:"invalid"`
	Warnings          []string            `json:"warnings"`
	SignatureStatus   string              `json:"signature_status"`
}

type RulePackageExportRequest struct {
	PackageID     string  `json:"package_id"`
	Name          string  `json:"name"`
	Version       string  `json:"version"`
	Author        string  `json:"author"`
	License       string  `json:"license"`
	Compatibility string  `json:"compatibility"`
	RuleIDs       []int64 `json:"rule_ids"`
	SigningKeyID  string  `json:"signing_key_id"`
}

type RulePackageExportPreview struct {
	Package       RulePackageMetadata `json:"package"`
	SelectedRules []Rule              `json:"selected_rules"`
	Invalid       []RulePackageError  `json:"invalid"`
	Warnings      []string            `json:"warnings"`
	ChecksumPlan  string              `json:"checksum_plan"`
	SigningStatus string              `json:"signing_status"`
}

type RulePackageExportArtifact struct {
	Package   RulePackageMetadata `json:"package"`
	Artifact  string              `json:"artifact"`
	Checksum  string              `json:"checksum"`
	RuleCount int                 `json:"rule_count"`
	Guidance  []string            `json:"guidance"`
	CreatedAt time.Time           `json:"created_at"`
}

type RuleAccountCredential struct {
	Alias           string    `json:"alias"`
	Fingerprint     string    `json:"fingerprint"`
	LastFour        string    `json:"last_four"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
	LastValidatedAt time.Time `json:"last_validated_at,omitempty"`
	Status          string    `json:"status"`
}

type RuleProviderRetryPolicy struct {
	MaxAttempts int `json:"max_attempts"`
	BackoffSec  int `json:"backoff_sec"`
}

type RuleProviderAdapter struct {
	ID               int64                   `json:"id"`
	Name             string                  `json:"name"`
	ProviderType     string                  `json:"provider_type"`
	Endpoint         string                  `json:"endpoint"`
	AuthMode         string                  `json:"auth_mode"`
	Enabled          bool                    `json:"enabled"`
	TimeoutSec       int                     `json:"timeout_sec"`
	RetryPolicy      RuleProviderRetryPolicy `json:"retry_policy"`
	Credential       RuleAccountCredential   `json:"credential"`
	HealthStatus     string                  `json:"health_status"`
	SyncStatus       string                  `json:"sync_status"`
	LastSyncAt       time.Time               `json:"last_sync_at,omitempty"`
	LastFailedSyncAt time.Time               `json:"last_failed_sync_at,omitempty"`
	LastError        string                  `json:"last_error,omitempty"`
	AttemptCount     int                     `json:"attempt_count"`
	NextRetryAt      time.Time               `json:"next_retry_at,omitempty"`
	RetryExhausted   bool                    `json:"retry_exhausted"`
	PackageCount     int                     `json:"package_count"`
	CreatedAt        time.Time               `json:"created_at"`
	UpdatedAt        time.Time               `json:"updated_at"`
}

type RuleProviderPackage struct {
	ID                 int64                `json:"id"`
	ProviderID         int64                `json:"provider_id"`
	ProviderName       string               `json:"provider_name"`
	ProviderType       string               `json:"provider_type"`
	ProviderPackageRef string               `json:"provider_package_ref"`
	PackageID          string               `json:"package_id"`
	Name               string               `json:"name"`
	Version            string               `json:"version"`
	Compatibility      string               `json:"compatibility"`
	Checksum           string               `json:"checksum"`
	Signature          RulePackageSignature `json:"signature"`
	SignatureStatus    string               `json:"signature_status"`
	UpdatedAtText      string               `json:"updated_at_text"`
	ManifestURL        string               `json:"manifest_url"`
	PackageJSON        string               `json:"-"`
	SourceIdentity     string               `json:"source_identity"`
	EntitlementState   string               `json:"entitlement_state"`
	SyncStatus         string               `json:"sync_status"`
	Stale              bool                 `json:"stale"`
	LastSyncedAt       time.Time            `json:"last_synced_at,omitempty"`
	CreatedAt          time.Time            `json:"created_at"`
	UpdatedAt          time.Time            `json:"updated_at"`
}

type RuleCommunityAccountSource struct {
	ID                  int64                 `json:"id"`
	Name                string                `json:"name"`
	ProviderType        string                `json:"provider_type"`
	ProviderAdapterID   int64                 `json:"provider_adapter_id,omitempty"`
	ProviderAdapterName string                `json:"provider_adapter_name,omitempty"`
	ProviderHealth      string                `json:"provider_health,omitempty"`
	ProviderRetryState  string                `json:"provider_retry_state,omitempty"`
	Endpoint            string                `json:"endpoint"`
	Enabled             bool                  `json:"enabled"`
	TimeoutSec          int                   `json:"timeout_sec"`
	Credential          RuleAccountCredential `json:"credential"`
	SubscriptionStatus  string                `json:"subscription_status"`
	EntitlementSummary  string                `json:"entitlement_summary"`
	PackageCount        int                   `json:"package_count"`
	Status              string                `json:"status"`
	LastSyncAt          time.Time             `json:"last_sync_at,omitempty"`
	LastError           string                `json:"last_error,omitempty"`
	RecommendationCount int                   `json:"recommendation_count"`
	CreatedAt           time.Time             `json:"created_at"`
	UpdatedAt           time.Time             `json:"updated_at"`
}

type RuleCommunityAccountSecret struct {
	Secret string `json:"secret,omitempty"`
}

type RuleContributionTarget struct {
	ID         int64                 `json:"id"`
	Name       string                `json:"name"`
	Provider   string                `json:"provider"`
	Endpoint   string                `json:"endpoint"`
	Channel    string                `json:"channel"`
	Enabled    bool                  `json:"enabled"`
	Credential RuleAccountCredential `json:"credential"`
	Status     string                `json:"status"`
	LastPushAt time.Time             `json:"last_push_at,omitempty"`
	LastError  string                `json:"last_error,omitempty"`
	CreatedAt  time.Time             `json:"created_at"`
	UpdatedAt  time.Time             `json:"updated_at"`
}

type RuleContributionPushRequest struct {
	TargetID int64                     `json:"target_id"`
	Artifact RulePackageExportArtifact `json:"artifact"`
}

type RuleContributionPushAttempt struct {
	ID              int64     `json:"id"`
	TargetID        int64     `json:"target_id"`
	TargetName      string    `json:"target_name"`
	PackageID       string    `json:"package_id"`
	PackageVersion  string    `json:"package_version"`
	Checksum        string    `json:"checksum"`
	Status          string    `json:"status"`
	RemoteReference string    `json:"remote_reference,omitempty"`
	Error           string    `json:"error,omitempty"`
	Actor           string    `json:"actor"`
	PreviewOnly     bool      `json:"preview_only"`
	CreatedAt       time.Time `json:"created_at"`
}

type RuleReviewQueueItem struct {
	ID                  int64     `json:"id"`
	ItemType            string    `json:"item_type"`
	PackageID           string    `json:"package_id"`
	PackageVersion      string    `json:"package_version"`
	CurrentVersion      string    `json:"current_version,omitempty"`
	SourceIdentity      string    `json:"source_identity"`
	Recommendation      string    `json:"recommendation"`
	RiskSummary         string    `json:"risk_summary"`
	SignatureStatus     string    `json:"signature_status"`
	CompatibilityStatus string    `json:"compatibility_status"`
	State               string    `json:"state"`
	DecisionReason      string    `json:"decision_reason,omitempty"`
	Actor               string    `json:"actor,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type RuleFeedback struct {
	ID             int64             `json:"id"`
	RuleID         int64             `json:"rule_id"`
	PackageID      string            `json:"package_id,omitempty"`
	PackageRuleID  string            `json:"package_rule_id,omitempty"`
	AttackLogID    int64             `json:"attack_log_id,omitempty"`
	Reason         string            `json:"reason"`
	Severity       string            `json:"severity"`
	Status         string            `json:"status"`
	RedactedSample map[string]string `json:"redacted_sample,omitempty"`
	Actor          string            `json:"actor,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type RuleFeedbackSuggestion struct {
	ID             int64          `json:"id"`
	FeedbackID     int64          `json:"feedback_id"`
	RuleID         int64          `json:"rule_id"`
	ProposedChange string         `json:"proposed_change"`
	RiskWarning    string         `json:"risk_warning"`
	Confidence     string         `json:"confidence"`
	State          string         `json:"state"`
	TestResult     RuleTestResult `json:"test_result,omitempty"`
	Actor          string         `json:"actor,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type RuleTestSample struct {
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Query          map[string]string `json:"query"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body"`
	UploadFilename string            `json:"upload_filename"`
	UploadMIME     string            `json:"upload_mime"`
	UploadSize     int               `json:"upload_size"`
}

type RuleTestRequest struct {
	RuleID int64          `json:"rule_id"`
	Rule   Rule           `json:"rule"`
	Sample RuleTestSample `json:"sample"`
}

type RuleTestResult struct {
	RuleID          int64             `json:"rule_id"`
	Matched         bool              `json:"matched"`
	Target          string            `json:"target"`
	EvaluatedValues []string          `json:"evaluated_values"`
	Action          string            `json:"action"`
	Score           int               `json:"score"`
	Status          string            `json:"status"`
	Diagnostics     map[string]string `json:"diagnostics"`
}
