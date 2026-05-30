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
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Policy struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	RiskThreshold int       `json:"risk_threshold"`
	DefaultAction string    `json:"default_action"`
	Enabled       bool      `json:"enabled"`
	SiteIDs       []int64   `json:"site_ids"`
	RuleIDs       []int64   `json:"rule_ids"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
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

type AccessListEntry struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	Value     string    `json:"value"`
	Action    string    `json:"action"`
	SiteID    int64     `json:"site_id"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RateLimitRule struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Scope       string    `json:"scope"`
	MatchValue  string    `json:"match_value"`
	Threshold   int       `json:"threshold"`
	WindowSec   int       `json:"window_sec"`
	Action      string    `json:"action"`
	BanDuration int       `json:"ban_duration_sec"`
	SiteID      int64     `json:"site_id"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
