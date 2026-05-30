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
	CreatedAt  time.Time `json:"created_at"`
	Time       string    `json:"time"`
}
