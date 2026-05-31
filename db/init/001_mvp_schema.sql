CREATE TABLE IF NOT EXISTS sites (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	host TEXT NOT NULL UNIQUE,
	upstream TEXT NOT NULL,
	mode TEXT NOT NULL DEFAULT 'monitor',
	enabled BOOLEAN NOT NULL DEFAULT true,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rules (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	type TEXT NOT NULL,
	target TEXT NOT NULL,
	action TEXT NOT NULL,
	expression TEXT NOT NULL,
	score INTEGER NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT true,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policies (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	risk_threshold INTEGER NOT NULL DEFAULT 100,
	default_action TEXT NOT NULL DEFAULT 'block',
	enabled BOOLEAN NOT NULL DEFAULT true,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_sites (
	policy_id BIGINT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
	site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	PRIMARY KEY (policy_id, site_id)
);

CREATE TABLE IF NOT EXISTS policy_rules (
	policy_id BIGINT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
	rule_id BIGINT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
	PRIMARY KEY (policy_id, rule_id)
);

CREATE TABLE IF NOT EXISTS publish_records (
	id BIGSERIAL PRIMARY KEY,
	version TEXT NOT NULL UNIQUE,
	operator TEXT NOT NULL,
	status TEXT NOT NULL,
	config_path TEXT NOT NULL,
	checksum TEXT NOT NULL,
	note TEXT NOT NULL DEFAULT '',
	config_json TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE publish_records ADD COLUMN IF NOT EXISTS config_json TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS users (
	id BIGSERIAL PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT true,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
	id BIGSERIAL PRIMARY KEY,
	actor TEXT NOT NULL,
	role TEXT NOT NULL,
	action TEXT NOT NULL,
	resource_type TEXT NOT NULL,
	resource_id TEXT NOT NULL DEFAULT '',
	result TEXT NOT NULL,
	remote_addr TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	message TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_logs (
	id BIGSERIAL PRIMARY KEY,
	request_id TEXT NOT NULL DEFAULT '',
	site_id BIGINT NOT NULL DEFAULT 0,
	host TEXT NOT NULL DEFAULT '',
	method TEXT NOT NULL DEFAULT '',
	uri TEXT NOT NULL DEFAULT '',
	status INTEGER NOT NULL DEFAULT 0,
	upstream_status INTEGER NOT NULL DEFAULT 0,
	duration_ms BIGINT NOT NULL DEFAULT 0,
	client_ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	disposition TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_logs_site_id ON access_logs (site_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip ON access_logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_access_logs_status ON access_logs (status);
CREATE INDEX IF NOT EXISTS idx_access_logs_disposition ON access_logs (disposition);

CREATE TABLE IF NOT EXISTS waf_events (
	id BIGSERIAL PRIMARY KEY,
	request_id TEXT NOT NULL DEFAULT '',
	site_id BIGINT NOT NULL DEFAULT 0,
	event_type TEXT NOT NULL DEFAULT '',
	rule_id BIGINT NOT NULL DEFAULT 0,
	rule_type TEXT NOT NULL DEFAULT '',
	target TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL DEFAULT '',
	disposition TEXT NOT NULL DEFAULT '',
	client_ip TEXT NOT NULL DEFAULT '',
	method TEXT NOT NULL DEFAULT '',
	uri TEXT NOT NULL DEFAULT '',
	summary TEXT NOT NULL DEFAULT '',
	access_list_id BIGINT NOT NULL DEFAULT 0,
	rate_limit_id BIGINT NOT NULL DEFAULT 0,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_waf_events_created_at ON waf_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_events_site_id ON waf_events (site_id);
CREATE INDEX IF NOT EXISTS idx_waf_events_client_ip ON waf_events (client_ip);
CREATE INDEX IF NOT EXISTS idx_waf_events_rule_id ON waf_events (rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_events_action ON waf_events (action);
CREATE INDEX IF NOT EXISTS idx_waf_events_disposition ON waf_events (disposition);
CREATE INDEX IF NOT EXISTS idx_waf_events_event_type ON waf_events (event_type);

CREATE TABLE IF NOT EXISTS access_list_entries (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	kind TEXT NOT NULL,
	target TEXT NOT NULL,
	value TEXT NOT NULL,
	action TEXT NOT NULL,
	site_id BIGINT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT true,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rate_limit_rules (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	scope TEXT NOT NULL,
	match_value TEXT NOT NULL DEFAULT '',
	threshold INTEGER NOT NULL,
	window_sec INTEGER NOT NULL,
	action TEXT NOT NULL,
	ban_duration_sec INTEGER NOT NULL DEFAULT 0,
	site_id BIGINT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT true,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS upload_protection_rules (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	path TEXT NOT NULL DEFAULT '/',
	path_match TEXT NOT NULL DEFAULT 'prefix',
	methods TEXT NOT NULL DEFAULT '',
	extensions TEXT NOT NULL DEFAULT '',
	max_bytes INTEGER NOT NULL DEFAULT 0,
	action TEXT NOT NULL DEFAULT 'block',
	site_id BIGINT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT true,
	priority INTEGER NOT NULL DEFAULT 100,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO rules (name, type, target, action, expression, score, enabled)
SELECT 'LiteWaf SQLi baseline', 'sqli', 'args', 'block', '(?i)(union\s+select|or\s+1=1|sleep\s*\(|benchmark\s*\()', 80, true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LiteWaf SQLi baseline');

INSERT INTO rules (name, type, target, action, expression, score, enabled)
SELECT 'LiteWaf XSS baseline', 'xss', 'args', 'block', '(?i)(<script|javascript:|onerror\s*=|onload\s*=)', 80, true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LiteWaf XSS baseline');

INSERT INTO rules (name, type, target, action, expression, score, enabled)
SELECT 'LiteWaf RCE baseline', 'rce', 'args', 'block', '(?i)(;\s*(cat|curl|wget|bash|sh)\b|\|\s*(bash|sh)\b|\$\(|/bin/(bash|sh))', 90, true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LiteWaf RCE baseline');

INSERT INTO rules (name, type, target, action, expression, score, enabled)
SELECT 'LiteWaf normalized traversal baseline', 'rce', 'normalized_uri', 'block', '(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self/environ)', 70, true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LiteWaf normalized traversal baseline');
