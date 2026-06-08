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
	listener_port INTEGER NOT NULL DEFAULT 0,
	scheme TEXT NOT NULL DEFAULT '',
	host TEXT NOT NULL DEFAULT '',
	method TEXT NOT NULL DEFAULT '',
	uri TEXT NOT NULL DEFAULT '',
	status INTEGER NOT NULL DEFAULT 0,
	upstream_status INTEGER NOT NULL DEFAULT 0,
	duration_ms BIGINT NOT NULL DEFAULT 0,
	client_ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	referer TEXT NOT NULL DEFAULT '',
	geo_country TEXT NOT NULL DEFAULT '',
	geo_region TEXT NOT NULL DEFAULT '',
	geo_city TEXT NOT NULL DEFAULT '',
	geo_district TEXT NOT NULL DEFAULT '',
	geo_longitude DOUBLE PRECISION NOT NULL DEFAULT 0,
	geo_latitude DOUBLE PRECISION NOT NULL DEFAULT 0,
	geo_resolved BOOLEAN NOT NULL DEFAULT false,
	geo_source TEXT NOT NULL DEFAULT '',
	geo_source_version TEXT NOT NULL DEFAULT '',
	geo_unresolved_reason TEXT NOT NULL DEFAULT '',
	disposition TEXT NOT NULL DEFAULT '',
	reason_code TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_logs_site_id ON access_logs (site_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_listener ON access_logs (site_id, listener_port, scheme);
CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip ON access_logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_access_logs_status ON access_logs (status);
CREATE INDEX IF NOT EXISTS idx_access_logs_disposition ON access_logs (disposition);
CREATE INDEX IF NOT EXISTS idx_access_logs_reason_code ON access_logs (reason_code);
CREATE INDEX IF NOT EXISTS idx_access_logs_geo_country ON access_logs (geo_country);
CREATE INDEX IF NOT EXISTS idx_access_logs_geo_region ON access_logs (geo_region);
CREATE INDEX IF NOT EXISTS idx_access_logs_geo_resolved ON access_logs (geo_resolved);

CREATE TABLE IF NOT EXISTS waf_events (
	id BIGSERIAL PRIMARY KEY,
	request_id TEXT NOT NULL DEFAULT '',
	site_id BIGINT NOT NULL DEFAULT 0,
	listener_port INTEGER NOT NULL DEFAULT 0,
	scheme TEXT NOT NULL DEFAULT '',
	host TEXT NOT NULL DEFAULT '',
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
CREATE INDEX IF NOT EXISTS idx_waf_events_listener ON waf_events (site_id, listener_port, scheme);
CREATE INDEX IF NOT EXISTS idx_waf_events_client_ip ON waf_events (client_ip);
CREATE INDEX IF NOT EXISTS idx_waf_events_rule_id ON waf_events (rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_events_action ON waf_events (action);
CREATE INDEX IF NOT EXISTS idx_waf_events_disposition ON waf_events (disposition);
CREATE INDEX IF NOT EXISTS idx_waf_events_event_type ON waf_events (event_type);

CREATE SEQUENCE IF NOT EXISTS dynamic_ban_clear_revision_seq;

CREATE TABLE IF NOT EXISTS dynamic_bans (
	id BIGSERIAL PRIMARY KEY,
	site_id BIGINT NOT NULL DEFAULT 0,
	listener_port INTEGER NOT NULL DEFAULT 0,
	scheme TEXT NOT NULL DEFAULT '',
	client_ip TEXT NOT NULL DEFAULT '',
	ban_reason TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL DEFAULT '',
	source_event_id BIGINT NOT NULL DEFAULT 0,
	ban_duration_sec INTEGER NOT NULL DEFAULT 0,
	ban_remaining_sec INTEGER NOT NULL DEFAULT 0,
	status TEXT NOT NULL DEFAULT 'active',
	revision BIGINT NOT NULL DEFAULT 0,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	expires_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	cleared_at TIMESTAMPTZ,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dynamic_bans_site_ip ON dynamic_bans (site_id, client_ip);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dynamic_bans_application_listener_ip ON dynamic_bans (site_id, listener_port, scheme, client_ip);
CREATE INDEX IF NOT EXISTS idx_dynamic_bans_status ON dynamic_bans (status);
CREATE INDEX IF NOT EXISTS idx_dynamic_bans_expires_at ON dynamic_bans (expires_at);
CREATE INDEX IF NOT EXISTS idx_dynamic_bans_revision ON dynamic_bans (revision);

CREATE TABLE IF NOT EXISTS dynamic_ban_clears (
	id BIGSERIAL PRIMARY KEY,
	site_id BIGINT NOT NULL DEFAULT 0,
	listener_port INTEGER NOT NULL DEFAULT 0,
	scheme TEXT NOT NULL DEFAULT '',
	client_ip TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT '',
	revision BIGINT NOT NULL DEFAULT nextval('dynamic_ban_clear_revision_seq'),
	actor TEXT NOT NULL DEFAULT '',
	message TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dynamic_ban_clears_revision ON dynamic_ban_clears (revision);
CREATE INDEX IF NOT EXISTS idx_dynamic_ban_clears_site_ip ON dynamic_ban_clears (site_id, client_ip);
CREATE INDEX IF NOT EXISTS idx_dynamic_ban_clears_listener ON dynamic_ban_clears (site_id, listener_port, scheme, client_ip);

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
