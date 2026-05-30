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

INSERT INTO rules (name, type, target, action, expression, score, enabled)
SELECT 'MVP SQLi baseline', 'sqli', 'args', 'block', '(?i)(union\s+select|or\s+1=1|sleep\s*\()', 80, true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'MVP SQLi baseline');

INSERT INTO rules (name, type, target, action, expression, score, enabled)
SELECT 'MVP XSS baseline', 'xss', 'args', 'block', '(?i)(<script|javascript:|onerror\s*=)', 80, true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'MVP XSS baseline');
