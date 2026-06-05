package store

const schemaSQL = `
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
	module TEXT NOT NULL DEFAULT '',
	category TEXT NOT NULL DEFAULT '',
	attack_type TEXT NOT NULL DEFAULT '',
	group_name TEXT NOT NULL DEFAULT '',
	priority INTEGER NOT NULL DEFAULT 100,
	package_id TEXT NOT NULL DEFAULT '',
	package_version TEXT NOT NULL DEFAULT '',
	package_rule_id TEXT NOT NULL DEFAULT '',
	source_checksum TEXT NOT NULL DEFAULT '',
	signature_status TEXT NOT NULL DEFAULT '',
	review_status TEXT NOT NULL DEFAULT '',
	last_test_status TEXT NOT NULL DEFAULT '',
	remote_catalog_id TEXT NOT NULL DEFAULT '',
	last_synced_version TEXT NOT NULL DEFAULT '',
	pending_update_state TEXT NOT NULL DEFAULT '',
	local_override_state TEXT NOT NULL DEFAULT '',
	export_eligible BOOLEAN NOT NULL DEFAULT false,
	export_ineligible_reasons TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE rules ADD COLUMN IF NOT EXISTS module TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS attack_type TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS group_name TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 100;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS package_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS package_version TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS package_rule_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS source_checksum TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS signature_status TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS review_status TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS last_test_status TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS remote_catalog_id TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS provider_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS provider_name TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS provider_package_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS last_synced_version TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS pending_update_state TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS local_override_state TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS export_eligible BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS export_ineligible_reasons TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS policies (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	risk_threshold INTEGER NOT NULL DEFAULT 100,
	default_action TEXT NOT NULL DEFAULT 'block',
	normalization_enabled BOOLEAN NOT NULL DEFAULT true,
	normalization_decode_passes INTEGER NOT NULL DEFAULT 2,
	normalization_max_value_bytes INTEGER NOT NULL DEFAULT 4096,
	body_inspection_enabled BOOLEAN NOT NULL DEFAULT false,
	body_inspection_content_types TEXT NOT NULL DEFAULT '',
	body_inspection_path_prefixes TEXT NOT NULL DEFAULT '',
	body_inspection_max_bytes INTEGER NOT NULL DEFAULT 65536,
	oversized_body_action TEXT NOT NULL DEFAULT 'log-only',
	upload_inspection_enabled BOOLEAN NOT NULL DEFAULT false,
	upload_max_bytes INTEGER NOT NULL DEFAULT 10485760,
	upload_size_action TEXT NOT NULL DEFAULT 'block',
	dynamic_ban_enabled BOOLEAN NOT NULL DEFAULT false,
	dynamic_ban_duration_sec INTEGER NOT NULL DEFAULT 300,
	dynamic_ban_score_threshold INTEGER NOT NULL DEFAULT 200,
	dynamic_ban_trigger_count INTEGER NOT NULL DEFAULT 3,
	dynamic_ban_window_sec INTEGER NOT NULL DEFAULT 60,
	enabled BOOLEAN NOT NULL DEFAULT true,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE policies ADD COLUMN IF NOT EXISTS normalization_enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS normalization_decode_passes INTEGER NOT NULL DEFAULT 2;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS normalization_max_value_bytes INTEGER NOT NULL DEFAULT 4096;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS body_inspection_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS body_inspection_content_types TEXT NOT NULL DEFAULT '';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS body_inspection_path_prefixes TEXT NOT NULL DEFAULT '';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS body_inspection_max_bytes INTEGER NOT NULL DEFAULT 65536;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS oversized_body_action TEXT NOT NULL DEFAULT 'log-only';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS upload_inspection_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS upload_max_bytes INTEGER NOT NULL DEFAULT 10485760;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS upload_size_action TEXT NOT NULL DEFAULT 'block';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS dynamic_ban_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS dynamic_ban_duration_sec INTEGER NOT NULL DEFAULT 300;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS dynamic_ban_score_threshold INTEGER NOT NULL DEFAULT 200;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS dynamic_ban_trigger_count INTEGER NOT NULL DEFAULT 3;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS dynamic_ban_window_sec INTEGER NOT NULL DEFAULT 60;

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
	module TEXT NOT NULL DEFAULT '',
	category TEXT NOT NULL DEFAULT '',
	rule_name TEXT NOT NULL DEFAULT '',
	attack_type TEXT NOT NULL DEFAULT '',
	group_name TEXT NOT NULL DEFAULT '',
	counter TEXT NOT NULL DEFAULT '',
	window_sec INTEGER NOT NULL DEFAULT 0,
	advanced_target TEXT NOT NULL DEFAULT '',
	normalized_value TEXT NOT NULL DEFAULT '',
	score INTEGER NOT NULL DEFAULT 0,
	threshold INTEGER NOT NULL DEFAULT 0,
	matched_rule_ids TEXT NOT NULL DEFAULT '',
	body_metadata TEXT NOT NULL DEFAULT '',
	upload_metadata TEXT NOT NULL DEFAULT '',
	ban_reason TEXT NOT NULL DEFAULT '',
	ban_duration_sec INTEGER NOT NULL DEFAULT 0,
	ban_remaining_sec INTEGER NOT NULL DEFAULT 0,
	challenge_mode TEXT NOT NULL DEFAULT '',
	challenge_result TEXT NOT NULL DEFAULT '',
	bot_result TEXT NOT NULL DEFAULT '',
	bot_reason TEXT NOT NULL DEFAULT '',
	device_signal TEXT NOT NULL DEFAULT '',
	package_id TEXT NOT NULL DEFAULT '',
	package_version TEXT NOT NULL DEFAULT '',
	package_rule_id TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS module TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS rule_name TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS attack_type TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS group_name TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS counter TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS window_sec INTEGER NOT NULL DEFAULT 0;

ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS advanced_target TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS normalized_value TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS threshold INTEGER NOT NULL DEFAULT 0;
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS matched_rule_ids TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS body_metadata TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS upload_metadata TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS ban_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS ban_duration_sec INTEGER NOT NULL DEFAULT 0;
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS ban_remaining_sec INTEGER NOT NULL DEFAULT 0;
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS challenge_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS challenge_result TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS bot_result TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS bot_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS device_signal TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS package_id TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS package_version TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS package_rule_id TEXT NOT NULL DEFAULT '';

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
	match_operator TEXT NOT NULL DEFAULT '',
	header_name TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL,
	site_id BIGINT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT true,
	priority INTEGER NOT NULL DEFAULT 100,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE access_list_entries ADD COLUMN IF NOT EXISTS match_operator TEXT NOT NULL DEFAULT '';
ALTER TABLE access_list_entries ADD COLUMN IF NOT EXISTS header_name TEXT NOT NULL DEFAULT '';
ALTER TABLE access_list_entries ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 100;

CREATE TABLE IF NOT EXISTS rate_limit_rules (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	scope TEXT NOT NULL,
	match_value TEXT NOT NULL DEFAULT '',
	threshold INTEGER NOT NULL,
	window_sec INTEGER NOT NULL,
	action TEXT NOT NULL,
	ban_duration_sec INTEGER NOT NULL DEFAULT 0,
	violation_threshold INTEGER NOT NULL DEFAULT 0,
	violation_window_sec INTEGER NOT NULL DEFAULT 0,
	site_id BIGINT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT true,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE rate_limit_rules ADD COLUMN IF NOT EXISTS violation_threshold INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rate_limit_rules ADD COLUMN IF NOT EXISTS violation_window_sec INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rate_limit_rules ADD COLUMN IF NOT EXISTS path_match TEXT NOT NULL DEFAULT '';
ALTER TABLE rate_limit_rules ADD COLUMN IF NOT EXISTS methods TEXT NOT NULL DEFAULT '';
ALTER TABLE rate_limit_rules ADD COLUMN IF NOT EXISTS cc_action TEXT NOT NULL DEFAULT '';

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

ALTER TABLE upload_protection_rules ADD COLUMN IF NOT EXISTS methods TEXT NOT NULL DEFAULT '';
ALTER TABLE upload_protection_rules ADD COLUMN IF NOT EXISTS extensions TEXT NOT NULL DEFAULT '';
ALTER TABLE upload_protection_rules ADD COLUMN IF NOT EXISTS max_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE upload_protection_rules ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 100;

CREATE TABLE IF NOT EXISTS bot_protection_rules (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	path TEXT NOT NULL DEFAULT '/',
	path_match TEXT NOT NULL DEFAULT 'prefix',
	methods TEXT NOT NULL DEFAULT '',
	challenge_mode TEXT NOT NULL DEFAULT 'js-challenge',
	verify_ttl_sec INTEGER NOT NULL DEFAULT 300,
	failure_action TEXT NOT NULL DEFAULT 'block',
	site_id BIGINT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT true,
	priority INTEGER NOT NULL DEFAULT 100,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE bot_protection_rules ADD COLUMN IF NOT EXISTS methods TEXT NOT NULL DEFAULT '';
ALTER TABLE bot_protection_rules ADD COLUMN IF NOT EXISTS challenge_mode TEXT NOT NULL DEFAULT 'js-challenge';
ALTER TABLE bot_protection_rules ADD COLUMN IF NOT EXISTS verify_ttl_sec INTEGER NOT NULL DEFAULT 300;
ALTER TABLE bot_protection_rules ADD COLUMN IF NOT EXISTS failure_action TEXT NOT NULL DEFAULT 'block';
ALTER TABLE bot_protection_rules ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 100;

CREATE TABLE IF NOT EXISTS dynamic_protection_rules (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	category TEXT NOT NULL DEFAULT 'dynamic-token',
	path TEXT NOT NULL DEFAULT '/',
	path_match TEXT NOT NULL DEFAULT 'prefix',
	methods TEXT NOT NULL DEFAULT '',
	token_ttl_sec INTEGER NOT NULL DEFAULT 300,
	token_placement TEXT NOT NULL DEFAULT 'cookie',
	failure_action TEXT NOT NULL DEFAULT 'block',
	mutation_marker TEXT NOT NULL DEFAULT 'body-end',
	mutation_max_bytes INTEGER NOT NULL DEFAULT 262144,
	queue_capacity INTEGER NOT NULL DEFAULT 100,
	admission_ttl_sec INTEGER NOT NULL DEFAULT 300,
	retry_interval_sec INTEGER NOT NULL DEFAULT 5,
	overflow_action TEXT NOT NULL DEFAULT 'waiting-room',
	site_id BIGINT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT true,
	priority INTEGER NOT NULL DEFAULT 100,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'dynamic-token';
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS methods TEXT NOT NULL DEFAULT '';
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS token_ttl_sec INTEGER NOT NULL DEFAULT 300;
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS token_placement TEXT NOT NULL DEFAULT 'cookie';
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS failure_action TEXT NOT NULL DEFAULT 'block';
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS mutation_marker TEXT NOT NULL DEFAULT 'body-end';
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS mutation_max_bytes INTEGER NOT NULL DEFAULT 262144;
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS queue_capacity INTEGER NOT NULL DEFAULT 100;
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS admission_ttl_sec INTEGER NOT NULL DEFAULT 300;
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS retry_interval_sec INTEGER NOT NULL DEFAULT 5;
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS overflow_action TEXT NOT NULL DEFAULT 'waiting-room';
ALTER TABLE dynamic_protection_rules ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 100;

CREATE TABLE IF NOT EXISTS protection_rules (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	module TEXT NOT NULL,
	category TEXT NOT NULL,
	site_id BIGINT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT true,
	priority INTEGER NOT NULL DEFAULT 100,
	match_json JSONB NOT NULL DEFAULT '{}'::jsonb,
	limit_json JSONB NOT NULL DEFAULT '{}'::jsonb,
	upload_json JSONB,
	challenge_json JSONB,
	dynamic_json JSONB,
	action_json JSONB NOT NULL DEFAULT '{}'::jsonb,
	source TEXT NOT NULL DEFAULT 'protection_rules',
	migration_status TEXT NOT NULL DEFAULT 'native',
	legacy_ref TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE protection_rules ADD COLUMN IF NOT EXISTS match_json JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE protection_rules ADD COLUMN IF NOT EXISTS limit_json JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE protection_rules ADD COLUMN IF NOT EXISTS upload_json JSONB;
ALTER TABLE protection_rules ADD COLUMN IF NOT EXISTS challenge_json JSONB;
ALTER TABLE protection_rules ADD COLUMN IF NOT EXISTS dynamic_json JSONB;
ALTER TABLE protection_rules ADD COLUMN IF NOT EXISTS action_json JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE protection_rules ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'protection_rules';
ALTER TABLE protection_rules ADD COLUMN IF NOT EXISTS migration_status TEXT NOT NULL DEFAULT 'native';
ALTER TABLE protection_rules ADD COLUMN IF NOT EXISTS legacy_ref TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_protection_rules_legacy_ref ON protection_rules (legacy_ref) WHERE legacy_ref <> '';
CREATE INDEX IF NOT EXISTS idx_protection_rules_module ON protection_rules (module, category);
CREATE INDEX IF NOT EXISTS idx_protection_rules_site_id ON protection_rules (site_id);

CREATE TABLE IF NOT EXISTS rule_catalog_sources (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	source TEXT NOT NULL,
	provider_id BIGINT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT true,
	timeout_sec INTEGER NOT NULL DEFAULT 5,
	status TEXT NOT NULL DEFAULT 'never-synced',
	last_sync_at TIMESTAMPTZ,
	last_error TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE rule_catalog_sources ADD COLUMN IF NOT EXISTS provider_id BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS rule_catalog_packages (
	id BIGSERIAL PRIMARY KEY,
	catalog_id BIGINT NOT NULL REFERENCES rule_catalog_sources(id) ON DELETE CASCADE,
	provider_id BIGINT NOT NULL DEFAULT 0,
	provider_name TEXT NOT NULL DEFAULT '',
	provider_package_ref TEXT NOT NULL DEFAULT '',
	entitlement_state TEXT NOT NULL DEFAULT '',
	package_id TEXT NOT NULL,
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	compatibility TEXT NOT NULL DEFAULT '',
	checksum TEXT NOT NULL DEFAULT '',
	signature_key_id TEXT NOT NULL DEFAULT '',
	signature_checksum TEXT NOT NULL DEFAULT '',
	signature_value TEXT NOT NULL DEFAULT '',
	signature_expires_at TEXT NOT NULL DEFAULT '',
	signature_status TEXT NOT NULL DEFAULT '',
	updated_at_text TEXT NOT NULL DEFAULT '',
	manifest_url TEXT NOT NULL DEFAULT '',
	package_json TEXT NOT NULL DEFAULT '',
	source_identity TEXT NOT NULL DEFAULT '',
	sync_status TEXT NOT NULL DEFAULT 'synced',
	stale BOOLEAN NOT NULL DEFAULT false,
	last_synced_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (catalog_id, package_id)
);

ALTER TABLE rule_catalog_packages ADD COLUMN IF NOT EXISTS provider_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE rule_catalog_packages ADD COLUMN IF NOT EXISTS provider_name TEXT NOT NULL DEFAULT '';
ALTER TABLE rule_catalog_packages ADD COLUMN IF NOT EXISTS provider_package_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE rule_catalog_packages ADD COLUMN IF NOT EXISTS entitlement_state TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS rule_provider_adapters (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	provider_type TEXT NOT NULL,
	endpoint TEXT NOT NULL,
	auth_mode TEXT NOT NULL DEFAULT 'none',
	enabled BOOLEAN NOT NULL DEFAULT true,
	timeout_sec INTEGER NOT NULL DEFAULT 5,
	retry_max_attempts INTEGER NOT NULL DEFAULT 3,
	retry_backoff_sec INTEGER NOT NULL DEFAULT 60,
	credential_alias TEXT NOT NULL DEFAULT '',
	credential_fingerprint TEXT NOT NULL DEFAULT '',
	credential_last_four TEXT NOT NULL DEFAULT '',
	credential_expires_at TIMESTAMPTZ NULL,
	credential_last_validated_at TIMESTAMPTZ NULL,
	credential_status TEXT NOT NULL DEFAULT '',
	credential_secret TEXT NOT NULL DEFAULT '',
	health_status TEXT NOT NULL DEFAULT 'never-synced',
	sync_status TEXT NOT NULL DEFAULT 'never-synced',
	last_sync_at TIMESTAMPTZ NULL,
	last_failed_sync_at TIMESTAMPTZ NULL,
	last_error TEXT NOT NULL DEFAULT '',
	attempt_count INTEGER NOT NULL DEFAULT 0,
	next_retry_at TIMESTAMPTZ NULL,
	retry_exhausted BOOLEAN NOT NULL DEFAULT false,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_provider_packages (
	id BIGSERIAL PRIMARY KEY,
	provider_id BIGINT NOT NULL REFERENCES rule_provider_adapters(id) ON DELETE CASCADE,
	provider_package_ref TEXT NOT NULL,
	package_id TEXT NOT NULL,
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	compatibility TEXT NOT NULL,
	checksum TEXT NOT NULL,
	signature_key_id TEXT NOT NULL DEFAULT '',
	signature_checksum TEXT NOT NULL DEFAULT '',
	signature_value TEXT NOT NULL DEFAULT '',
	signature_expires_at TEXT NOT NULL DEFAULT '',
	signature_status TEXT NOT NULL DEFAULT '',
	updated_at_text TEXT NOT NULL DEFAULT '',
	manifest_url TEXT NOT NULL DEFAULT '',
	package_json TEXT NOT NULL DEFAULT '',
	source_identity TEXT NOT NULL DEFAULT '',
	entitlement_state TEXT NOT NULL DEFAULT '',
	sync_status TEXT NOT NULL DEFAULT '',
	stale BOOLEAN NOT NULL DEFAULT false,
	last_synced_at TIMESTAMPTZ NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE(provider_id, package_id)
);

CREATE TABLE IF NOT EXISTS rule_trust_keys (
	id BIGSERIAL PRIMARY KEY,
	key_id TEXT NOT NULL UNIQUE,
	algorithm TEXT NOT NULL,
	owner TEXT NOT NULL DEFAULT '',
	public_key TEXT NOT NULL DEFAULT '',
	enabled BOOLEAN NOT NULL DEFAULT true,
	revoked BOOLEAN NOT NULL DEFAULT false,
	expires_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_community_account_sources (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	provider_type TEXT NOT NULL,
	provider_adapter_id BIGINT NOT NULL DEFAULT 0,
	endpoint TEXT NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT true,
	timeout_sec INTEGER NOT NULL DEFAULT 5,
	credential_alias TEXT NOT NULL DEFAULT '',
	credential_fingerprint TEXT NOT NULL DEFAULT '',
	credential_last_four TEXT NOT NULL DEFAULT '',
	credential_expires_at TIMESTAMPTZ,
	credential_last_validated_at TIMESTAMPTZ,
	credential_status TEXT NOT NULL DEFAULT 'not-configured',
	credential_secret TEXT NOT NULL DEFAULT '',
	subscription_status TEXT NOT NULL DEFAULT 'unknown',
	entitlement_summary TEXT NOT NULL DEFAULT '',
	package_count INTEGER NOT NULL DEFAULT 0,
	status TEXT NOT NULL DEFAULT 'never-synced',
	last_sync_at TIMESTAMPTZ,
	last_error TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE rule_community_account_sources ADD COLUMN IF NOT EXISTS provider_adapter_id BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS rule_contribution_targets (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	provider TEXT NOT NULL,
	endpoint TEXT NOT NULL,
	channel TEXT NOT NULL DEFAULT '',
	enabled BOOLEAN NOT NULL DEFAULT true,
	credential_alias TEXT NOT NULL DEFAULT '',
	credential_fingerprint TEXT NOT NULL DEFAULT '',
	credential_last_four TEXT NOT NULL DEFAULT '',
	credential_expires_at TIMESTAMPTZ,
	credential_last_validated_at TIMESTAMPTZ,
	credential_status TEXT NOT NULL DEFAULT 'not-configured',
	credential_secret TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'ready',
	last_push_at TIMESTAMPTZ,
	last_error TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_contribution_push_attempts (
	id BIGSERIAL PRIMARY KEY,
	target_id BIGINT NOT NULL DEFAULT 0,
	target_name TEXT NOT NULL DEFAULT '',
	package_id TEXT NOT NULL DEFAULT '',
	package_version TEXT NOT NULL DEFAULT '',
	checksum TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT '',
	remote_reference TEXT NOT NULL DEFAULT '',
	error TEXT NOT NULL DEFAULT '',
	actor TEXT NOT NULL DEFAULT '',
	preview_only BOOLEAN NOT NULL DEFAULT false,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_review_queue (
	id BIGSERIAL PRIMARY KEY,
	item_type TEXT NOT NULL,
	package_id TEXT NOT NULL DEFAULT '',
	package_version TEXT NOT NULL DEFAULT '',
	current_version TEXT NOT NULL DEFAULT '',
	source_identity TEXT NOT NULL DEFAULT '',
	recommendation TEXT NOT NULL DEFAULT '',
	risk_summary TEXT NOT NULL DEFAULT '',
	signature_status TEXT NOT NULL DEFAULT '',
	compatibility_status TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL DEFAULT 'queued',
	decision_reason TEXT NOT NULL DEFAULT '',
	actor TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_feedback (
	id BIGSERIAL PRIMARY KEY,
	rule_id BIGINT NOT NULL DEFAULT 0,
	package_id TEXT NOT NULL DEFAULT '',
	package_rule_id TEXT NOT NULL DEFAULT '',
	attack_log_id BIGINT NOT NULL DEFAULT 0,
	reason TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT '',
	redacted_sample TEXT NOT NULL DEFAULT '',
	actor TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_feedback_suggestions (
	id BIGSERIAL PRIMARY KEY,
	feedback_id BIGINT NOT NULL DEFAULT 0,
	rule_id BIGINT NOT NULL DEFAULT 0,
	proposed_change TEXT NOT NULL DEFAULT '',
	risk_warning TEXT NOT NULL DEFAULT '',
	confidence TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL DEFAULT '',
	test_result TEXT NOT NULL DEFAULT '',
	actor TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO rules (name, type, target, action, expression, score, enabled, module, category, attack_type, group_name, priority)
SELECT 'LiteWaf SQLi baseline', 'sqli', 'args', 'block', '(?i)(union\s+select|or\s+1=1|sleep\s*\(|benchmark\s*\()', 80, true, 'attack-protection', 'managed', 'sqli', 'SQL 注入防护', 100
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LiteWaf SQLi baseline');

INSERT INTO rules (name, type, target, action, expression, score, enabled, module, category, attack_type, group_name, priority)
SELECT 'LiteWaf XSS baseline', 'xss', 'args', 'block', '(?i)(<script|javascript:|onerror\s*=|onload\s*=)', 80, true, 'attack-protection', 'managed', 'xss', 'XSS 防护', 110
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LiteWaf XSS baseline');

INSERT INTO rules (name, type, target, action, expression, score, enabled, module, category, attack_type, group_name, priority)
SELECT 'LiteWaf RCE baseline', 'rce', 'args', 'block', '(?i)(;\s*(cat|curl|wget|bash|sh)\b|\|\s*(bash|sh)\b|\$\(|/bin/(bash|sh))', 90, true, 'attack-protection', 'managed', 'rce', 'RCE 防护', 120
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LiteWaf RCE baseline');

INSERT INTO rules (name, type, target, action, expression, score, enabled, module, category, attack_type, group_name, priority)
SELECT 'LiteWaf normalized traversal baseline', 'path-traversal', 'normalized_path', 'block', '(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self/environ)', 70, true, 'attack-protection', 'managed', 'path-traversal', '路径穿越防护', 130
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'LiteWaf normalized traversal baseline');

UPDATE rules SET module = 'attack-protection', category = 'managed', attack_type = 'sqli', group_name = 'SQL 注入防护', priority = 100 WHERE name = 'LiteWaf SQLi baseline';
UPDATE rules SET module = 'attack-protection', category = 'managed', attack_type = 'xss', group_name = 'XSS 防护', priority = 110 WHERE name = 'LiteWaf XSS baseline';
UPDATE rules SET module = 'attack-protection', category = 'managed', attack_type = 'rce', group_name = 'RCE 防护', priority = 120 WHERE name = 'LiteWaf RCE baseline';
UPDATE rules SET type = 'path-traversal', target = 'normalized_path', module = 'attack-protection', category = 'managed', attack_type = 'path-traversal', group_name = '路径穿越防护', priority = 130 WHERE name = 'LiteWaf normalized traversal baseline';
`
