# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package services.loki_test

import data.services.loki
import rego.v1

# --- MOCK DATA ---
valid_input := {
	"server": {
		"http_listen_port": 3100,
		"http_listen_address": "::",
		"grpc_listen_port": 9095,
		"grpc_listen_address": "::",
		"http_tls_config": {
			"client_auth_type": "RequireAndVerifyClientCert",
			"cert_file": "/run/secrets/loki.crt",
			"key_file": "/run/secrets/loki.key",
			"client_ca_file": "/run/secrets/ca.crt",
		},
	},
	"common": {
		"path_prefix": "/loki",
		"instance_addr": "::1",
		"storage": {"filesystem": {
			"chunks_directory": "/loki/chunks",
			"rules_directory": "/loki/rules",
		}},
		"ring": {"kvstore": {"store": "inmemory"}},
	},
	"schema_config": {"configs": [{
		"store": "tsdb",
		"object_store": "filesystem",
		"schema": "v13",
		"index": {"period": "24h"},
	}]},
	"analytics": {"reporting_enabled": false},
	"tracing": {"enabled": true},
	"auth_enabled": false,
	"compactor": {"retention_enabled": true, "delete_request_store": "filesystem"},
	"limits_config": {
		"reject_old_samples": true,
		"unordered_writes": true,
		"allow_structured_metadata": true,
		"retention_period": "2h",
		"reject_old_samples_max_age": "24h",
	},
	"ingester": {"lifecycler": {"ring": {"kvstore": {"store": "inmemory"}}}},
	"distributor": {"ring": {"kvstore": {"store": "inmemory"}}},
	"ruler": {"ring": {"kvstore": {"store": "inmemory"}}},
	"memberlist": {"bind_addr": ["::"]},
}

# --- TESTS ---

test_golden_config_passes if {
	count(loki.deny) == 0 with input as valid_input
		# regal ignore:unresolved-reference
with 		data.runtime.environment as "development"
}

test_deny_unknown_environment if {
	msg := loki.deny with input as valid_input
		# regal ignore:unresolved-reference
with 		data.runtime.environment as "outer_space"
	msg["loki: unknown environment \"outer_space\""]
}

test_deny_invalid_http_port if {
	bad_input := object.union(valid_input, {"server": {"http_listen_port": 8080}})
	msg := loki.deny with input as bad_input
	msg["loki: server.http_listen_port must be 3100 (got 8080)"]
}

test_deny_insecure_cert_path if {
	bad_input := json.patch(valid_input, [{
		"op": "replace",
		"path": "/server/http_tls_config/cert_file",
		"value": "/tmp/loki.crt",
	}])
	msg := loki.deny with input as bad_input
	msg["loki: server.http_tls_config.cert_file must start with \"/run/secrets/\""]
}

test_production_retention_enforcement if {
	prod_input := json.patch(valid_input, [{
		"op": "replace",
		"path": "/limits_config/retention_period",
		"value": "90000h",
	}])
	msg := loki.deny with input as prod_input
		# regal ignore:unresolved-reference
with 		data.runtime.environment as "production"
	msg["loki: limits_config.retention_period must be <= 87600h"]
}

test_development_retention_fail_if_exceeded if {
	bad_input := json.patch(valid_input, [{
		"op": "replace",
		"path": "/limits_config/retention_period",
		"value": "5h",
	}])
	msg := loki.deny with input as bad_input
		# regal ignore:unresolved-reference
with 		data.runtime.environment as "development"
	msg["loki: limits_config.retention_period must be <= 2h"]
}

test_deny_missing_ipv6_bind if {
	bad_input := object.union(valid_input, {"memberlist": {"bind_addr": ["127.0.0.1"]}})
	msg := loki.deny with input as bad_input
	msg["loki: memberlist.bind_addr must include \"::\""]
}

test_warn_auth_disabled if {
	msg := loki.warn with input as valid_input
	msg["loki: auth_enabled=false without required mTLS; check exposure controls"]
}
