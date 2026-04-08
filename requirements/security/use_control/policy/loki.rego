# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package services.loki

import rego.v1

# --- Invariant Profiles & Settings ---

# METADATA
# entrypoint: true
default env := "development"

# regal ignore:unresolved-reference
env := data.runtime.environment

env_profiles := {
	"development": {"retention": "2h", "reject_age": "24h"},
	"testing": {"retention": "8h", "reject_age": "168h"},
	"staging": {"retention": "24h", "reject_age": "168h"},
	"production": {"retention": "87600h", "reject_age": "168h"},
}

exact_matches := [
	{"path": ["analytics", "reporting_enabled"], "val": false},
	{"path": ["tracing", "enabled"], "val": true},
	{"path": ["auth_enabled"], "val": false},
	{"path": ["server", "http_listen_address"], "val": "::"},
	{"path": ["server", "http_listen_port"], "val": 3100},
	{"path": ["server", "grpc_listen_address"], "val": "::"},
	{"path": ["server", "grpc_listen_port"], "val": 9095},
	{"path": ["common", "instance_addr"], "val": "::1"},
	{"path": ["common", "storage", "filesystem", "chunks_directory"], "val": "/loki/chunks"},
	{"path": ["common", "storage", "filesystem", "rules_directory"], "val": "/loki/rules"},
	{"path": ["compactor", "retention_enabled"], "val": true},
	{"path": ["compactor", "delete_request_store"], "val": "filesystem"},
	{"path": ["limits_config", "reject_old_samples"], "val": true},
	{"path": ["limits_config", "unordered_writes"], "val": true},
	{"path": ["limits_config", "allow_structured_metadata"], "val": true},
	{"path": ["common", "ring", "kvstore", "store"], "val": "inmemory"},
	{"path": ["ingester", "lifecycler", "ring", "kvstore", "store"], "val": "inmemory"},
	{"path": ["distributor", "ring", "kvstore", "store"], "val": "inmemory"},
	{"path": ["ruler", "ring", "kvstore", "store"], "val": "inmemory"},
	{"path": ["server", "http_tls_config", "client_auth_type"], "val": "RequireAndVerifyClientCert"},
]

prefix_matches := [
	{"path": ["server", "http_tls_config", "cert_file"], "prefix": "/run/secrets/"},
	{"path": ["server", "http_tls_config", "key_file"], "prefix": "/run/secrets/"},
	{"path": ["server", "http_tls_config", "client_ca_file"], "prefix": "/run/secrets/"},
]

# Use object.get to fall back to conservative options if env is unknown.
duration_limits := [
	{
		"path": ["limits_config", "retention_period"],
		"max": object.get(env_profiles, env, {"retention": "87600h"}).retention,
	},
	{
		"path": ["limits_config", "reject_old_samples_max_age"],
		"max": object.get(env_profiles, env, {"reject_age": "168h"}).reject_age,
	},
]

# --- Core Policy Logic ---

is_loki_config if {
	input.server.http_listen_port
	input.common.path_prefix == "/loki"
	input.schema_config.configs
}

deny contains msg if {
	is_loki_config
	not env_profiles[env]
	msg := sprintf("loki: unknown environment %q", [env])
}

# 1. Exact Match Engine
deny contains msg if {
	is_loki_config
	some req in exact_matches
	err := check_exact(input, req.path, req.val)
	msg := sprintf("loki: %s %s", [concat(".", req.path), err])
}

# 2. Prefix Match Engine
deny contains msg if {
	is_loki_config
	some req in prefix_matches
	err := check_prefix(input, req.path, req.prefix)
	msg := sprintf("loki: %s %s", [concat(".", req.path), err])
}

# 3. Duration Limit Engine
deny contains msg if {
	is_loki_config
	some req in duration_limits
	err := check_duration(input, req.path, req.max)
	msg := sprintf("loki: %s %s", [concat(".", req.path), err])
}

# 4. IPv6 Clustering
deny contains msg if {
	is_loki_config
	not contains_value(object.get(input, "memberlist", {}), "bind_addr", "::")
	msg := "loki: memberlist.bind_addr must include \"::\""
}

# 5. Schema Integrity
deny contains msg if {
	is_loki_config
	not schema_valid
	msg := "loki: schema_config must include tsdb/filesystem schema v13 index 24h"
}

# --- Advisory Warnings ---

warn contains msg if {
	is_loki_config
	input.auth_enabled == false
	msg := "loki: auth_enabled=false without required mTLS; check exposure controls"
}

warn contains msg if {
	is_loki_config
	not input.server.grpc_tls_config
	input.server.grpc_listen_address == "::"
	msg := "loki: gRPC listens on :: without TLS; ensure it is not externally exposed"
}

# --- Evaluation Engines & Utilities ---

schema_valid if {
	some c in input.schema_config.configs
	c.store == "tsdb"
	c.object_store == "filesystem"
	c.schema == "v13"
	c.index.period == "24h"
}

check_exact(obj, parts, _) := "is missing" if {
	not path_exists(obj, parts)
}

check_exact(obj, parts, expected) := sprintf("must be %v (got %v)", [expected, path_value(obj, parts)]) if {
	path_exists(obj, parts)
	path_value(obj, parts) != expected
}

check_prefix(obj, parts, _) := "is missing" if {
	not path_exists(obj, parts)
}

check_prefix(obj, parts, prefix) := sprintf("must start with %q", [prefix]) if {
	path_exists(obj, parts)
	not startswith(path_value(obj, parts), prefix)
}

check_duration(obj, parts, _) := "is missing" if {
	not path_exists(obj, parts)
}

check_duration(obj, parts, _) := "must be a valid duration string" if {
	path_exists(obj, parts)
	not is_simple_duration(path_value(obj, parts))
}

check_duration(obj, parts, max_dur) := sprintf("must be <= %s", [max_dur]) if {
	path_exists(obj, parts)
	val := path_value(obj, parts)
	is_simple_duration(val)
	duration_ns(val) > duration_ns(max_dur)
}

path_exists(obj, parts) if {
	walk(obj, [p, _])
	p == parts
}

path_value(obj, parts) := val if {
	walk(obj, [p, val])
	p == parts
}

contains_value(obj, key, val) if {
	arr := object.get(obj, key, [])
	some x in arr
	x == val
}

is_simple_duration(s) if {
	is_string(s)
	s != ""
	regex.match(`^[0-9]+(ns|us|µs|ms|s|m|h|d|w)$`, s)
}

duration_ns(s) := time.parse_duration_ns(s) if {
	is_simple_duration(s)
}
