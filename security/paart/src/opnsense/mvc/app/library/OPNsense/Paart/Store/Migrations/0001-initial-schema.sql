-- Copyright (C) 2026 Lux-World PC SARL
--
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions are met:
--
-- 1. Redistributions of source code must retain the above copyright notice,
--    this list of conditions and the following disclaimer.
--
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
-- INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
-- AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
-- AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
-- OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-- SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-- INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-- CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-- ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.

-- Migration 0001 — initial schema (M02, docs/specs/02-donnees-persistance.md).
--
-- Conventions: ULID primary keys (TEXT, 26 chars); timestamps TEXT, UTC,
-- RFC 3339 'YYYY-MM-DDTHH:MM:SSZ'; booleans INTEGER 0/1; *_json columns hold
-- JSON documents. Secrets are stored HASHED ONLY (token_hash columns); no
-- WireGuard private key has any column here, by design (forbidden rule #1).
--
-- The schema_meta table is created and maintained by the Migrator itself.
--
-- Note on `instances`: the authoritative declaration of a managed instance
-- lives in config.xml (M02 separation rule — included in OPNsense config
-- backups). This table mirrors each declared instance under a stable ULID so
-- that operational state can reference it with real foreign keys; it is
-- written only when a declaration is created or updated.
--
-- Foreign keys deliberately RESTRICT: deleting a declared instance or a user
-- must never silently cascade into devices, allocations or tokens (M02
-- acceptance: no deletion without explicit intent).

CREATE TABLE instances (
  id                  TEXT PRIMARY KEY,
  wg_instance_ref     TEXT NOT NULL UNIQUE,  -- os-wireguard server uuid (verified V3)
  label               TEXT NOT NULL,
  endpoint            TEXT NOT NULL,         -- host:port published in bundles
  ip_range_cidr       TEXT NOT NULL,         -- contained in a single /24 (ADR 0005)
  pool_start_octet    INTEGER NOT NULL CHECK (pool_start_octet BETWEEN 1 AND 254),
  pool_end_octet      INTEGER NOT NULL CHECK (pool_end_octet BETWEEN 1 AND 254),
  dns_servers_json    TEXT NOT NULL DEFAULT '[]',
  match_domains_json  TEXT NOT NULL DEFAULT '[]',
  allow_full_tunnel   INTEGER NOT NULL DEFAULT 0,
  allow_subnet_toggle INTEGER NOT NULL DEFAULT 0,
  enabled             INTEGER NOT NULL DEFAULT 1,
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL,
  CHECK (pool_end_octet >= pool_start_octet)
);

CREATE TABLE users (
  id           TEXT PRIMARY KEY,
  slug         TEXT NOT NULL UNIQUE,          -- [a-z0-9-]{2,32}, validated in domain (M03)
  display_name TEXT NOT NULL,
  email        TEXT,
  external_ref TEXT,                          -- reserved for AD/LDAP (v2), keep empty
  status       TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

CREATE TABLE devices (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
  label             TEXT NOT NULL,
  platform          TEXT NOT NULL CHECK
                    (platform IN ('ios', 'ipados', 'macos', 'windows', 'linux', 'android', 'other')),
  management_level  TEXT NOT NULL CHECK (management_level IN ('full', 'manual')),
  instance_id       TEXT NOT NULL REFERENCES instances (id) ON DELETE RESTRICT,
  public_key        TEXT NOT NULL,            -- reconciliation key; unique PER INSTANCE
  ip_host_octet     INTEGER NOT NULL CHECK (ip_host_octet BETWEEN 1 AND 254),
  ip_address        TEXT NOT NULL,
  device_token_hash TEXT NOT NULL,            -- API token, hashed only
  status            TEXT NOT NULL CHECK (status IN ('pending', 'active', 'rotating', 'revoked')),
  enrolled_at       TEXT NOT NULL,
  last_seen_at      TEXT,
  last_handshake_at TEXT,
  key_created_at    TEXT NOT NULL,            -- feeds the future "key age" report
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  UNIQUE (instance_id, public_key)
);

CREATE INDEX idx_devices_user_id     ON devices (user_id);
CREATE INDEX idx_devices_instance_id ON devices (instance_id);

CREATE TABLE enroll_tokens (
  id          TEXT PRIMARY KEY,
  user_id     TEXT REFERENCES users (id) ON DELETE RESTRICT,
  token_hash  TEXT NOT NULL UNIQUE,
  label       TEXT NOT NULL,
  instance_id TEXT NOT NULL REFERENCES instances (id) ON DELETE RESTRICT,
  max_uses    INTEGER NOT NULL DEFAULT 1,
  used_count  INTEGER NOT NULL DEFAULT 0,
  expires_at  TEXT NOT NULL,
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  consumed_at TEXT
);

CREATE INDEX idx_enroll_tokens_instance_id ON enroll_tokens (instance_id);

CREATE TABLE ip_allocations (
  instance_id     TEXT NOT NULL REFERENCES instances (id) ON DELETE RESTRICT,
  host_octet      INTEGER NOT NULL CHECK (host_octet BETWEEN 1 AND 254),
  device_id       TEXT REFERENCES devices (id) ON DELETE RESTRICT,
  reserved_reason TEXT,                       -- non-device holds: infra, manual peer, quarantine
  allocated_at    TEXT NOT NULL,
  released_at     TEXT,                       -- start of the quarantine window (M03)
  PRIMARY KEY (instance_id, host_octet)
);

CREATE TABLE rotations (
  id             TEXT PRIMARY KEY,
  device_id      TEXT NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
  old_public_key TEXT NOT NULL,
  new_public_key TEXT,
  state          TEXT NOT NULL CHECK (state IN ('pending', 'applied', 'confirmed', 'failed', 'expired')),
  requested_at   TEXT NOT NULL,
  applied_at     TEXT,
  confirmed_at   TEXT,
  grace_until    TEXT NOT NULL
);

CREATE INDEX idx_rotations_device_id ON rotations (device_id);

-- Audit log lives here, never in config.xml (forbidden rule #2).
CREATE TABLE audit_log (
  id           TEXT PRIMARY KEY,
  occurred_at  TEXT NOT NULL,
  actor_type   TEXT NOT NULL CHECK (actor_type IN ('admin', 'device', 'system')),
  actor_ref    TEXT NOT NULL,
  action       TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_ref  TEXT NOT NULL,
  outcome      TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  detail_json  TEXT NOT NULL DEFAULT '{}',
  source_ip    TEXT
);

CREATE INDEX idx_audit_log_occurred_at ON audit_log (occurred_at);

CREATE TABLE hosts (
  id          TEXT PRIMARY KEY,
  instance_id TEXT NOT NULL REFERENCES instances (id) ON DELETE RESTRICT,
  label       TEXT NOT NULL,
  address     TEXT NOT NULL,
  probe_port  INTEGER,
  sort_order  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE subnets (
  id          TEXT PRIMARY KEY,
  instance_id TEXT NOT NULL REFERENCES instances (id) ON DELETE RESTRICT,
  label       TEXT NOT NULL,
  cidr        TEXT NOT NULL,
  default_on  INTEGER NOT NULL DEFAULT 0,
  sort_order  INTEGER NOT NULL DEFAULT 0
);
