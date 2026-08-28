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

-- Migration 0004 — redact full public keys from historical audit entries
-- (M07: the journal stores key FINGERPRINTS — first 8 characters + '…' —
-- never a complete key, so it is useless as a collection source).
--
-- Entries written before M07 landed carried full keys in detail_json;
-- every writer now fingerprints at the source (PublicKey::fingerprint).
-- This is the plugin's only rewriting of audit entries, ever: it REMOVES
-- key material the spec forbids, it adds and alters nothing else, and
-- the Migrator snapshots the database before applying it (M02 rule for
-- destructive migrations). The key redactions only touch values still at
-- the full 44-character length; the report statement below relies on the
-- schema-version gate alone (post-M07 reports also carry '$.report',
-- already fingerprinted — this file must never run against them).
--
-- reconcile.report entries embedded whole findings dumps (keys at
-- arbitrary nesting): their detail is replaced by a redaction notice.
-- No known store holds any — the shape had never fired on the bench —
-- and the entry itself (that drift was detected, when) survives.

UPDATE audit_log SET detail_json = json_set(detail_json, '$.public_key',
    substr(json_extract(detail_json, '$.public_key'), 1, 8) || '…')
 WHERE length(json_extract(detail_json, '$.public_key')) = 44;

UPDATE audit_log SET detail_json = json_set(detail_json, '$.old_public_key',
    substr(json_extract(detail_json, '$.old_public_key'), 1, 8) || '…')
 WHERE length(json_extract(detail_json, '$.old_public_key')) = 44;

UPDATE audit_log SET detail_json = json_set(detail_json, '$.new_public_key',
    substr(json_extract(detail_json, '$.new_public_key'), 1, 8) || '…')
 WHERE length(json_extract(detail_json, '$.new_public_key')) = 44;

UPDATE audit_log SET detail_json = json_set(detail_json, '$.revoked_devices', (
    SELECT json_group_array(json(
        CASE WHEN length(json_extract(je.value, '$.public_key')) = 44
             THEN json_set(je.value, '$.public_key',
                           substr(json_extract(je.value, '$.public_key'), 1, 8) || '…')
             ELSE je.value END))
      FROM json_each(audit_log.detail_json, '$.revoked_devices') AS je))
 WHERE json_extract(detail_json, '$.revoked_devices') IS NOT NULL;

UPDATE audit_log SET detail_json = json_set(detail_json, '$.live_devices', (
    SELECT json_group_array(json(
        CASE WHEN length(json_extract(je.value, '$.public_key')) = 44
             THEN json_set(je.value, '$.public_key',
                           substr(json_extract(je.value, '$.public_key'), 1, 8) || '…')
             ELSE je.value END))
      FROM json_each(audit_log.detail_json, '$.live_devices') AS je))
 WHERE json_extract(detail_json, '$.live_devices') IS NOT NULL;

UPDATE audit_log SET detail_json = json_object('redacted',
    'pre-M07 reconciliation report removed: it embedded full public keys')
 WHERE action = 'reconcile.report'
   AND json_extract(detail_json, '$.report') IS NOT NULL;
