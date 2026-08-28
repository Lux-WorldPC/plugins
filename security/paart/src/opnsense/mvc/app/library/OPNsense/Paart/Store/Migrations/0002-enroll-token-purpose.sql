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

-- Migration 0002 — rekey tokens ride the enroll_tokens table (ADR 0006, M04).
--
-- Additive only: two columns, no data rewritten. A rekey token reuses the
-- whole enrollment token mechanism (hashed, single-use, uniform validation)
-- but is bound to an existing 'manual' device under rotation (issuance is
-- guarded in the M05 rotation layer — only 'manual' devices get one; the
-- schema itself only ties device_id to purpose):
--   purpose   'enroll' (default, historical rows) or 'rekey';
--   device_id set if and only if purpose = 'rekey' (enforced in the domain
--             layer — SQLite cannot ALTER TABLE ADD a two-column CHECK).
-- FK RESTRICT like everywhere else: deleting a device with a live rekey
-- token must be an explicit two-step, never a silent cascade.

ALTER TABLE enroll_tokens ADD COLUMN purpose TEXT NOT NULL DEFAULT 'enroll'
  CHECK (purpose IN ('enroll', 'rekey'));
ALTER TABLE enroll_tokens ADD COLUMN device_id TEXT
  REFERENCES devices (id) ON DELETE RESTRICT;
