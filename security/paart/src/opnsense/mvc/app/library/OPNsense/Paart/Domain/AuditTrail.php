<?php

/**
 *    Copyright (C) 2026 Lux-World PC SARL
 *
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * Append-only writer for the audit log. The log lives in the SQLite store,
 * never in config.xml (forbidden rule #2). M03 domain operations record
 * one INTENT entry per admin operation — a bulk action (disable user)
 * writes a single entry listing its effects, never N orphan entries.
 *
 * Retention (M07) is the ONE deletion this class performs: purgeExpired()
 * drops entries past the configured horizon and journalizes the purge
 * itself. No application route modifies or deletes an individual entry —
 * that absence is an M07 acceptance criterion, not an oversight. Querying
 * lives in AdminService::queryAudit (contract) and Admin\AuditScreen (UI).
 */

namespace OPNsense\Paart\Domain;

use OPNsense\Paart\Store\Database;
use OPNsense\Paart\Support\Ulid;

final class AuditTrail
{
    /** Spec (M07) retention horizon, in months, when the setting is unset. */
    public const DEFAULT_RETENTION_MONTHS = 24;

    private Database $db;

    /** @param Database $db the plugin store; every write lands in its `audit` table. */
    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    /**
     * Append one entry. $detail must never contain a secret (token or
     * device-token plaintext, any private key) — and not even a FULL
     * public key: the spec (M07) wants the journal useless as a
     * collection source, so keys travel as PublicKey::fingerprint().
     *
     * @param string $actorType 'admin' | 'device' | 'system'.
     * @param string $actorRef who acted: an admin identity; for 'device',
     *        its ULID once known, else the client IP (public endpoint);
     *        for 'system', the job name ('scheduler', 'provisioner',
     *        'enroll', 'reconciliation').
     * @param string $action dotted verb, '<subject>.<verb>' ('device.revoke',
     *        'audit.purge') — the Audit screen's action picker lists the
     *        distinct values found in the log, so spell new ones consistently.
     * @param string $subjectType what was acted on ('user', 'device',
     *        'instance', 'store', ...).
     * @param string $subjectRef the subject's ULID or fixed name.
     * @param string $outcome 'success' | 'failure' — nothing else: the
     *        Audit screen filter and its outcome badge branch on exactly
     *        these two values.
     * @param array<string, mixed> $detail JSON-encoded into detail_json.
     * @param ?string $sourceIp client address when the act came over the
     *        public endpoint (M04), null for admin and system entries.
     * @return string ULID of the entry.
     */
    public function record(
        string $actorType,
        string $actorRef,
        string $action,
        string $subjectType,
        string $subjectRef,
        string $outcome = 'success',
        array $detail = [],
        ?string $sourceIp = null
    ): string {
        $id = Ulid::generate();
        $this->db->run(
            'INSERT INTO audit_log (id, occurred_at, actor_type, actor_ref, action,
                                    subject_type, subject_ref, outcome, detail_json, source_ip)
             VALUES (:id, :at, :atype, :aref, :action, :stype, :sref, :outcome, :detail, :ip)',
            [
                ':id' => $id,
                ':at' => Database::utcNow(),
                ':atype' => $actorType,
                ':aref' => $actorRef,
                ':action' => $action,
                ':stype' => $subjectType,
                ':sref' => $subjectRef,
                ':outcome' => $outcome,
                ':detail' => \json_encode($detail, JSON_UNESCAPED_SLASHES),
                ':ip' => $sourceIp,
            ]
        );
        return $id;
    }

    /**
     * Delete every entry older than the retention horizon and journalize
     * the purge itself (M07: the only deletion the log ever sees, and it
     * leaves its own trace). Deleting nothing records nothing — a no-op
     * purge every scheduler run would drown the log it protects.
     *
     * The horizon is calendar months before now, computed in UTC like
     * every stored timestamp. Runs in one transaction so the purge and its
     * trace land together or not at all.
     *
     * @param int $retentionMonths configured horizon (Paart.xml bounds it
     *        to 1..120; DEFAULT_RETENTION_MONTHS when unset).
     * @param string $actorRef who triggered the purge — 'scheduler' for
     *        the periodic run (M10), an admin identity for a manual one.
     * @return int entries deleted.
     * @throws DomainException VALIDATION_FAILED on a horizon below one
     *         month (nothing is purged).
     */
    public function purgeExpired(int $retentionMonths, string $actorRef = 'scheduler'): int
    {
        if ($retentionMonths < 1) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Audit retention must be at least one month, got $retentionMonths. Nothing was purged."
            );
        }
        $cutoff = (new \DateTimeImmutable(Database::utcNow()))
            ->sub(new \DateInterval("P{$retentionMonths}M"))
            ->format('Y-m-d\TH:i:s\Z');
        return $this->db->transaction(function () use ($retentionMonths, $actorRef, $cutoff): int {
            $this->db->run(
                'DELETE FROM audit_log WHERE occurred_at < :cutoff',
                [':cutoff' => $cutoff]
            );
            $deleted = (int)$this->db->scalar('SELECT changes()');
            if ($deleted > 0) {
                $this->record('system', $actorRef, 'audit.purge', 'store', 'audit_log', 'success', [
                    'deleted' => $deleted,
                    'retention_months' => $retentionMonths,
                    'cutoff' => $cutoff,
                ]);
            }
            return $deleted;
        });
    }
}
