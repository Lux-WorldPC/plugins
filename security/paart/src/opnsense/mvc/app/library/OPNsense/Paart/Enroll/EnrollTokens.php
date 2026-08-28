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
 * Enrollment and rekey token lifecycle (M04, ADR 0006).
 *
 * Tokens are 130-bit cryptographic randoms (spec floor: 128) encoded in
 * Crockford base32 — no I, L, O or U, so nothing ambiguous to retype from
 * a QR fallback. Only the SHA-256 of a token is ever stored (forbidden-rule
 * corollary: secrets hashed only); issue() returns the plaintext exactly
 * once and it cannot be retrieved again.
 *
 * Validation is UNIFORM by design (M04): unknown, expired, consumed and
 * revoked tokens all raise the same ENROLLMENT_REJECTED with the same
 * work done (one hash, one indexed lookup, same checks) — the distinction
 * exists only in the audit log. Revocation reuses consumed_at as the
 * terminal marker: the schema has no separate revoked column and a revoked
 * token must be indistinguishable from a consumed one anyway.
 *
 * Consumption is guarded (used_count < max_uses AND consumed_at IS NULL)
 * inside the caller's IMMEDIATE transaction, so two devices racing on the
 * same token cannot exceed max_uses (spec: serialize, respect strictly).
 */

namespace OPNsense\Paart\Enroll;

use OPNsense\Paart\Domain\AuditTrail;
use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Store\Database;
use OPNsense\Paart\Support\Ulid;

final class EnrollTokens
{
    /** Spec defaults: 24 h TTL, hard maximum 7 days, single use. */
    public const DEFAULT_TTL_SECONDS = 86400;
    public const MAX_TTL_SECONDS = 7 * 86400;

    /** Crockford base32 — 32 symbols, none visually ambiguous. */
    private const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    /** 26 symbols x 5 bits = 130 bits of entropy (spec floor: 128). */
    private const TOKEN_CHARS = 26;

    private Database $db;
    private AuditTrail $audit;

    public function __construct(Database $db, AuditTrail $audit)
    {
        $this->db = $db;
        $this->audit = $audit;
    }

    /**
     * Issue an enrollment token for an active user on a declared instance.
     * The plaintext token is returned ONCE and never retrievable again.
     *
     * @param string $userId ULID of an ACTIVE user (owner of the devices).
     * @param string $instanceId ULID of the declared target instance.
     * @param string $label admin-facing purpose of the token (trimmed).
     * @param string $createdBy admin actor reference for the audit entry.
     * @param int $maxUses >= 1 — one admin token may enroll N devices (spec).
     * @param ?int $ttlSeconds null = spec default (24 h); capped at 7 days.
     * @return array{token: string, row: array<string, mixed>}
     * @throws DomainException NOT_FOUND | USER_DISABLED | VALIDATION_FAILED.
     */
    public function issue(
        string $userId,
        string $instanceId,
        string $label,
        string $createdBy,
        int $maxUses = 1,
        ?int $ttlSeconds = null
    ): array {
        $ttlSeconds ??= self::DEFAULT_TTL_SECONDS;
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL_SECONDS) {
            throw new DomainException(
                'VALIDATION_FAILED',
                'Token TTL must be between 1 second and 7 days (spec maximum).'
            );
        }
        if ($maxUses < 1) {
            throw new DomainException('VALIDATION_FAILED', 'max_uses must be at least 1.');
        }

        return $this->db->transaction(function (Database $db) use (
            $userId,
            $instanceId,
            $label,
            $createdBy,
            $maxUses,
            $ttlSeconds
        ): array {
            $user = $db->query('SELECT * FROM users WHERE id = :id', [':id' => $userId]);
            if ($user === []) {
                throw new DomainException('NOT_FOUND', "User '$userId' does not exist.");
            }
            if ($user[0]['status'] !== 'active') {
                throw new DomainException(
                    'USER_DISABLED',
                    "User '{$user[0]['slug']}' is disabled; tokens require an active user."
                );
            }
            if ($db->query('SELECT id FROM instances WHERE id = :id', [':id' => $instanceId]) === []) {
                throw new DomainException('NOT_FOUND', "Declared instance '$instanceId' does not exist.");
            }

            $token = self::generate();
            $row = $this->insert($db, [
                ':user' => $userId,
                ':hash' => self::hash($token),
                ':label' => \trim($label),
                ':instance' => $instanceId,
                ':uses' => $maxUses,
                ':expires' => self::expiry($ttlSeconds),
                ':by' => $createdBy,
                ':purpose' => 'enroll',
                ':device' => null,
            ]);
            $this->audit->record('admin', $createdBy, 'token.issue', 'enroll_token', $row['id'], 'success', [
                'user_id' => $userId,
                'instance_id' => $instanceId,
                'max_uses' => $maxUses,
            ]);
            return ['token' => $token, 'row' => $row];
        });
    }

    /**
     * Issue a rekey token bound to an existing device (ADR 0006). Single
     * use by nature; $expiresAt comes from the rotation's grace_until (M05),
     * not from the short enrollment TTL.
     *
     * @param string $deviceId ULID of the device the token is bound to.
     * @param string $expiresAt RFC 3339 UTC expiry (the rotation's grace_until).
     * @param string $createdBy admin actor reference for the audit entry.
     * @return array{token: string, row: array<string, mixed>}
     * @throws DomainException NOT_FOUND on unknown device.
     */
    public function issueRekey(string $deviceId, string $expiresAt, string $createdBy): array
    {
        return $this->db->transaction(function (Database $db) use ($deviceId, $expiresAt, $createdBy): array {
            $device = $db->query('SELECT * FROM devices WHERE id = :id', [':id' => $deviceId]);
            if ($device === []) {
                throw new DomainException('NOT_FOUND', "Device '$deviceId' does not exist.");
            }
            $device = $device[0];

            $token = self::generate();
            $row = $this->insert($db, [
                ':user' => $device['user_id'],
                ':hash' => self::hash($token),
                ':label' => 'rekey: ' . $device['label'],
                ':instance' => $device['instance_id'],
                ':uses' => 1,
                ':expires' => $expiresAt,
                ':by' => $createdBy,
                ':purpose' => 'rekey',
                ':device' => $deviceId,
            ]);
            $this->audit->record('admin', $createdBy, 'token.issue', 'enroll_token', $row['id'], 'success', [
                'purpose' => 'rekey',
                'device_id' => $deviceId,
            ]);
            return ['token' => $token, 'row' => $row];
        });
    }

    /**
     * Uniform validation (M04): the ONLY outcome for an unknown, expired,
     * consumed or revoked token is ENROLLMENT_REJECTED with an identical
     * message — never reveal that a token existed. The caller audits the
     * rejection with the source IP; the specific cause stays out of the
     * response by design.
     *
     * @return array<string, mixed> the valid enroll_tokens row.
     * @throws DomainException ENROLLMENT_REJECTED.
     */
    public function validate(string $token): array
    {
        // Same work on every path: one hash, one indexed lookup, both checks.
        $rows = $this->db->query(
            'SELECT * FROM enroll_tokens WHERE token_hash = :h',
            [':h' => self::hash($token)]
        );
        $row = $rows[0] ?? null;
        $expired = $row === null || $row['expires_at'] <= Database::utcNow();
        $spent = $row === null
            || $row['consumed_at'] !== null
            || (int)$row['used_count'] >= (int)$row['max_uses'];
        if ($row === null || $expired || $spent) {
            throw new DomainException('ENROLLMENT_REJECTED', 'Enrollment was not accepted.');
        }
        return $row;
    }

    /**
     * Record one use, inside the caller's transaction (the enrollment flow
     * consumes only AFTER provisioning succeeded — M04). The WHERE guard
     * makes over-consumption impossible even when two requests raced past
     * validate() with the same token.
     *
     * @throws DomainException ENROLLMENT_REJECTED when the guard refuses —
     *         the race loser gets the same uniform response as any invalid token.
     */
    public function consume(string $tokenId): void
    {
        $this->db->run(
            'UPDATE enroll_tokens
             SET used_count = used_count + 1,
                 consumed_at = CASE WHEN used_count + 1 >= max_uses
                                    THEN :now ELSE consumed_at END
             WHERE id = :id AND consumed_at IS NULL AND used_count < max_uses',
            [':now' => Database::utcNow(), ':id' => $tokenId]
        );
        if ((int)$this->db->scalar('SELECT changes()') !== 1) {
            throw new DomainException('ENROLLMENT_REJECTED', 'Enrollment was not accepted.');
        }
    }

    /**
     * Revoke a token (admin action, M08 UI). Terminal and idempotent;
     * afterwards validation rejects it uniformly. Only the actual
     * transition is audited — repeat calls on an already-dead token
     * change nothing and log nothing.
     *
     * @throws DomainException NOT_FOUND.
     */
    public function revoke(string $tokenId, string $actorRef): void
    {
        if ($this->db->query('SELECT id FROM enroll_tokens WHERE id = :id', [':id' => $tokenId]) === []) {
            throw new DomainException('NOT_FOUND', "Token '$tokenId' does not exist.");
        }
        $this->db->run(
            'UPDATE enroll_tokens SET consumed_at = :now WHERE id = :id AND consumed_at IS NULL',
            [':now' => Database::utcNow(), ':id' => $tokenId]
        );
        if ((int)$this->db->scalar('SELECT changes()') === 1) {
            $this->audit->record('admin', $actorRef, 'token.revoke', 'enroll_token', $tokenId);
        }
    }

    /** Plaintext token: TOKEN_CHARS symbols from the Crockford alphabet. */
    public static function generate(): string
    {
        $out = '';
        for ($i = 0; $i < self::TOKEN_CHARS; $i++) {
            $out .= self::ALPHABET[\random_int(0, \strlen(self::ALPHABET) - 1)];
        }
        return $out;
    }

    /** Storage form of a token — SHA-256 hex; the plaintext is never stored. */
    public static function hash(string $token): string
    {
        return \hash('sha256', $token);
    }

    /**
     * @param array<string, mixed> $params named SQL parameters :user, :hash,
     *        :label, :instance, :uses, :expires, :by, :purpose, :device —
     *        :id and :now are supplied here.
     * @return array<string, mixed> the inserted row.
     */
    private function insert(Database $db, array $params): array
    {
        $id = Ulid::generate();
        $db->run(
            'INSERT INTO enroll_tokens (id, user_id, token_hash, label, instance_id, max_uses,
                                        used_count, expires_at, created_by, created_at,
                                        purpose, device_id)
             VALUES (:id, :user, :hash, :label, :instance, :uses,
                     0, :expires, :by, :now, :purpose, :device)',
            $params + [':id' => $id, ':now' => Database::utcNow()]
        );
        return $db->query('SELECT * FROM enroll_tokens WHERE id = :id', [':id' => $id])[0];
    }

    private static function expiry(int $ttlSeconds): string
    {
        return \gmdate('Y-m-d\TH:i:s\Z', \strtotime(Database::utcNow()) + $ttlSeconds);
    }
}
