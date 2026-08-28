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
 * Enrollment orchestration (M04): one entry point for the public /enroll
 * endpoint, routing on token purpose (enroll | rekey, ADR 0006) after the
 * uniform validation, plus the abandoned-pending cleanup the spec mandates.
 *
 * Ordering rules enforced here, from the spec and the M01 contract:
 *  - the token is consumed only AFTER provisioning succeeded — a firewall
 *    failure returns PROVISIONING_UNAVAILABLE (retryable) with the token
 *    intact and no active device;
 *  - an enrollment interrupted after the peer was staged/applied leaves a
 *    'pending' device: a retry with the SAME public key resumes it (the
 *    device is matched by key, forbidden rule #5), and cleanupAbandoned()
 *    reaps whatever never completed after one hour;
 *  - failed attempts are audited with the source IP, and the rate limiter
 *    counts those audit entries — no extra table, and the block slides for
 *    as long as rejections keep aging in the window;
 *  - a rekey swap touches the firewall FIRST, the store second: if the swap
 *    fails, the store still holds the old key and the token stays valid.
 *    The reverse order could promise a key the firewall never accepted.
 *
 * The HTTP layer (Api\EnrollController + Enroll\Bundles) owns response
 * shaping — bundle assembly, headers, body-size limit, field whitelist;
 * this service returns rows and one-time plaintext tokens.
 */

namespace OPNsense\Paart\Enroll;

use OPNsense\Paart\Domain\AuditTrail;
use OPNsense\Paart\Domain\Devices;
use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Domain\PublicKey;
use OPNsense\Paart\Provision\PeerProvisioner;
use OPNsense\Paart\Provision\PeerSpec;
use OPNsense\Paart\Store\Database;

final class EnrollmentService
{
    /** Spec default: 10 failed attempts per source IP per 10 minutes. */
    public const RATE_LIMIT_ATTEMPTS = 10;
    public const RATE_LIMIT_WINDOW_S = 600;
    /** Spec: a 'pending' device older than 1 h is reaped automatically. */
    public const ABANDONED_PENDING_S = 3600;

    private Database $db;
    private EnrollTokens $tokens;
    private Devices $devices;
    private PeerProvisioner $provisioner;
    private AuditTrail $audit;

    public function __construct(
        Database $db,
        EnrollTokens $tokens,
        Devices $devices,
        PeerProvisioner $provisioner,
        AuditTrail $audit
    ) {
        $this->db = $db;
        $this->tokens = $tokens;
        $this->devices = $devices;
        $this->provisioner = $provisioner;
        $this->audit = $audit;
    }

    /**
     * Handle one /enroll submission (app or portal — same endpoint, M15).
     *
     * @param array{token?: string, public_key?: string, device_name?: string,
     *              platform?: string, management_level?: string} $req
     *        management_level defaults to 'full'; the portal flow passes
     *        'manual' (a downloaded .conf cannot self-rotate, M05).
     * @param string $sourceIp client IP as seen by the endpoint — keys the
     *        per-IP rate limit and is recorded with every audit entry (M07).
     * @return array{device: array<string, mixed>, device_token: ?string}
     *         device_token is the one-time plaintext for a NEW enrollment;
     *         null for a rekey (same identity, existing token untouched).
     * @throws DomainException RATE_LIMITED | ENROLLMENT_REJECTED |
     *         VALIDATION_FAILED | PUBLIC_KEY_IN_USE | DEVICE_LIMIT_REACHED |
     *         POOL_EXHAUSTED | PROVISIONING_UNAVAILABLE.
     */
    public function enroll(array $req, string $sourceIp): array
    {
        $this->assertNotThrottled($sourceIp);
        try {
            $token = $this->tokens->validate((string)($req['token'] ?? ''));
            return $token['purpose'] === 'rekey'
                ? $this->completeRekey($token, $req, $sourceIp)
                : $this->enrollNew($token, $req, $sourceIp);
        } catch (DomainException $e) {
            if ($e->apiCode() === 'ENROLLMENT_REJECTED') {
                // Spec: every failed attempt is logged with its source IP; the
                // cause stays here (M07), never in the uniform response.
                $this->audit->record(
                    'system',
                    'enroll',
                    'enroll.rejected',
                    'endpoint',
                    '/enroll',
                    'failure',
                    [],
                    $sourceIp
                );
            }
            throw $e;
        }
    }

    /**
     * Reap 'pending' devices older than the spec cutoff: remove their peer
     * (the explicit intent the spec mandates — not an on-error deletion),
     * quarantine the address, mark the device revoked. One reconfigure for
     * the whole batch. An unavailable instance skips its devices; they are
     * retried on the next run.
     *
     * @return array{cleaned: array<int, string>, skipped: array<int, string>} device ids.
     */
    public function cleanupAbandoned(): array
    {
        $cutoff = \gmdate('Y-m-d\TH:i:s\Z', \strtotime(Database::utcNow()) - self::ABANDONED_PENDING_S);
        $stale = $this->db->query(
            "SELECT d.id, d.public_key, i.wg_instance_ref
             FROM devices d JOIN instances i ON i.id = d.instance_id
             WHERE d.status = 'pending' AND d.enrolled_at <= :cutoff",
            [':cutoff' => $cutoff]
        );

        $cleaned = [];
        $skipped = [];
        foreach ($stale as $device) {
            try {
                // No-op if the peer never reached the config; staged-only
                // removals are applied by the single commit below. The catch
                // covers gateway failures too: ProvisionException extends
                // DomainException by design (single stable-code hierarchy).
                $this->provisioner->deletePeer($device['wg_instance_ref'], $device['public_key']);
            } catch (DomainException $e) {
                $skipped[] = $device['id'];
                continue;
            }
            $this->db->transaction(function () use ($device): void {
                $this->devices->revokeQuietly($device['id']);
                $this->audit->record(
                    'system',
                    'enroll',
                    'enroll.abandoned',
                    'device',
                    $device['id'],
                    'success',
                    ['public_key' => $device['public_key']]
                );
            });
            $cleaned[] = $device['id'];
        }
        if ($cleaned !== []) {
            $this->provisioner->commit();
        }
        return ['cleaned' => $cleaned, 'skipped' => $skipped];
    }

    /** @param array<string, mixed> $token @param array<string, mixed> $req */
    private function enrollNew(array $token, array $req, string $sourceIp): array
    {
        $publicKey = (string)($req['public_key'] ?? '');
        PublicKey::assertValid($publicKey);
        $deviceToken = self::generateDeviceToken();
        $tokenHash = \hash('sha256', $deviceToken);

        // Resume: a pending device holding this key on the token's instance
        // is this same enrollment, interrupted before the client got its
        // response. Reuse the entity (metadata kept as first submitted) and
        // rotate its device token — the previous plaintext may be lost.
        $pending = $this->db->query(
            "SELECT * FROM devices
             WHERE instance_id = :i AND public_key = :k AND user_id = :u
               AND status = 'pending'",
            [':i' => $token['instance_id'], ':k' => $publicKey, ':u' => $token['user_id']]
        );
        if ($pending !== []) {
            $device = $pending[0];
            $this->db->run(
                'UPDATE devices SET device_token_hash = :h, updated_at = :now WHERE id = :id',
                [':h' => $tokenHash, ':now' => Database::utcNow(), ':id' => $device['id']]
            );
        } else {
            $device = $this->devices->enroll([
                'user_id' => (string)$token['user_id'],
                'instance_id' => (string)$token['instance_id'],
                'label' => (string)($req['device_name'] ?? ''),
                'platform' => (string)($req['platform'] ?? ''),
                'management_level' => (string)($req['management_level'] ?? 'full'),
                'public_key' => $publicKey,
                'device_token_hash' => $tokenHash,
            ], 'device', $sourceIp);
        }

        // Firewall failure from here on: the device stays 'pending' with its
        // allocation, the token is NOT consumed — the same request resumes
        // above, and cleanupAbandoned() reaps it after the spec cutoff.
        $instance = $this->instanceRow((string)$token['instance_id']);
        $spec = PeerSpec::forDevice(
            $this->userSlug((string)$device['user_id']),
            (string)$device['label'],
            $publicKey,
            (string)$device['ip_address']
        );
        $this->provisioner->createPeer($instance['wg_instance_ref'], $spec);
        $this->provisioner->commit();

        // A lost consume race rolls back the activation too: the device stays
        // 'pending' with its peer applied, and the cleanup reaps both.
        $this->db->transaction(function () use ($device, $token): void {
            $this->devices->activate($device['id']);
            $this->tokens->consume($token['id']);
        });
        $this->audit->record(
            'device',
            $sourceIp,
            'enroll.completed',
            'device',
            $device['id'],
            'success',
            ['token_id' => $token['id']],
            $sourceIp
        );
        return ['device' => $this->devices->get($device['id']), 'device_token' => $deviceToken];
    }

    /** @param array<string, mixed> $token @param array<string, mixed> $req */
    private function completeRekey(array $token, array $req, string $sourceIp): array
    {
        $newKey = (string)($req['public_key'] ?? '');
        PublicKey::assertValid($newKey);

        $rows = $this->db->query('SELECT * FROM devices WHERE id = :id', [':id' => $token['device_id']]);
        $device = $rows[0] ?? null;
        if ($device === null || $device['status'] !== 'rotating') {
            // ADR 0006: a rekey token whose device is no longer rotating must
            // be indistinguishable from any other invalid token.
            throw new DomainException('ENROLLMENT_REJECTED', 'Enrollment was not accepted.');
        }
        $known = (int)$this->db->scalar(
            'SELECT COUNT(*) FROM devices WHERE instance_id = :i AND public_key = :k',
            [':i' => $device['instance_id'], ':k' => $newKey]
        );
        if ($known !== 0) {
            throw new DomainException(
                'PUBLIC_KEY_IN_USE',
                'This public key is already known on the target instance; ' .
                'generate a fresh key pair for the rekey.'
            );
        }

        $instance = $this->instanceRow((string)$device['instance_id']);
        $spec = PeerSpec::forDevice(
            $this->userSlug((string)$device['user_id']),
            (string)$device['label'],
            $newKey,
            (string)$device['ip_address'] // same identity, same IP — no allocation (ADR 0006)
        );
        $this->provisioner->replacePeer($instance['wg_instance_ref'], (string)$device['public_key'], $spec);
        $this->provisioner->commit();

        $this->db->transaction(function (Database $db) use ($device, $newKey, $token): void {
            $now = Database::utcNow();
            $db->run(
                "UPDATE devices SET public_key = :k, key_created_at = :now,
                        status = 'active', updated_at = :now
                 WHERE id = :id",
                [':k' => $newKey, ':now' => $now, ':id' => $device['id']]
            );
            // The pending rotation row is M05's bookkeeping; tolerate its
            // absence (0 rows) rather than owning M05 invariants here.
            $db->run(
                "UPDATE rotations SET state = 'applied', new_public_key = :k, applied_at = :now
                 WHERE device_id = :d AND state = 'pending'",
                [':k' => $newKey, ':now' => $now, ':d' => $device['id']]
            );
            $this->tokens->consume($token['id']);
        });
        $this->audit->record(
            'device',
            $sourceIp,
            'device.rekey',
            'device',
            $device['id'],
            'success',
            [
                'old_public_key' => $device['public_key'],
                'new_public_key' => $newKey,
            ],
            $sourceIp
        );
        return ['device' => $this->devices->get($device['id']), 'device_token' => null];
    }

    /** @throws DomainException RATE_LIMITED past the failed-attempt budget. */
    private function assertNotThrottled(string $sourceIp): void
    {
        $cutoff = \gmdate('Y-m-d\TH:i:s\Z', \strtotime(Database::utcNow()) - self::RATE_LIMIT_WINDOW_S);
        $rejected = (int)$this->db->scalar(
            "SELECT COUNT(*) FROM audit_log
             WHERE action = 'enroll.rejected' AND source_ip = :ip AND occurred_at > :cutoff",
            [':ip' => $sourceIp, ':cutoff' => $cutoff]
        );
        if ($rejected >= self::RATE_LIMIT_ATTEMPTS) {
            // Audited under its own action so throttled hits never extend the
            // block themselves; it ends when rejections age out of the window.
            $this->audit->record(
                'system',
                'enroll',
                'enroll.rate_limited',
                'endpoint',
                '/enroll',
                'failure',
                [],
                $sourceIp
            );
            throw new DomainException('RATE_LIMITED', 'Too many attempts; retry later.');
        }
    }

    /** One-time device API token: 32 random bytes, base64url (spec M02). */
    private static function generateDeviceToken(): string
    {
        return \rtrim(\strtr(\base64_encode(\random_bytes(32)), '+/', '-_'), '=');
    }

    /** @return array<string, mixed> @throws DomainException NOT_FOUND. */
    private function instanceRow(string $instanceId): array
    {
        $rows = $this->db->query('SELECT * FROM instances WHERE id = :id', [':id' => $instanceId]);
        if ($rows === []) {
            throw new DomainException('NOT_FOUND', "Declared instance '$instanceId' does not exist.");
        }
        return $rows[0];
    }

    /** @throws DomainException NOT_FOUND. */
    private function userSlug(string $userId): string
    {
        $slug = $this->db->scalar('SELECT slug FROM users WHERE id = :id', [':id' => $userId]);
        if ($slug === null) {
            throw new DomainException('NOT_FOUND', "User '$userId' does not exist.");
        }
        return (string)$slug;
    }
}
