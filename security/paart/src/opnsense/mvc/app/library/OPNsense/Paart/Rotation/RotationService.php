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
 * Rotation and revocation orchestration (M05).
 *
 * Rotation renews a device's key without touching its identity or address;
 * revocation cuts access immediately and terminally. They are distinct
 * operations by spec — never two variants of one action.
 *
 * State machine owned here (rotations.state):
 *   pending → applied → confirmed        (full flow: poll, rekey, ack)
 *   pending → applied                    (manual flow, ADR 0006: the swap is
 *                                         completed by EnrollmentService via a
 *                                         rekey token; no ack is possible for a
 *                                         static .conf, applied is terminal)
 *   pending → expired                    (grace elapsed — alert, NEVER a cutoff)
 *   pending|applied → failed             (device revoked mid-rotation)
 *
 * Ordering rules, from the spec:
 *  - the old key is NEVER removed before the new one arrived: initiation only
 *    flags the device 'rotating', the peer is untouched until the atomic swap;
 *  - the swap touches the firewall FIRST, the store second (same rule as the
 *    M04 rekey): a failed swap leaves the old key live and the store truthful;
 *  - after the swap the store holds the NEW key and key_created_at is set to
 *    the swap time (the key's real age — the spec sketches it at ack time, but
 *    ack may never come and the age would then lie); the device stays
 *    'rotating' until it acknowledges a verified handshake;
 *  - an expired grace changes rotations.state only. The device keeps whatever
 *    key it has, the peer stays. Cutting access on silence is a human decision;
 *  - revocation deletes the peer BEFORE the store change: reporting a device
 *    revoked while its tunnel still works would be the dangerous lie. On a
 *    firewall failure nothing is recorded and the call must be retried
 *    (deletePeer is idempotent, so the retry is safe);
 *  - firewall-first has a mirror case: when the store write AFTER a committed
 *    firewall batch fails, the batch cannot be undone — the error (INTERNAL)
 *    says the firewall is now ahead and that reconciliation will flag the
 *    drift, never repair it (recordAfterFirewall).
 */

namespace OPNsense\Paart\Rotation;

use OPNsense\Paart\Domain\AuditTrail;
use OPNsense\Paart\Domain\Devices;
use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Domain\PublicKey;
use OPNsense\Paart\Enroll\EnrollTokens;
use OPNsense\Paart\Provision\PeerProvisioner;
use OPNsense\Paart\Provision\PeerSpec;
use OPNsense\Paart\Store\Database;
use OPNsense\Paart\Support\Ulid;

final class RotationService
{
    /** Spec default grace TTL: 30 days, configurable per install (M08). */
    public const DEFAULT_GRACE_SECONDS = 30 * 86400;

    private Database $db;
    private Devices $devices;
    private EnrollTokens $tokens;
    private PeerProvisioner $provisioner;
    private AuditTrail $audit;
    private int $graceSeconds;

    public function __construct(
        Database $db,
        Devices $devices,
        EnrollTokens $tokens,
        PeerProvisioner $provisioner,
        AuditTrail $audit,
        ?int $graceSeconds = null
    ) {
        $this->db = $db;
        $this->devices = $devices;
        $this->tokens = $tokens;
        $this->provisioner = $provisioner;
        $this->audit = $audit;
        $this->graceSeconds = $graceSeconds ?? self::DEFAULT_GRACE_SECONDS;
    }

    /**
     * Start a rotation on one ACTIVE device (admin "Rotate" button). The
     * device becomes 'rotating', a pending rotations row records the current
     * key and the grace deadline; the peer is untouched. A 'manual' device
     * additionally gets a rekey token (ADR 0006) expiring with the grace.
     *
     * @param string $deviceId device ULID.
     * @param string $actorRef admin identity for the audit trail.
     * @return array{rotation: array<string, mixed>, rekey_token: ?string}
     *         rekey_token is the one-time plaintext for a 'manual' device,
     *         null for a 'full' device (it learns via its next poll).
     * @throws DomainException NOT_FOUND | DEVICE_NOT_ACTIVE when the device
     *         is not 'active' (a rotation is already open, or it is revoked).
     */
    public function initiate(string $deviceId, string $actorRef): array
    {
        return $this->db->transaction(function () use ($deviceId, $actorRef): array {
            $device = $this->devices->get($deviceId);
            if ($device['status'] !== 'active') {
                throw new DomainException(
                    'DEVICE_NOT_ACTIVE',
                    "Cannot rotate device '{$device['label']}' in status '{$device['status']}'; " .
                    'only active devices can be rotated.'
                );
            }
            $out = $this->beginRotation($device, $actorRef);
            $this->audit->record('admin', $actorRef, 'rotation.initiate', 'device', $deviceId, 'success', [
                'rotation_id' => $out['rotation']['id'],
                'grace_until' => $out['rotation']['grace_until'],
                'management_level' => $device['management_level'],
            ]);
            return $out;
        });
    }

    /**
     * Start a rotation on every ACTIVE device of a user ("Rotate all
     * devices", M08). Devices already mid-lifecycle (pending, rotating) are
     * skipped and listed, not an error — the intent is "everything this
     * user has ends up on fresh keys". Revoked devices are terminal and not
     * candidates at all, so they appear nowhere in the result. One bulk
     * audit entry lists all effects (M03 pattern).
     *
     * @param string $userId user ULID.
     * @param string $actorRef admin identity for the audit trail.
     * @return array{
     *   initiated: array<int, array{device_id: string, rotation: array<string, mixed>, rekey_token: ?string}>,
     *   skipped: array<int, string>
     * } skipped holds the device ids left untouched (pending or rotating).
     * @throws DomainException NOT_FOUND | USER_DISABLED.
     */
    public function initiateForUser(string $userId, string $actorRef): array
    {
        return $this->db->transaction(function (Database $db) use ($userId, $actorRef): array {
            $user = $db->query('SELECT * FROM users WHERE id = :id', [':id' => $userId]);
            if ($user === []) {
                throw new DomainException('NOT_FOUND', "User '$userId' does not exist.");
            }
            if ($user[0]['status'] !== 'active') {
                throw new DomainException(
                    'USER_DISABLED',
                    'Cannot rotate devices of a disabled user.'
                );
            }

            $initiated = [];
            $skipped = [];
            $rows = $db->query(
                "SELECT * FROM devices WHERE user_id = :u AND status != 'revoked' ORDER BY id",
                [':u' => $userId]
            );
            foreach ($rows as $device) {
                if ($device['status'] !== 'active') {
                    $skipped[] = $device['id'];
                    continue;
                }
                $out = $this->beginRotation($device, $actorRef);
                $initiated[] = ['device_id' => $device['id']] + $out;
            }
            $this->audit->record('admin', $actorRef, 'user.rotate_all', 'user', $userId, 'success', [
                'rotated_device_ids' => \array_column($initiated, 'device_id'),
                'skipped_device_ids' => $skipped,
            ]);
            return ['initiated' => $initiated, 'skipped' => $skipped];
        });
    }

    /**
     * Re-arm the rotation of a device stuck in 'rotating' — the spec's
     * "explicit token re-issue" after an expired grace, also usable when a
     * manual device's token was lost. Outstanding rekey tokens for the
     * device are revoked first so exactly one stays valid. An open pending
     * rotation gets a fresh grace deadline; an expired/failed one is
     * superseded by a new pending row (history is kept, rows are immutable
     * once terminal).
     *
     * @param string $deviceId device ULID.
     * @param string $actorRef admin identity for the audit trail.
     * @return array{rotation: array<string, mixed>, rekey_token: ?string}
     *         rekey_token as in initiate() — only for 'manual' devices.
     * @throws DomainException NOT_FOUND | DEVICE_NOT_ACTIVE when the device
     *         is not 'rotating' (nothing to re-arm), or ROTATION_NOT_PENDING
     *         when its rotation is already 'applied' (the new key is on the
     *         firewall; re-issuing would fork the state).
     */
    public function reissue(string $deviceId, string $actorRef): array
    {
        return $this->db->transaction(function (Database $db) use ($deviceId, $actorRef): array {
            $device = $this->devices->get($deviceId);
            if ($device['status'] !== 'rotating') {
                throw new DomainException(
                    'DEVICE_NOT_ACTIVE',
                    "Cannot re-issue a rotation for device '{$device['label']}' in status " .
                    "'{$device['status']}'; only a rotating device can be re-armed."
                );
            }
            if ($this->openRotation($deviceId, 'applied') !== null) {
                throw new DomainException(
                    'ROTATION_NOT_PENDING',
                    'The new key is already applied; awaiting device acknowledgement.'
                );
            }

            // One valid rekey token at a time: silently retire the others.
            $db->run(
                "UPDATE enroll_tokens SET consumed_at = :now
                 WHERE device_id = :d AND purpose = 'rekey' AND consumed_at IS NULL",
                [':now' => Database::utcNow(), ':d' => $deviceId]
            );

            $graceUntil = $this->graceDeadline();
            $pending = $this->openRotation($deviceId, 'pending');
            if ($pending !== null) {
                $db->run(
                    'UPDATE rotations SET grace_until = :g WHERE id = :id',
                    [':g' => $graceUntil, ':id' => $pending['id']]
                );
                $rotation = $this->rotationRow($pending['id']);
            } else {
                $rotation = $this->insertRotation($deviceId, (string)$device['public_key'], $graceUntil);
            }

            $rekeyToken = null;
            if ($device['management_level'] === 'manual') {
                $issued = $this->tokens->issueRekey($deviceId, $graceUntil, $actorRef);
                $rekeyToken = $issued['token'];
            }
            $this->audit->record('admin', $actorRef, 'rotation.reissue', 'device', $deviceId, 'success', [
                'rotation_id' => $rotation['id'],
                'grace_until' => $graceUntil,
            ]);
            return ['rotation' => $rotation, 'rekey_token' => $rekeyToken];
        });
    }

    /**
     * Complete the rotation of a 'full' device (/device/rekey): atomically
     * swap the peer to the submitted key — same identity, same IP — then
     * record the new key. The device stays 'rotating' until acknowledge();
     * the rotation is 'applied'. Replaying after success with the same key
     * is a no-op (the device retries when it missed the response).
     *
     * The 'manual' flow does NOT come here: it goes through /enroll with a
     * rekey token (EnrollmentService, ADR 0006).
     *
     * @param string $deviceId device ULID (resolved from the device token by
     *        the device API, submitted separately — this service never sees
     *        credentials).
     * @param string $newPublicKey freshly generated WireGuard public key.
     * @return array<string, mixed> the updated device row.
     * @throws DomainException NOT_FOUND | VALIDATION_FAILED |
     *         ROTATION_NOT_PENDING when no rotation is pending |
     *         PUBLIC_KEY_IN_USE | PROVISIONING_UNAVAILABLE (retry: the old
     *         key is still live and the rotation still pending) | INTERNAL
     *         (store failure AFTER the swap: the firewall already runs the
     *         new key — see recordAfterFirewall).
     */
    public function completeFull(string $deviceId, string $newPublicKey): array
    {
        PublicKey::assertValid($newPublicKey);
        $device = $this->devices->get($deviceId);

        // Retry after a lost response: swap already done, just answer again.
        $applied = $this->openRotation($deviceId, 'applied');
        if (
            $device['status'] === 'rotating'
            && $applied !== null
            && $applied['new_public_key'] === $newPublicKey
        ) {
            return $device;
        }

        $rotation = $this->openRotation($deviceId, 'pending');
        if ($device['status'] !== 'rotating' || $rotation === null) {
            throw new DomainException(
                'ROTATION_NOT_PENDING',
                'No rotation is pending for this device.'
            );
        }
        $known = (int)$this->db->scalar(
            'SELECT COUNT(*) FROM devices WHERE instance_id = :i AND public_key = :k',
            [':i' => $device['instance_id'], ':k' => $newPublicKey]
        );
        if ($known !== 0) {
            throw new DomainException(
                'PUBLIC_KEY_IN_USE',
                'This public key is already known on the target instance; ' .
                'generate a fresh key pair for the rotation.'
            );
        }

        $instance = $this->instanceRow((string)$device['instance_id']);
        $spec = PeerSpec::forDevice(
            $this->userSlug((string)$device['user_id']),
            (string)$device['label'],
            $newPublicKey,
            (string)$device['ip_address'] // same identity, same IP — no allocation
        );
        $this->provisioner->replacePeer((string)$instance['wg_instance_ref'], (string)$device['public_key'], $spec);
        $this->provisioner->commit();

        return $this->recordAfterFirewall(
            'the peer was already replaced with the new key',
            function () use ($device, $rotation, $newPublicKey): array {
                $this->db->transaction(function (Database $db) use ($device, $rotation, $newPublicKey): void {
                    $now = Database::utcNow();
                    // status stays 'rotating': active again only after the ack.
                    $db->run(
                        'UPDATE devices SET public_key = :k, key_created_at = :now, updated_at = :now
                         WHERE id = :id',
                        [':k' => $newPublicKey, ':now' => $now, ':id' => $device['id']]
                    );
                    $db->run(
                        "UPDATE rotations SET state = 'applied', new_public_key = :k, applied_at = :now
                         WHERE id = :id",
                        [':k' => $newPublicKey, ':now' => $now, ':id' => $rotation['id']]
                    );
                });
                $this->audit->record('device', $device['id'], 'device.rekey', 'device', $device['id'], 'success', [
                    'old_public_key' => PublicKey::fingerprint((string)$device['public_key']),
                    'new_public_key' => PublicKey::fingerprint($newPublicKey),
                    'rotation_id' => $rotation['id'],
                ]);
                return $this->devices->get($device['id']);
            }
        );
    }

    /**
     * Device acknowledgement (/device/ack) after a verified handshake with
     * the new key: rotation 'applied' → 'confirmed', device 'rotating' →
     * 'active'. Idempotent on an already-confirmed rotation.
     *
     * @param string $deviceId device ULID.
     * @return array<string, mixed> the updated device row.
     * @throws DomainException NOT_FOUND | ROTATION_NOT_PENDING when no
     *         rotation is applied nor freshly confirmed for this device.
     */
    public function acknowledge(string $deviceId): array
    {
        return $this->db->transaction(function (Database $db) use ($deviceId): array {
            $device = $this->devices->get($deviceId);
            $applied = $this->openRotation($deviceId, 'applied');
            if ($applied === null) {
                if ($device['status'] === 'active' && $this->latestRotationState($deviceId) === 'confirmed') {
                    return $device; // duplicate ack — the retry is harmless
                }
                throw new DomainException(
                    'ROTATION_NOT_PENDING',
                    'No applied rotation is awaiting acknowledgement for this device.'
                );
            }
            $now = Database::utcNow();
            $db->run(
                "UPDATE rotations SET state = 'confirmed', confirmed_at = :now WHERE id = :id",
                [':now' => $now, ':id' => $applied['id']]
            );
            $db->run(
                "UPDATE devices SET status = 'active', updated_at = :now WHERE id = :id",
                [':now' => $now, ':id' => $deviceId]
            );
            $this->audit->record('device', $deviceId, 'rotation.confirmed', 'device', $deviceId, 'success', [
                'rotation_id' => $applied['id'],
            ]);
            return $this->devices->get($deviceId);
        });
    }

    /**
     * Flag pending rotations whose grace elapsed: state → 'expired' plus one
     * audit entry per rotation — the admin alert the spec mandates (surfaced
     * by M07/M08). The device is NOT touched: it stays 'rotating' and its
     * current key stays live. No cutoff, ever — reissue() re-arms it when
     * the admin decides. Intended to run periodically (cron/configd, M10).
     *
     * @return array<int, string> ids of the rotations flagged this run.
     */
    public function expireOverdueGraces(): array
    {
        return $this->db->transaction(function (Database $db): array {
            $now = Database::utcNow();
            $overdue = $db->query(
                "SELECT * FROM rotations WHERE state = 'pending' AND grace_until <= :now",
                [':now' => $now]
            );
            $flagged = [];
            foreach ($overdue as $rotation) {
                $db->run(
                    "UPDATE rotations SET state = 'expired' WHERE id = :id",
                    [':id' => $rotation['id']]
                );
                $this->audit->record(
                    'system',
                    'rotation',
                    'rotation.grace_expired',
                    'device',
                    (string)$rotation['device_id'],
                    'failure',
                    ['rotation_id' => $rotation['id'], 'grace_until' => $rotation['grace_until']]
                );
                $flagged[] = (string)$rotation['id'];
            }
            return $flagged;
        });
    }

    /**
     * Revoke one device — the full M05 sequence: peer deleted from the
     * firewall FIRST, then (in one transaction) terminal 'revoked' status,
     * quarantined address and audit entry (Devices::revoke), any open
     * rotation flagged 'failed', and outstanding rekey tokens retired.
     * The device token is invalidated by the status change (M04 auth
     * accepts non-revoked devices only). Idempotent: an already-revoked
     * device returns null.
     *
     * On a firewall failure nothing is recorded — the device must NOT read
     * as revoked while its tunnel still works. Retry until it succeeds
     * (deletePeer and commit are idempotent).
     *
     * @param string $deviceId device ULID.
     * @param string $actorRef admin identity for the audit trail.
     * @return ?array<string, mixed> the revoked device row; null when it
     *         already was.
     * @throws DomainException NOT_FOUND | PROVISIONING_UNAVAILABLE |
     *         INSTANCE_UNAVAILABLE (nothing changed; retry) | INTERNAL
     *         (store failure AFTER the delete: the peer is already gone
     *         from the firewall — see recordAfterFirewall).
     */
    public function revokeDevice(string $deviceId, string $actorRef): ?array
    {
        $device = $this->devices->get($deviceId);
        if ($device['status'] === 'revoked') {
            return null;
        }
        $instance = $this->instanceRow((string)$device['instance_id']);
        $this->provisioner->deletePeer((string)$instance['wg_instance_ref'], (string)$device['public_key']);
        $this->provisioner->commit();

        return $this->recordAfterFirewall(
            "the device's peer was already deleted from the firewall",
            fn(): array => $this->db->transaction(function (Database $db) use ($deviceId, $actorRef): array {
                $this->devices->revoke($deviceId, 'admin', $actorRef);
                $db->run(
                    "UPDATE rotations SET state = 'failed'
                     WHERE device_id = :d AND state IN ('pending', 'applied')",
                    [':d' => $deviceId]
                );
                $db->run(
                    "UPDATE enroll_tokens SET consumed_at = :now
                     WHERE device_id = :d AND purpose = 'rekey' AND consumed_at IS NULL",
                    [':now' => Database::utcNow(), ':d' => $deviceId]
                );
                return $this->devices->get($deviceId);
            })
        );
    }

    /**
     * Run the store bookkeeping that follows an already-applied firewall
     * batch. When it fails, the one thing the admin must learn is that the
     * firewall is now AHEAD of the store — $applied names what already
     * happened there and cannot be undone by the failure. Reconciliation
     * (M05) flags the drift; it never repairs it. Same shape as
     * AdminService::recordAfterFirewall — each class keeps its own copy so
     * the wording stays next to the batches it covers; tests pin the same
     * message fragments in both (test_rotation, test_admin_service), so a
     * wording change here must land in the twin too.
     *
     * @template T
     * @param string $applied past-tense description of the firewall change.
     * @param callable(): T $fn the store writes to attempt.
     * @return T
     * @throws DomainException INTERNAL wrapping any failure of $fn.
     */
    private function recordAfterFirewall(string $applied, callable $fn): mixed
    {
        try {
            return $fn();
        } catch (\Throwable $e) {
            throw new DomainException(
                'INTERNAL',
                "The firewall change was already applied — $applied — but recording it " .
                'in the store failed: ' . $e->getMessage() .
                ' The store now lags the firewall; reconciliation will flag the drift.'
            );
        }
    }

    /**
     * Rotation core shared by initiate() and initiateForUser(), WITHOUT its
     * own audit entry (callers own the audit granularity, M03 pattern).
     *
     * @param array<string, mixed> $device an 'active' devices row.
     * @param string $actorRef admin identity, forwarded to the rekey token.
     * @return array{rotation: array<string, mixed>, rekey_token: ?string}
     */
    private function beginRotation(array $device, string $actorRef): array
    {
        $graceUntil = $this->graceDeadline();
        $this->db->run(
            "UPDATE devices SET status = 'rotating', updated_at = :now WHERE id = :id",
            [':now' => Database::utcNow(), ':id' => $device['id']]
        );
        $rotation = $this->insertRotation((string)$device['id'], (string)$device['public_key'], $graceUntil);

        $rekeyToken = null;
        if ($device['management_level'] === 'manual') {
            $issued = $this->tokens->issueRekey((string)$device['id'], $graceUntil, $actorRef);
            $rekeyToken = $issued['token'];
        }
        return ['rotation' => $rotation, 'rekey_token' => $rekeyToken];
    }

    /** @return array<string, mixed> the inserted pending rotations row. */
    private function insertRotation(string $deviceId, string $oldPublicKey, string $graceUntil): array
    {
        $id = Ulid::generate();
        $this->db->run(
            "INSERT INTO rotations (id, device_id, old_public_key, state, requested_at, grace_until)
             VALUES (:id, :device, :old, 'pending', :now, :grace)",
            [
                ':id' => $id,
                ':device' => $deviceId,
                ':old' => $oldPublicKey,
                ':now' => Database::utcNow(),
                ':grace' => $graceUntil,
            ]
        );
        return $this->rotationRow($id);
    }

    /**
     * The device's rotation still in flight — 'pending' (waiting for the
     * device's new key) or 'applied' (swapped, waiting for the ack) — or
     * null when nothing is open: no rotation, or the last one confirmed,
     * failed or expired. An expired grace is null on purpose: the device
     * cannot complete it until the admin re-issues (reissue() re-arms a
     * fresh 'pending'), so the device surface (M05 poll) shows it nothing
     * to do. At most one rotation is open per device (initiate refuses a
     * device that is not 'active').
     *
     * @return ?array<string, mixed> rotations row.
     */
    public function currentRotation(string $deviceId): ?array
    {
        $rows = $this->db->query(
            "SELECT * FROM rotations WHERE device_id = :d AND state IN ('pending', 'applied')
             ORDER BY id DESC LIMIT 1",
            [':d' => $deviceId]
        );
        return $rows[0] ?? null;
    }

    /** @return ?array<string, mixed> the device's rotation in $state, if any. */
    private function openRotation(string $deviceId, string $state): ?array
    {
        $rows = $this->db->query(
            'SELECT * FROM rotations WHERE device_id = :d AND state = :s ORDER BY id DESC LIMIT 1',
            [':d' => $deviceId, ':s' => $state]
        );
        return $rows[0] ?? null;
    }

    /** @return ?string state of the device's most recent rotation, if any. */
    private function latestRotationState(string $deviceId): ?string
    {
        $state = $this->db->scalar(
            'SELECT state FROM rotations WHERE device_id = :d ORDER BY id DESC LIMIT 1',
            [':d' => $deviceId]
        );
        return $state === null ? null : (string)$state;
    }

    /**
     * @return array<string, mixed>
     * @throws DomainException NOT_FOUND.
     */
    private function rotationRow(string $rotationId): array
    {
        $rows = $this->db->query('SELECT * FROM rotations WHERE id = :id', [':id' => $rotationId]);
        if ($rows === []) {
            throw new DomainException('NOT_FOUND', "Rotation '$rotationId' does not exist.");
        }
        return $rows[0];
    }

    /** Grace deadline from now, RFC 3339 UTC. */
    private function graceDeadline(): string
    {
        return \gmdate('Y-m-d\TH:i:s\Z', \strtotime(Database::utcNow()) + $this->graceSeconds);
    }

    /**
     * @return array<string, mixed>
     * @throws DomainException NOT_FOUND.
     */
    private function instanceRow(string $instanceId): array
    {
        $rows = $this->db->query('SELECT * FROM instances WHERE id = :id', [':id' => $instanceId]);
        if ($rows === []) {
            throw new DomainException('NOT_FOUND', "Declared instance '$instanceId' does not exist.");
        }
        return $rows[0];
    }

    /**
     * @throws DomainException NOT_FOUND.
     */
    private function userSlug(string $userId): string
    {
        $slug = $this->db->scalar('SELECT slug FROM users WHERE id = :id', [':id' => $userId]);
        if ($slug === null) {
            throw new DomainException('NOT_FOUND', "User '$userId' does not exist.");
        }
        return (string)$slug;
    }
}
