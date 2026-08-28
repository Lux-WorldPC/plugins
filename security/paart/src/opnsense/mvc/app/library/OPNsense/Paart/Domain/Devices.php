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
 * Device lifecycle (M03): pending → active → (rotating →) revoked.
 *
 * Enrollment records the device and allocates its address atomically; the
 * peer itself is applied by the provisioner (M06), which then calls
 * activate(). Revocation here only changes STATE and quarantines the
 * address — the peer removal is returned as an explicit intent for M06,
 * never executed implicitly (forbidden rule #4). A revoked device is never
 * reactivated: re-enrollment creates a new entity with a new key pair.
 *
 * The device token is invalidated by status: the device API (a
 * separate PR, M05/M11) accepts only 'active' and 'rotating' devices —
 * a 'pending' one never received its token (the response carrying it is
 * only sent once the peer is applied), a revoked one is refused; the
 * hash column is immutable and never cleared.
 * Devices are matched by public key, never by name (forbidden rule #5) —
 * renaming is metadata-only and has no effect on the peer.
 */

namespace OPNsense\Paart\Domain;

use OPNsense\Paart\Store\Database;
use OPNsense\Paart\Support\Ulid;

final class Devices
{
    /** Contract Platform enum (M01) — public: /enroll/policy serves it. */
    public const PLATFORMS = ['ios', 'ipados', 'macos', 'windows', 'linux', 'android', 'other'];
    private const MANAGEMENT_LEVELS = ['full', 'manual'];

    private Database $db;
    private Ipam $ipam;
    private PeerSource $peers;
    private AuditTrail $audit;
    /**
     * Max non-revoked devices per user; null = unlimited (spec default).
     * The ONLY refusal an addition can meet here, and it is administrative
     * hygiene from M03 — never commercial: the plugin carries no licence,
     * no cap and no verdict (ADR 0018, D16; forbidden rule #10).
     */
    private ?int $maxDevicesPerUser;

    public function __construct(
        Database $db,
        Ipam $ipam,
        PeerSource $peers,
        AuditTrail $audit,
        ?int $maxDevicesPerUser = null
    ) {
        $this->db = $db;
        $this->ipam = $ipam;
        $this->peers = $peers;
        $this->audit = $audit;
        $this->maxDevicesPerUser = $maxDevicesPerUser;
    }

    /**
     * Enroll a device: validate, allocate an address, store as 'pending'.
     * The public key must be unknown to the TARGET instance, managed or not
     * (live peers included); the same physical device enrolling on another
     * instance is a distinct entity with its own key pair.
     *
     * @param array{
     *   user_id: string, instance_id: string, label: string, platform: string,
     *   management_level: string, public_key: string, device_token_hash: string
     * } $req
     * @param string $actorType 'admin' | 'device' | 'system' (enrollment flows differ, M04).
     * @return array<string, mixed> the stored device row.
     * @throws DomainException NOT_FOUND | USER_DISABLED | VALIDATION_FAILED |
     *         PUBLIC_KEY_IN_USE | DEVICE_LIMIT_REACHED | POOL_EXHAUSTED.
     */
    public function enroll(array $req, string $actorType, string $actorRef): array
    {
        $label = \trim($req['label']);
        if ($label === '') {
            throw new DomainException('VALIDATION_FAILED', 'Device label must not be empty.');
        }
        if (!\in_array($req['platform'], self::PLATFORMS, true)) {
            throw new DomainException('VALIDATION_FAILED', "Unknown platform '{$req['platform']}'.");
        }
        if (!\in_array($req['management_level'], self::MANAGEMENT_LEVELS, true)) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Unknown management level '{$req['management_level']}'."
            );
        }
        PublicKey::assertValid($req['public_key']);

        $publicSurface = $actorType !== 'admin';
        return $this->enrollInTransaction($req, $label, $actorType, $actorRef, $publicSurface);
    }

    /**
     * @param array<string, mixed> $req
     * @return array<string, mixed>
     */
    private function enrollInTransaction(
        array $req,
        string $label,
        string $actorType,
        string $actorRef,
        bool $publicSurface
    ): array {
        return $this->db->transaction(function (Database $db) use ($req, $label, $actorType, $actorRef, $publicSurface): array {
            $user = $db->query('SELECT * FROM users WHERE id = :id', [':id' => $req['user_id']]);
            if ($user === []) {
                throw new DomainException('NOT_FOUND', "User '{$req['user_id']}' does not exist.");
            }
            if ($user[0]['status'] !== 'active') {
                throw new DomainException(
                    'USER_DISABLED',
                    "User '{$user[0]['slug']}' is disabled; enrollment requires an active user."
                );
            }

            $instance = $db->query('SELECT * FROM instances WHERE id = :id', [':id' => $req['instance_id']]);
            if ($instance === []) {
                throw new DomainException('NOT_FOUND', "Declared instance '{$req['instance_id']}' does not exist.");
            }
            $instance = $instance[0];
            if ((int)$instance['enabled'] !== 1) {
                throw new DomainException(
                    'VALIDATION_FAILED',
                    "Instance '{$instance['label']}' is disabled; no enrollment while disabled."
                );
            }

            if ($this->maxDevicesPerUser !== null) {
                $count = (int)$db->scalar(
                    "SELECT COUNT(*) FROM devices WHERE user_id = :u AND status != 'revoked'",
                    [':u' => $req['user_id']]
                );
                if ($count >= $this->maxDevicesPerUser) {
                    throw new DomainException(
                        'DEVICE_LIMIT_REACHED',
                        "User '{$user[0]['slug']}' already has $count device(s); " .
                        "the limit is {$this->maxDevicesPerUser}. Revoke a device first."
                    );
                }
            }

            $this->assertKeyUnknown($instance, $req['public_key']);

            $id = Ulid::generate();
            $alloc = $this->ipam->allocate($req['instance_id']);
            $now = Database::utcNow();
            $db->run(
                "INSERT INTO devices (id, user_id, label, platform, management_level, instance_id,
                                      public_key, ip_host_octet, ip_address, device_token_hash,
                                      status, enrolled_at, key_created_at, created_at, updated_at)
                 VALUES (:id, :user, :label, :platform, :level, :instance,
                         :pubkey, :octet, :ip, :token_hash,
                         'pending', :now, :now, :now, :now)",
                [
                    ':id' => $id,
                    ':user' => $req['user_id'],
                    ':label' => $label,
                    ':platform' => $req['platform'],
                    ':level' => $req['management_level'],
                    ':instance' => $req['instance_id'],
                    ':pubkey' => $req['public_key'],
                    ':octet' => $alloc['host_octet'],
                    ':ip' => $alloc['ip_address'],
                    ':token_hash' => $req['device_token_hash'],
                    ':now' => $now,
                ]
            );
            $this->ipam->bindDevice($req['instance_id'], $alloc['host_octet'], $id);
            $this->audit->record($actorType, $actorRef, 'device.enroll', 'device', $id, 'success', [
                'user_id' => $req['user_id'],
                'instance_id' => $req['instance_id'],
                'public_key' => PublicKey::fingerprint($req['public_key']),
                'ip_address' => $alloc['ip_address'],
            ]);
            return $this->get($id);
        });
    }

    /**
     * Mark a pending device active, once the provisioner has applied its
     * peer (M06 callback). Idempotent on an already-active device, so a
     * provisioner retry is harmless.
     *
     * @throws DomainException NOT_FOUND | DEVICE_NOT_ACTIVE on any other state.
     */
    public function activate(string $deviceId): void
    {
        $device = $this->get($deviceId);
        if ($device['status'] === 'active') {
            return;
        }
        if ($device['status'] !== 'pending') {
            throw new DomainException(
                'DEVICE_NOT_ACTIVE',
                "Cannot activate device '{$device['label']}' in status '{$device['status']}'; " .
                'only a pending device becomes active.'
            );
        }
        $this->db->run(
            "UPDATE devices SET status = 'active', updated_at = :now WHERE id = :id",
            [':now' => Database::utcNow(), ':id' => $deviceId]
        );
        $this->audit->record('system', 'provisioner', 'device.activate', 'device', $deviceId);
    }

    /**
     * Rename a device — metadata only, no effect on the peer (the peer name
     * is rebuilt from current data by M06).
     *
     * @param string $actorRef admin identity for the audit trail.
     * @throws DomainException NOT_FOUND | VALIDATION_FAILED on empty label.
     */
    public function rename(string $deviceId, string $label, string $actorRef): void
    {
        $label = \trim($label);
        if ($label === '') {
            throw new DomainException('VALIDATION_FAILED', 'Device label must not be empty.');
        }
        $device = $this->get($deviceId);
        $this->db->run(
            'UPDATE devices SET label = :label, updated_at = :now WHERE id = :id',
            [':label' => $label, ':now' => Database::utcNow(), ':id' => $deviceId]
        );
        $this->audit->record('admin', $actorRef, 'device.rename', 'device', $deviceId, 'success', [
            'from' => $device['label'],
            'to' => $label,
        ]);
    }

    /**
     * Move one device between 'full' and 'manual' — metadata only, like
     * rename: no peer is touched, no key changes, no tunnel is affected.
     *
     * It exists because the level was written once at enrollment and could
     * never be changed afterwards, which made the fleet count a one-way
     * ratchet. `Enroll\Bundles` counts 'full' devices and publishes the
     * number; a device enrolled by the app was 'full' for life, so the only
     * way for a site to lower that number was to REVOKE a device — to cut
     * somebody's access. Being able to say "this one takes its .conf and
     * polls nothing" is ordinary device administration, and it is the
     * missing half of a number the plugin already publishes.
     *
     * Counting is not gating and neither is this: the plugin still reads no
     * key, holds no tier and issues no verdict (ADR 0018, D16; forbidden
     * rule #10). What a client binary does with the published number is
     * decided somewhere this repository does not reach.
     *
     * What the level actually changes on this side is one thing only: a
     * rotation issues an out-of-band rekey token for a 'manual' device,
     * which cannot re-key itself (M05, RotationService). Nothing refuses a
     * 'manual' device at the device API, so a demoted device whose app is
     * still polling keeps working — the level describes intent, it does not
     * enforce it.
     *
     * @param string $level 'full' | 'manual'.
     * @param string $actorRef admin identity for the audit trail.
     * @throws DomainException NOT_FOUND | VALIDATION_FAILED on any other level.
     */
    public function setManagementLevel(string $deviceId, string $level, string $actorRef): void
    {
        if (!\in_array($level, self::MANAGEMENT_LEVELS, true)) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Unknown management level '{$level}'."
            );
        }
        $device = $this->get($deviceId);
        if ((string)$device['management_level'] === $level) {
            return; // Idempotent, and no audit entry for a change that is not one.
        }
        $this->db->run(
            'UPDATE devices SET management_level = :level, updated_at = :now WHERE id = :id',
            [':level' => $level, ':now' => Database::utcNow(), ':id' => $deviceId]
        );
        $this->audit->record('admin', $actorRef, 'device.set_management', 'device', $deviceId, 'success', [
            'from' => (string)$device['management_level'],
            'to' => $level,
        ]);
    }

    /**
     * Revoke one device: state change + quarantined address + ONE audit
     * entry, returning the peer-removal intent for the provisioner.
     * Idempotent: revoking an already-revoked device returns null.
     *
     * @param string $actorType 'admin' | 'device' | 'system' (audit).
     * @param string $actorRef actor identity for the audit trail.
     * @return ?array{device_id: string, wg_instance_ref: string, public_key: string}
     * @throws DomainException NOT_FOUND.
     */
    public function revoke(string $deviceId, string $actorType, string $actorRef): ?array
    {
        return $this->db->transaction(function () use ($deviceId, $actorType, $actorRef): ?array {
            $intent = $this->revokeQuietly($deviceId);
            if ($intent !== null) {
                $this->audit->record($actorType, $actorRef, 'device.revoke', 'device', $deviceId, 'success', [
                    'public_key' => PublicKey::fingerprint((string)$intent['public_key']),
                ]);
            }
            return $intent;
        });
    }

    /**
     * Revocation core WITHOUT its own audit entry — for bulk operations
     * that must produce a single intent entry (Users::disable). Callers
     * other than revoke() and Users are a design smell.
     *
     * @return ?array{device_id: string, wg_instance_ref: string, public_key: string}
     *         null when the device is already revoked.
     * @throws DomainException NOT_FOUND.
     */
    public function revokeQuietly(string $deviceId): ?array
    {
        $device = $this->get($deviceId);
        if ($device['status'] === 'revoked') {
            return null;
        }
        $this->db->run(
            "UPDATE devices SET status = 'revoked', updated_at = :now WHERE id = :id",
            [':now' => Database::utcNow(), ':id' => $deviceId]
        );
        $this->ipam->release($device['instance_id'], (int)$device['ip_host_octet']);
        $wgRef = $this->db->scalar(
            'SELECT wg_instance_ref FROM instances WHERE id = :id',
            [':id' => $device['instance_id']]
        );
        return [
            'device_id' => $deviceId,
            'wg_instance_ref' => (string)$wgRef,
            'public_key' => $device['public_key'],
        ];
    }

    /**
     * @return array<string, mixed>
     * @throws DomainException NOT_FOUND.
     */
    public function get(string $deviceId): array
    {
        $rows = $this->db->query('SELECT * FROM devices WHERE id = :id', [':id' => $deviceId]);
        if ($rows === []) {
            throw new DomainException('NOT_FOUND', "Device '$deviceId' does not exist.");
        }
        return $rows[0];
    }

    /**
     * @param array<string, mixed> $instance instances row.
     * @throws DomainException PUBLIC_KEY_IN_USE when the key is already
     *         known to this instance — as a stored device (any status) or
     *         as a live peer on the firewall.
     */
    private function assertKeyUnknown(array $instance, string $publicKey): void
    {
        $known = $this->db->scalar(
            'SELECT COUNT(*) FROM devices WHERE instance_id = :i AND public_key = :k',
            [':i' => $instance['id'], ':k' => $publicKey]
        );
        if ((int)$known === 0) {
            foreach ($this->peers->livePeers($instance['wg_instance_ref']) as $peer) {
                if ($peer['public_key'] === $publicKey) {
                    $known = 1;
                    break;
                }
            }
        }
        if ((int)$known !== 0) {
            throw new DomainException(
                'PUBLIC_KEY_IN_USE',
                "This public key is already known on instance '{$instance['label']}'. " .
                'Each device enrollment must use a freshly generated key pair.'
            );
        }
    }
}
