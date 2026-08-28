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
 * Admin API façade (M08): projects the delivered service layers (M03–M06
 * domain, M04 tokens, M05 rotation/revocation, M09 exposure state) onto
 * the exact payload
 * shapes of the /admin/* operations in protocol/openapi.yaml. Controllers
 * stay thin: JSON I/O, authentication and HTTP status mapping only.
 *
 * Framework-free so every contract shape is testable on the target
 * runtime. Errors surface as DomainException / ProvisionException /
 * StoreException carrying stable M01 codes; HttpError maps them.
 *
 * Multi-device operations (disableUser, withdrawInstance) follow the M05
 * sequence — peers deleted from the firewall FIRST, ONE commit for the
 * whole batch (never one reconfigure per peer) — so a firewall failure
 * leaves every device untouched and retryable, and no device ever reads
 * as revoked while its tunnel still works. The mirror case: a store
 * failure AFTER the committed batch cannot undo it — the error (INTERNAL)
 * says the firewall is now ahead and that reconciliation will flag the
 * drift (recordAfterFirewall).
 */

namespace OPNsense\Paart\Admin;

use OPNsense\Paart\Domain\Devices;
use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Domain\Instances;
use OPNsense\Paart\Domain\Users;
use OPNsense\Paart\Enroll\EnrollTokens;
use OPNsense\Paart\Enroll\Portal;
use OPNsense\Paart\Exposure\ExposureService;
use OPNsense\Paart\Provision\PeerProvisioner;
use OPNsense\Paart\Rotation\Reconciliation;
use OPNsense\Paart\Rotation\RotationService;
use OPNsense\Paart\Store\Database;

final class AdminService
{
    /**
     * URL scheme of the enrollment link and its QR code — frozen for /api/v1
     * (ADR 0007, protocol/enrollment-link.md). Deliberately decoupled from the
     * product's commercial name, which is still open: changing it would break
     * every QR already handed out and the scheme the Apple app registers.
     */
    private const ENROLL_URL_SCHEME = 'lwpcvpn';

    private Database $db;
    private Users $users;
    private Devices $devices;
    private Instances $instances;
    private EnrollTokens $tokens;
    private RotationService $rotation;
    private Reconciliation $reconciliation;
    private PeerProvisioner $provisioner;
    /** Public enrollment host (host[:port], M01 setting; M09 exposes it) used to build enroll links. */
    private ?string $enrollHost;
    /** Optional SPKI SHA-256 pin (base64) for the enrollment host (ADR 0004). */
    private ?string $enrollPin;
    /** M09 exposure state for health(); null reads as not exposed. */
    private ?ExposureService $exposure;

    /**
     * Wired by App\Container from the delivered service layers.
     *
     * @param Database $db store handle (direct reads for list/health shapes)
     * @param Users $users M03 user lifecycle
     * @param Devices $devices M03 device lifecycle
     * @param Instances $instances M03 declared-instance registry (withdrawal)
     * @param EnrollTokens $tokens M04 token issuance/revocation
     * @param RotationService $rotation M05 rotation/revocation sequences
     * @param Reconciliation $reconciliation M05 drift reporting (health)
     * @param PeerProvisioner $provisioner M06 firewall writes (disable batches)
     * @param ?string $enrollHost public host[:port] printed into enroll links;
     *                            null/blank = token issuance refuses (M08 setting)
     * @param ?string $enrollPin optional SPKI SHA-256 pin (base64) added to
     *                           enroll links (ADR 0004); null/blank = no pin
     * @param ?ExposureService $exposure M09 exposure state for the health
     *                                   payload; null = reported as not exposed
     */
    public function __construct(
        Database $db,
        Users $users,
        Devices $devices,
        Instances $instances,
        EnrollTokens $tokens,
        RotationService $rotation,
        Reconciliation $reconciliation,
        PeerProvisioner $provisioner,
        ?string $enrollHost = null,
        ?string $enrollPin = null,
        ?ExposureService $exposure = null
    ) {
        $this->db = $db;
        $this->users = $users;
        $this->devices = $devices;
        $this->instances = $instances;
        $this->tokens = $tokens;
        $this->rotation = $rotation;
        $this->reconciliation = $reconciliation;
        $this->provisioner = $provisioner;
        $this->enrollHost = self::blankToNull($enrollHost);
        $this->enrollPin = self::blankToNull($enrollPin);
        $this->exposure = $exposure;
    }

    // ---------------------------------------------------------------- users

    /**
     * GET /admin/users.
     *
     * @param ?string $status contract status filter ('active'/'disabled');
     *                        null lists every status.
     * @param ?string $q substring matched against slug and display name;
     *                   null or '' disables the search.
     * @return array{users: array<int, array<string, mixed>>}
     */
    public function listUsers(?string $status = null, ?string $q = null): array
    {
        $where = [];
        $params = [];
        if ($status !== null) {
            $where[] = 'u.status = :status';
            $params[':status'] = $status;
        }
        if ($q !== null && $q !== '') {
            $where[] = '(u.slug LIKE :q OR u.display_name LIKE :q)';
            $params[':q'] = '%' . $q . '%';
        }
        $rows = $this->db->query(
            self::USER_SELECT .
            ($where === [] ? '' : ' WHERE ' . \implode(' AND ', $where)) .
            ' ORDER BY u.slug',
            $params
        );
        return ['users' => \array_map([self::class, 'userPayload'], $rows)];
    }

    /**
     * POST /admin/users.
     *
     * @param array<string, mixed> $body contract createUser request body.
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array<string, mixed> User payload.
     * @throws DomainException VALIDATION_FAILED.
     */
    public function createUser(array $body, string $actorRef): array
    {
        self::allowKeys($body, ['slug', 'display_name', 'email'], ['slug', 'display_name']);
        $row = $this->users->create(
            (string)$body['slug'],
            (string)$body['display_name'],
            isset($body['email']) ? (string)$body['email'] : null,
            $actorRef
        );
        return $this->userRow((string)$row['id']);
    }

    /**
     * PATCH /admin/users/{id} — update the mutable profile fields
     * (display_name, email). The slug is immutable in v1 (M03), so it is
     * not an accepted key; an empty email clears the address.
     *
     * @param string $id user ULID.
     * @param array<string, mixed> $body contract updateUser request body.
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array<string, mixed> User payload.
     * @throws DomainException NOT_FOUND | VALIDATION_FAILED.
     */
    public function updateUser(string $id, array $body, string $actorRef): array
    {
        self::allowKeys($body, ['display_name', 'email'], ['display_name']);
        $this->users->updateProfile(
            $id,
            (string)$body['display_name'],
            self::blankToNull(isset($body['email']) ? (string)$body['email'] : null),
            $actorRef
        );
        return $this->userRow($id);
    }

    /**
     * DELETE /admin/users/{id} — disable the user, revoking every
     * non-revoked device: peers deleted firewall-first in ONE batch commit,
     * then the store transaction (single audit intent, Users::disable),
     * then the revoked devices' open rotations and rekey tokens are closed
     * exactly as a unit revocation would (M05). Idempotent on a disabled
     * user.
     *
     * @param string $id user ULID.
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array{user: array<string, mixed>, revoked_device_ids: array<int, string>}
     * @throws DomainException NOT_FOUND | PROVISIONING_UNAVAILABLE |
     *         INSTANCE_UNAVAILABLE (firewall failure: nothing changed) |
     *         INTERNAL (store failure AFTER the peer batch: the peers are
     *         already gone — see recordAfterFirewall).
     */
    public function disableUser(string $id, string $actorRef): array
    {
        $user = $this->users->get($id);
        $revokedIds = [];
        if ($user['status'] !== 'disabled') {
            $targets = $this->db->query(
                "SELECT d.id, d.public_key, i.wg_instance_ref
                 FROM devices d JOIN instances i ON i.id = d.instance_id
                 WHERE d.user_id = :u AND d.status != 'revoked' ORDER BY d.id",
                [':u' => $id]
            );
            foreach ($targets as $target) {
                $this->provisioner->deletePeer(
                    (string)$target['wg_instance_ref'],
                    (string)$target['public_key']
                );
            }
            if ($targets !== []) {
                $this->provisioner->commit();
            }

            $record = function () use ($id, $actorRef, &$revokedIds): void {
                $intents = $this->users->disable($id, $actorRef);
                $revokedIds = \array_map(
                    static fn(array $intent): string => (string)$intent['device_id'],
                    $intents
                );
                $this->closeRotationArtifacts($revokedIds);
            };
            if ($targets === []) {
                // Nothing was committed to the firewall: a store failure
                // here leaves nothing ahead, the plain message is the truth.
                $record();
            } else {
                $this->recordAfterFirewall(
                    "the user's peers were already deleted in one batch",
                    $record
                );
            }
        }
        return ['user' => $this->userRow($id), 'revoked_device_ids' => $revokedIds];
    }

    /**
     * POST /admin/users/{id}/rotate.
     *
     * rekey_tokens carries the one-time plaintext for 'manual' devices
     * (additive contract field): without it the admin could never hand the
     * re-download link over, the secret is not retrievable later.
     *
     * @param string $id user ULID.
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array{
     *   rotating_device_ids: array<int, string>,
     *   rekey_tokens: array<int, array{device_id: string, rekey_token: string,
     *                                  enroll_link: ?string, portal_link: ?string}>
     * }
     * @throws DomainException NOT_FOUND | USER_DISABLED.
     */
    public function rotateUserDevices(string $id, string $actorRef): array
    {
        $out = $this->rotation->initiateForUser($id, $actorRef);
        $rekey = [];
        foreach ($out['initiated'] as $item) {
            if ($item['rekey_token'] !== null) {
                $rekey[] = [
                    'device_id' => (string)$item['device_id'],
                    'rekey_token' => (string)$item['rekey_token'],
                    'enroll_link' => $this->tryEnrollLink((string)$item['rekey_token']),
                    'portal_link' => $this->portalLink(
                        (string)$item['rekey_token'],
                        (string)$this->devices->get((string)$item['device_id'])['label']
                    ),
                ];
            }
        }
        return [
            'rotating_device_ids' => \array_map(
                static fn(array $item): string => (string)$item['device_id'],
                $out['initiated']
            ),
            'rekey_tokens' => $rekey,
        ];
    }

    // -------------------------------------------------------------- devices

    /**
     * GET /admin/devices.
     *
     * @param ?string $userId owner ULID filter; null lists every user.
     * @param ?string $instanceId declared instance ULID filter; null lists all.
     * @param ?string $status device status filter; null lists every status.
     * @return array{devices: array<int, array<string, mixed>>}
     */
    public function listDevices(
        ?string $userId = null,
        ?string $instanceId = null,
        ?string $status = null
    ): array {
        $where = [];
        $params = [];
        if ($userId !== null) {
            $where[] = 'user_id = :user';
            $params[':user'] = $userId;
        }
        if ($instanceId !== null) {
            $where[] = 'instance_id = :instance';
            $params[':instance'] = $instanceId;
        }
        if ($status !== null) {
            $where[] = 'status = :status';
            $params[':status'] = $status;
        }
        $rows = $this->db->query(
            'SELECT * FROM devices' .
            ($where === [] ? '' : ' WHERE ' . \implode(' AND ', $where)) .
            ' ORDER BY id',
            $params
        );
        return ['devices' => \array_map([self::class, 'devicePayload'], $rows)];
    }

    /**
     * PATCH /admin/devices/{id}.
     *
     * @param string $id device ULID.
     * @param string $label new device label (validated by Devices::rename).
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array<string, mixed> Device payload.
     * @throws DomainException NOT_FOUND | VALIDATION_FAILED.
     */
    public function renameDevice(string $id, string $label, string $actorRef): array
    {
        $this->devices->rename($id, $label, $actorRef);
        return self::devicePayload($this->devices->get($id));
    }

    /**
     * POST /admin/devices/{id}/manage — move a device between 'full' and
     * 'manual'. Metadata only, like rename: no peer, no key, no tunnel.
     *
     * A sub-command rather than a field on the PATCH, for the reason the
     * neighbours below are sub-commands: PATCH carries what a device IS
     * called, these carry what is DONE to it. It also leaves `renameDevice`
     * untouched — several specs and design notes name that operation as the
     * reason a device's own surface cannot rename itself, and renaming it
     * would have made them all point at nothing.
     *
     * @param string $id device ULID.
     * @param string $level 'full' | 'manual' (validated by Devices).
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array<string, mixed> Device payload.
     * @throws DomainException NOT_FOUND | VALIDATION_FAILED.
     */
    public function manageDevice(string $id, string $level, string $actorRef): array
    {
        $this->devices->setManagementLevel($id, $level, $actorRef);
        return self::devicePayload($this->devices->get($id));
    }

    /**
     * POST /admin/devices/{id}/rotate — rekey_token / enroll_link /
     * portal_link are the additive fields for 'manual' devices (null for
     * 'full' ones); the portal link carries the device name as its
     * fragment hint (ADR 0010).
     *
     * @param string $id device ULID.
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array<string, mixed> Device payload + rekey_token + enroll_link + portal_link.
     * @throws DomainException NOT_FOUND | DEVICE_NOT_ACTIVE.
     */
    public function rotateDevice(string $id, string $actorRef): array
    {
        $out = $this->rotation->initiate($id, $actorRef);
        return $this->deviceWithRekey($id, $out['rekey_token']);
    }

    /**
     * POST /admin/devices/{id}/reissue — re-arm a stuck rotation (M05
     * explicit re-issue; additive contract operation, same response shape
     * as /rotate, portal_link included).
     *
     * @param string $id device ULID.
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array<string, mixed> Device payload + rekey_token + enroll_link + portal_link.
     * @throws DomainException NOT_FOUND | DEVICE_NOT_ACTIVE | ROTATION_NOT_PENDING.
     */
    public function reissueDevice(string $id, string $actorRef): array
    {
        $out = $this->rotation->reissue($id, $actorRef);
        return $this->deviceWithRekey($id, $out['rekey_token']);
    }

    /**
     * POST /admin/devices/{id}/revoke and DELETE /admin/devices/{id}.
     * Idempotent: an already-revoked device is returned unchanged (200).
     *
     * @param string $id device ULID.
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array<string, mixed> Device payload.
     * @throws DomainException NOT_FOUND | PROVISIONING_UNAVAILABLE |
     *         INSTANCE_UNAVAILABLE (nothing changed; retry) | INTERNAL
     *         (store failure AFTER the peer delete: the peer is already
     *         gone — see RotationService::revokeDevice).
     */
    public function revokeDevice(string $id, string $actorRef): array
    {
        $row = $this->rotation->revokeDevice($id, $actorRef) ?? $this->devices->get($id);
        return self::devicePayload($row);
    }

    // ------------------------------------------------------------- networks

    /**
     * What removing a declared instance from management would cost (M08
     * Networks: a strong warning listing the devices affected).
     *
     * Read-only and side-effect free — the screen calls it to build the
     * warning BEFORE the admin chooses, so it must never be the thing that
     * changes anything. It reads the store alone: the firewall is not
     * consulted, both because the answer is about what the plugin knows
     * and because an unreachable firewall must not stop an admin from
     * seeing what is at stake.
     *
     * `devices` lists what is still in service — the rows whose peers the
     * choice is about. Revoked devices are counted, never listed: their
     * tunnels are already dead and naming them would bury the live ones.
     *
     * `active_tokens` counts the still-usable *enrollment* tokens bound
     * to the instance — pending invitations the withdrawal would void.
     * Rekey tokens are excluded, as everywhere the admin inventory is
     * concerned (ADR 0006): rotation plumbing that falls with its device
     * rows either way.
     *
     * @param string $id declared instance ULID (mirror row).
     * @return array{
     *   instance: array{id: string, label: string, wg_instance_ref: string},
     *   devices: array<int, array{id: string, label: string,
     *                             user_display_name: string,
     *                             ip_address: ?string, status: string}>,
     *   live_count: int, revoked_count: int, active_tokens: int
     * }
     * @throws DomainException NOT_FOUND.
     */
    public function instanceWithdrawalImpact(string $id): array
    {
        $instance = $this->instances->get($id);
        $rows = $this->db->query(
            "SELECT d.id, d.label, d.ip_address, d.status, u.display_name
             FROM devices d JOIN users u ON u.id = d.user_id
             WHERE d.instance_id = :id AND d.status != 'revoked'
             ORDER BY u.display_name, d.label, d.id",
            [':id' => $id]
        );
        return [
            'instance' => [
                'id' => (string)$instance['id'],
                'label' => (string)$instance['label'],
                'wg_instance_ref' => (string)$instance['wg_instance_ref'],
            ],
            'devices' => \array_map(
                static fn(array $r): array => [
                    'id' => (string)$r['id'],
                    'label' => (string)$r['label'],
                    'user_display_name' => (string)$r['display_name'],
                    'ip_address' => $r['ip_address'] !== null ? (string)$r['ip_address'] : null,
                    'status' => (string)$r['status'],
                ],
                $rows
            ),
            'live_count' => \count($rows),
            'revoked_count' => (int)$this->db->scalar(
                "SELECT COUNT(*) FROM devices WHERE instance_id = :id AND status = 'revoked'",
                [':id' => $id]
            ),
            'active_tokens' => (int)$this->db->scalar(
                "SELECT COUNT(*) FROM enroll_tokens
                 WHERE instance_id = :id AND purpose = 'enroll' AND consumed_at IS NULL
                   AND used_count < max_uses AND expires_at > :now",
                [':id' => $id, ':now' => Database::utcNow()]
            ),
        ];
    }

    /**
     * Remove a declared instance from management, having been told what to
     * do with the peers of the devices still in service (M08 Networks).
     *
     * The two dispositions differ in exactly one step, and the difference
     * is irreversible:
     *
     *  - **'keep'** — nothing is written to the firewall. Those peers stay
     *    up and their tunnels keep working; the plugin forgets them, and
     *    from the next second they are peers it did not create.
     *  - **'delete'** — every live peer is removed FIRST and in ONE batch
     *    (deletePeer × N, a single commit — never one reconfigure per
     *    peer), exactly as disableUser does, so a firewall failure leaves
     *    every peer up, the store untouched and the whole call retryable.
     *    It must happen before the withdrawal, while the instance is still
     *    declared: the provisioner refuses to write to an undeclared one
     *    (M06) and forbidden rule #3 says the same.
     *
     * The store purge then follows in Instances::undeclare, which records
     * the single audit entry — including the public keys of those devices,
     * the only trace left of which peers were abandoned or cut off.
     *
     * The declaration node of config.xml is not written here: removing it
     * belongs to the Networks controller, which calls this first and saves
     * afterwards. The 'delete' branch does rewrite config.xml all the
     * same — the peer batch goes through the local WireGuard API, i.e.
     * another process — which is exactly why that controller reloads its
     * DOM from disk before saving (a stale DOM would resurrect the
     * deleted peers; seen live, session 16).
     *
     * @param string $id declared instance ULID (mirror row).
     * @param string $peerDisposition 'keep' or 'delete' — no default, the
     *        admin's choice is the whole point (forbidden rule #4).
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array{instance_id: string, label: string,
     *               peer_disposition: string, peers_deleted: int}
     *         peers_deleted counts the peers REMOVED from the firewall, which
     *         under drift is fewer than the devices targeted (a peer someone
     *         deleted by hand is already gone). It is therefore also the
     *         caller's test for "did a reconfigure happen", i.e. was
     *         config.xml rewritten from another process.
     * @throws DomainException NOT_FOUND | VALIDATION_FAILED (unknown
     *         disposition) | PROVISIONING_UNAVAILABLE | INSTANCE_UNAVAILABLE
     *         (firewall failure while deleting: nothing was changed) |
     *         INTERNAL (store failure AFTER the peer batch: the peers are
     *         already gone — see recordAfterFirewall).
     */
    public function withdrawInstance(string $id, string $peerDisposition, string $actorRef): array
    {
        $instance = $this->instances->get($id);
        if (!\in_array($peerDisposition, Instances::PEER_DISPOSITIONS, true)) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Removing '{$instance['label']}' from management needs an explicit choice for " .
                "the peers of its devices: 'keep' or 'delete'. Nothing was changed."
            );
        }
        $deleted = 0;
        if ($peerDisposition === 'delete') {
            $targets = $this->db->query(
                "SELECT public_key FROM devices
                 WHERE instance_id = :id AND status != 'revoked' ORDER BY id",
                [':id' => $id]
            );
            foreach ($targets as $target) {
                // Count what the firewall actually lost, not what we aimed
                // at: deletePeer is a no-op on a key already absent (drift,
                // or a replayed call). Counting targets would overstate the
                // damage to the admin AND make the caller's "was config.xml
                // rewritten?" test wrong, since a batch with nothing to
                // delete stages nothing and commit() reconfigures nothing.
                $removed = $this->provisioner->deletePeer(
                    (string)$instance['wg_instance_ref'],
                    (string)$target['public_key']
                );
                $deleted += $removed ? 1 : 0;
            }
            if ($targets !== []) {
                $this->provisioner->commit();
            }
        }
        if ($deleted > 0) {
            $this->recordAfterFirewall(
                "the $deleted live peer(s) of '{$instance['label']}' were already deleted",
                fn() => $this->instances->undeclare($id, $actorRef, $peerDisposition)
            );
        } else {
            // Nothing reached the firewall ('keep', 'delete' with no live
            // device, or every target already absent — commit() stages
            // nothing then): a store failure here leaves nothing ahead, the
            // plain message is the truth.
            $this->instances->undeclare($id, $actorRef, $peerDisposition);
        }
        return [
            'instance_id' => (string)$instance['id'],
            'label' => (string)$instance['label'],
            'peer_disposition' => $peerDisposition,
            'peers_deleted' => $deleted,
        ];
    }

    // --------------------------------------------------------------- tokens

    /**
     * GET /admin/tokens — active enrollment tokens only: still valid,
     * not consumed, uses left. Rekey tokens are rotation plumbing (ADR
     * 0006), not admin inventory, and never listed here.
     *
     * @return array{tokens: array<int, array<string, mixed>>}
     */
    public function listTokens(): array
    {
        $rows = $this->db->query(
            "SELECT * FROM enroll_tokens
             WHERE purpose = 'enroll' AND consumed_at IS NULL
               AND used_count < max_uses AND expires_at > :now
             ORDER BY id DESC",
            [':now' => Database::utcNow()]
        );
        return ['tokens' => \array_map([self::class, 'tokenPayload'], $rows)];
    }

    /**
     * POST /admin/tokens. The plaintext token and the ready-to-encode
     * enroll link are returned ONCE (contract rule). Refuses to issue when
     * no enrollment host is configured: a token nobody can use would only
     * age out — the error states that nothing was issued.
     *
     * @param array<string, mixed> $body contract issueToken request body.
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array<string, mixed> EnrollTokenInfo + token + enroll_link
     *         + portal_link (additive, M15; null when the composition has
     *         no exposure service).
     * @throws DomainException VALIDATION_FAILED | NOT_FOUND | USER_DISABLED.
     */
    public function issueToken(array $body, string $actorRef): array
    {
        self::allowKeys(
            $body,
            ['user_id', 'instance_id', 'label', 'max_uses', 'ttl_seconds'],
            ['user_id', 'instance_id']
        );
        if ($this->enrollHost === null) {
            throw new DomainException(
                'VALIDATION_FAILED',
                'No enrollment host is configured (Settings). No token was issued.'
            );
        }
        $issued = $this->tokens->issue(
            (string)$body['user_id'],
            (string)$body['instance_id'],
            (string)($body['label'] ?? ''),
            $actorRef,
            (int)($body['max_uses'] ?? 1),
            isset($body['ttl_seconds']) ? (int)$body['ttl_seconds'] : null
        );
        return self::tokenPayload($issued['row']) + [
            'token' => $issued['token'],
            'enroll_link' => $this->enrollLink($issued['token']),
            'portal_link' => $this->portalLink($issued['token']),
        ];
    }

    /**
     * DELETE /admin/tokens/{id}. Terminal and idempotent.
     *
     * @param string $id enrollment token ULID.
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array<string, mixed> EnrollTokenInfo payload.
     * @throws DomainException NOT_FOUND.
     */
    public function revokeToken(string $id, string $actorRef): array
    {
        $this->tokens->revoke($id, $actorRef);
        $rows = $this->db->query('SELECT * FROM enroll_tokens WHERE id = :id', [':id' => $id]);
        return self::tokenPayload($rows[0]);
    }

    // ---------------------------------------------------------------- audit

    /**
     * GET /admin/audit — read-only, anti-chronological, paginated (M07).
     * Ordered by ULID, so by generation millisecond: entries recorded
     * within the same millisecond order arbitrarily between themselves
     * (Support\Ulid pads with pure randomness, not a monotonic counter).
     *
     * @param array<string, mixed> $filters contract query parameters
     *        (from, to, actor_ref, subject_ref, action, outcome, q, page,
     *        page_size); unknown keys are ignored (query strings carry
     *        harness noise, unlike JSON bodies).
     * @return array{entries: array<int, array<string, mixed>>, total: int}
     */
    public function queryAudit(array $filters = []): array
    {
        $where = [];
        $params = [];
        foreach (
            [
                'from' => ['occurred_at >= :from', ':from'],
                'to' => ['occurred_at <= :to', ':to'],
                'actor_ref' => ['actor_ref = :actor', ':actor'],
                'subject_ref' => ['subject_ref = :subject', ':subject'],
                'action' => ['action = :action', ':action'],
                'outcome' => ['outcome = :outcome', ':outcome'],
            ] as $key => [$sql, $param]
        ) {
            if (isset($filters[$key]) && $filters[$key] !== '') {
                $where[] = $sql;
                $params[$param] = (string)$filters[$key];
            }
        }
        if (isset($filters['q']) && $filters['q'] !== '') {
            $where[] = '(action LIKE :q OR actor_ref LIKE :q OR subject_ref LIKE :q OR detail_json LIKE :q)';
            $params[':q'] = '%' . (string)$filters['q'] . '%';
        }
        $clause = $where === [] ? '' : ' WHERE ' . \implode(' AND ', $where);

        // Contract bounds for page_size (default 50, maximum 200). Clamped
        // rather than refused: these arrive in a query string, where a stale
        // bookmark must still render a page instead of an error.
        $page = \max(1, (int)($filters['page'] ?? 1));
        $pageSize = \min(200, \max(1, (int)($filters['page_size'] ?? 50)));

        $total = (int)$this->db->scalar("SELECT COUNT(*) FROM audit_log$clause", $params);
        $rows = $this->db->query(
            "SELECT * FROM audit_log$clause ORDER BY id DESC LIMIT :limit OFFSET :offset",
            $params + [':limit' => $pageSize, ':offset' => ($page - 1) * $pageSize]
        );
        return [
            'entries' => \array_map([self::class, 'auditPayload'], $rows),
            'total' => $total,
        ];
    }

    // --------------------------------------------------------------- health

    /**
     * GET /admin/health — dashboard feed (M08). Reachability comes from the
     * provisioner's health check, drift from one reconciliation pass
     * (read-only by design, M05); an unreachable instance reports no drift
     * — absence of evidence is not evidence of removal. The exposure block
     * (M09) costs a handful of local API calls toward os-haproxy (presence,
     * service state, one search per owned collection); one 404 when absent.
     *
     * @return array<string, mixed> contract Health payload.
     */
    public function health(): array
    {
        $reachable = [];
        foreach ($this->provisioner->healthCheck()->instances as $probe) {
            $reachable[(string)$probe['wg_instance_ref']] = (bool)$probe['available'];
        }
        $findings = $this->reconciliation->run();

        $instances = [];
        foreach ($this->db->query('SELECT * FROM instances ORDER BY id') as $row) {
            $ref = (string)$row['wg_instance_ref'];
            $size = (int)$row['pool_end_octet'] - (int)$row['pool_start_octet'] + 1;
            $used = (int)$this->db->scalar(
                'SELECT COUNT(*) FROM ip_allocations WHERE instance_id = :id AND released_at IS NULL',
                [':id' => $row['id']]
            );
            $instance = [
                'id' => (string)$row['id'],
                'label' => (string)$row['label'],
                'reachable' => $reachable[$ref] ?? false,
                'pool' => [
                    'used' => $used,
                    'size' => $size,
                    // A zero-size pool reads as full (100): nothing is
                    // allocatable, which is what the dashboard must convey.
                    'occupancy_pct' => $size > 0 ? (int)\round($used * 100 / $size) : 100,
                ],
            ];
            if (isset($findings['instances'][$ref])) {
                $found = $findings['instances'][$ref];
                $instance['drift'] = [
                    'unmanaged' => \count($found['unmanaged']),
                    'missing' => \count($found['drift']),
                    'conflict' => \count($found['conflict']),
                    // Additive field: the alarming subset of 'unmanaged' —
                    // a live peer whose key belongs to a REVOKED device, so
                    // a removal that never took and access that is NOT cut
                    // (M05). Plain unmanaged peers are hand-managed ones,
                    // normal by D8; only this subset warrants an alert.
                    'stale_revoked' => \count(\array_filter(
                        $found['unmanaged'],
                        static fn(array $finding): bool => isset($finding['device_id'])
                    )),
                ];
            }
            $instances[] = $instance;
        }

        return [
            'storage' => [
                'engine' => 'sqlite',
                'schema_version' => (int)$this->db->scalar(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ),
                'ok' => true,
            ],
            'instances' => $instances,
            'pending_rotations' => (int)$this->db->scalar(
                "SELECT COUNT(*) FROM rotations WHERE state IN ('pending', 'applied')"
            ),
            'overdue_rotations' => (int)$this->db->scalar(
                "SELECT COUNT(*) FROM rotations WHERE state = 'expired'"
            ),
            // M09: mode from the HAProxy side (the generated frontend exists
            // and is enabled), the verification date from the store; the
            // additive `haproxy` field says whether os-haproxy is there at
            // all. summary() never throws — an unreachable HAProxy API reads
            // as internal_only/unreachable, and the rest of health() stands.
            'enrollment_exposure' => $this->exposure !== null
                ? $this->exposure->summary()
                : ['mode' => 'internal_only', 'last_verified_at' => null, 'haproxy' => 'absent'],
        ];
    }

    // ------------------------------------------------------------- payloads

    private const USER_SELECT = "SELECT u.*,
        (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.status != 'revoked')
            AS device_count,
        (SELECT MAX(d.last_seen_at) FROM devices d WHERE d.user_id = u.id) AS last_seen_at
        FROM users u";

    /**
     * @return array<string, mixed> single contract User payload.
     * @throws DomainException NOT_FOUND.
     */
    private function userRow(string $id): array
    {
        $rows = $this->db->query(self::USER_SELECT . ' WHERE u.id = :id', [':id' => $id]);
        if ($rows === []) {
            throw new DomainException('NOT_FOUND', "User '$id' does not exist.");
        }
        return self::userPayload($rows[0]);
    }

    /** @param array<string, mixed> $row users row + device_count + last_seen_at. */
    private static function userPayload(array $row): array
    {
        return [
            'id' => (string)$row['id'],
            'slug' => (string)$row['slug'],
            'display_name' => (string)$row['display_name'],
            'email' => $row['email'] !== null ? (string)$row['email'] : null,
            'status' => (string)$row['status'],
            'device_count' => (int)$row['device_count'],
            'last_seen_at' => $row['last_seen_at'] !== null ? (string)$row['last_seen_at'] : null,
        ];
    }

    /** @param array<string, mixed> $row devices row. */
    private static function devicePayload(array $row): array
    {
        $revoked = $row['status'] === 'revoked';
        return [
            'id' => (string)$row['id'],
            'user_id' => (string)$row['user_id'],
            'label' => (string)$row['label'],
            'platform' => (string)$row['platform'],
            'management_level' => (string)$row['management_level'],
            'instance_id' => (string)$row['instance_id'],
            // Contract: null once revoked — the address is quarantined, not his.
            'ip_address' => $revoked || $row['ip_address'] === null ? null : (string)$row['ip_address'],
            'status' => (string)$row['status'],
            'enrolled_at' => (string)$row['enrolled_at'],
            'last_seen_at' => $row['last_seen_at'] !== null ? (string)$row['last_seen_at'] : null,
            'last_handshake_at' => $row['last_handshake_at'] !== null ? (string)$row['last_handshake_at'] : null,
            'key_created_at' => (string)$row['key_created_at'],
            // Contract length: the first 8 base64 characters of the public
            // key — enough for an admin to match a row against 'wg show',
            // never enough to reconstruct the key itself.
            'public_key_fingerprint' => \substr((string)$row['public_key'], 0, 8),
        ];
    }

    /** @param array<string, mixed> $row enroll_tokens row. */
    private static function tokenPayload(array $row): array
    {
        return [
            'id' => (string)$row['id'],
            'user_id' => (string)$row['user_id'],
            'instance_id' => (string)$row['instance_id'],
            'label' => (string)$row['label'],
            'max_uses' => (int)$row['max_uses'],
            'used_count' => (int)$row['used_count'],
            'expires_at' => (string)$row['expires_at'],
        ];
    }

    /** @param array<string, mixed> $row audit_log row. */
    private static function auditPayload(array $row): array
    {
        return [
            'id' => (string)$row['id'],
            'occurred_at' => (string)$row['occurred_at'],
            'actor_type' => (string)$row['actor_type'],
            'actor_ref' => (string)$row['actor_ref'],
            'action' => (string)$row['action'],
            'subject_type' => (string)$row['subject_type'],
            'subject_ref' => (string)$row['subject_ref'],
            'outcome' => (string)$row['outcome'],
            'source_ip' => $row['source_ip'] !== null ? (string)$row['source_ip'] : null,
            'detail' => $row['detail_json'] !== null
                ? (array)\json_decode((string)$row['detail_json'], true)
                : [],
        ];
    }

    // -------------------------------------------------------------- helpers

    /** @return array<string, mixed> Device payload + rekey_token + enroll_link + portal_link. */
    private function deviceWithRekey(string $deviceId, ?string $rekeyToken): array
    {
        $device = $this->devices->get($deviceId);
        return self::devicePayload($device) + [
            'rekey_token' => $rekeyToken,
            'enroll_link' => $rekeyToken !== null ? $this->tryEnrollLink($rekeyToken) : null,
            'portal_link' => $rekeyToken !== null
                ? $this->portalLink($rekeyToken, (string)$device['label'])
                : null,
        ];
    }

    /**
     * The portal link for a token (M15, additive next to enroll_link):
     * the public /enroll/ form when the M09 exposure is applied, the
     * plugin's own path on the web GUI port otherwise — what a LAN
     * browser can reach in internal-only mode. Null without an
     * enrollment host, like enroll_link; also null when the composition
     * carries no exposure service (tests of the façade alone).
     *
     * @param string $token plaintext enrollment or rekey token.
     * @param string|null $deviceName for a rekey token, the label of the
     *        device it is bound to — the page shows it non-editable
     *        (Portal::link()); null for an enrollment token.
     * @return string|null absolute https:// URL, null when no host or no
     *         exposure service is composed.
     */
    private function portalLink(string $token, ?string $deviceName = null): ?string
    {
        if ($this->enrollHost === null || $this->exposure === null) {
            return null;
        }
        $status = $this->exposure->status();
        return Portal::link(
            $this->enrollHost,
            $token,
            $status['mode'] === 'haproxy',
            (string)$status['backend_port'],
            $deviceName
        );
    }

    /**
     * Close the rotation artifacts of freshly revoked devices, exactly as
     * a unit revocation does (M05): open rotations flagged 'failed',
     * outstanding rekey tokens retired.
     *
     * @param array<int, string> $deviceIds
     */
    private function closeRotationArtifacts(array $deviceIds): void
    {
        if ($deviceIds === []) {
            return;
        }
        $params = [];
        foreach (\array_values($deviceIds) as $i => $deviceId) {
            $params[":d$i"] = $deviceId;
        }
        $in = \implode(', ', \array_keys($params));
        $this->db->run(
            "UPDATE rotations SET state = 'failed'
             WHERE device_id IN ($in) AND state IN ('pending', 'applied')",
            $params
        );
        $this->db->run(
            "UPDATE enroll_tokens SET consumed_at = :now
             WHERE device_id IN ($in) AND purpose = 'rekey' AND consumed_at IS NULL",
            $params + [':now' => Database::utcNow()]
        );
    }

    /**
     * Run the store bookkeeping that follows an already-applied firewall
     * batch. When it fails, the one thing the admin must learn is that the
     * firewall is now AHEAD of the store — $applied names what already
     * happened there and cannot be undone by the failure. Reconciliation
     * (M05) flags the drift; it never repairs it. Same shape as
     * RotationService::recordAfterFirewall — each class keeps its own copy
     * so the wording stays next to the batches it covers; tests pin the
     * same message fragments in both (test_admin_service, test_rotation),
     * so a wording change here must land in the twin too.
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
     * Build the enrollment link (protocol/enrollment-link.md): host and token
     * mandatory, fp appended only when a pin is configured.
     *
     * @throws DomainException VALIDATION_FAILED when no host is configured.
     */
    private function enrollLink(string $token): string
    {
        if ($this->enrollHost === null) {
            throw new DomainException(
                'VALIDATION_FAILED',
                'No enrollment host is configured (Settings); cannot build an enroll link.'
            );
        }
        $link = self::ENROLL_URL_SCHEME . '://enroll?host=' . \rawurlencode($this->enrollHost)
            . '&token=' . \rawurlencode($token);
        if ($this->enrollPin !== null) {
            $link .= '&fp=' . \rawurlencode($this->enrollPin);
        }
        return $link;
    }

    /** Like enrollLink(), but null when no host is configured (rekey paths). */
    private function tryEnrollLink(string $token): ?string
    {
        return $this->enrollHost === null ? null : $this->enrollLink($token);
    }

    /**
     * Contract bodies are additionalProperties:false — enforce it, plus
     * required keys, before touching any service.
     *
     * @param array<string, mixed> $body
     * @param array<int, string> $allowed
     * @param array<int, string> $required
     * @throws DomainException VALIDATION_FAILED.
     */
    private static function allowKeys(array $body, array $allowed, array $required): void
    {
        foreach ($required as $key) {
            if (!isset($body[$key]) || $body[$key] === '') {
                throw new DomainException('VALIDATION_FAILED', "Missing required field '$key'.");
            }
        }
        $unknown = \array_diff(\array_keys($body), $allowed);
        if ($unknown !== []) {
            throw new DomainException(
                'VALIDATION_FAILED',
                'Unknown field(s): ' . \implode(', ', $unknown) . '.'
            );
        }
    }

    private static function blankToNull(?string $value): ?string
    {
        $value = $value !== null ? \trim($value) : null;
        return $value === '' ? null : $value;
    }
}
