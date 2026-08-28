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
 * User registry (M03): named identities the administrator reasons in.
 *
 * Disabling a user revokes ALL its devices in one atomic operation with a
 * SINGLE intent entry in the audit log (spec: never N orphan entries), and
 * returns the peer-removal intents for the provisioner (M06) — nothing is
 * deleted from WireGuard here (forbidden rule #4).
 *
 * The slug is the stable admin-facing handle ([a-z0-9-]{2,32}, unique) and
 * is immutable in v1 — renaming a person changes display_name only.
 * Re-enabling a disabled user is not a v1 operation (the spec only defines
 * disable); revoked devices are never resurrected either way.
 */

namespace OPNsense\Paart\Domain;

use OPNsense\Paart\Store\Database;
use OPNsense\Paart\Support\Ulid;

final class Users
{
    private const SLUG_PATTERN = '/^[a-z0-9-]{2,32}$/';

    private Database $db;
    private Devices $devices;
    private AuditTrail $audit;

    public function __construct(Database $db, Devices $devices, AuditTrail $audit)
    {
        $this->db = $db;
        $this->devices = $devices;
        $this->audit = $audit;
    }

    /**
     * Create an active user.
     *
     * @return array<string, mixed> the stored row.
     * @throws DomainException VALIDATION_FAILED on bad slug, empty display
     *         name, or slug already taken.
     */
    public function create(string $slug, string $displayName, ?string $email, string $actorRef): array
    {
        if (\preg_match(self::SLUG_PATTERN, $slug) !== 1) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Invalid slug '$slug': expected [a-z0-9-], 2 to 32 characters."
            );
        }
        $displayName = \trim($displayName);
        if ($displayName === '') {
            throw new DomainException('VALIDATION_FAILED', 'Display name must not be empty.');
        }

        return $this->db->transaction(function (Database $db) use ($slug, $displayName, $email, $actorRef): array {
            $taken = $db->scalar('SELECT COUNT(*) FROM users WHERE slug = :s', [':s' => $slug]);
            if ((int)$taken !== 0) {
                throw new DomainException('VALIDATION_FAILED', "Slug '$slug' is already taken.");
            }
            $id = Ulid::generate();
            $now = Database::utcNow();
            $db->run(
                "INSERT INTO users (id, slug, display_name, email, status, created_at, updated_at)
                 VALUES (:id, :slug, :name, :email, 'active', :now, :now)",
                [':id' => $id, ':slug' => $slug, ':name' => $displayName, ':email' => $email, ':now' => $now]
            );
            $this->audit->record('admin', $actorRef, 'user.create', 'user', $id, 'success', [
                'slug' => $slug,
            ]);
            return $this->get($id);
        });
    }

    /**
     * Update mutable profile fields (display name, email). The slug is
     * immutable in v1.
     *
     * @throws DomainException NOT_FOUND | VALIDATION_FAILED.
     */
    public function updateProfile(string $id, string $displayName, ?string $email, string $actorRef): void
    {
        $displayName = \trim($displayName);
        if ($displayName === '') {
            throw new DomainException('VALIDATION_FAILED', 'Display name must not be empty.');
        }
        $this->get($id);
        $this->db->run(
            'UPDATE users SET display_name = :name, email = :email, updated_at = :now WHERE id = :id',
            [':name' => $displayName, ':email' => $email, ':now' => Database::utcNow(), ':id' => $id]
        );
        $this->audit->record('admin', $actorRef, 'user.update', 'user', $id);
    }

    /**
     * Disable a user and revoke all its non-revoked devices atomically.
     * One audit entry records the whole intent, listing every device it
     * revoked. Idempotent: disabling a disabled user changes nothing and
     * returns no intents.
     *
     * @return array<int, array{device_id: string, wg_instance_ref: string, public_key: string}>
     *         peer-removal intents for the provisioner, one per device.
     * @throws DomainException NOT_FOUND.
     */
    public function disable(string $id, string $actorRef): array
    {
        return $this->db->transaction(function (Database $db) use ($id, $actorRef): array {
            $user = $this->get($id);
            if ($user['status'] === 'disabled') {
                return [];
            }
            $db->run(
                "UPDATE users SET status = 'disabled', updated_at = :now WHERE id = :id",
                [':now' => Database::utcNow(), ':id' => $id]
            );

            $deviceIds = $db->query(
                "SELECT id FROM devices WHERE user_id = :u AND status != 'revoked'",
                [':u' => $id]
            );
            $intents = [];
            foreach ($deviceIds as $row) {
                $intent = $this->devices->revokeQuietly($row['id']);
                if ($intent !== null) {
                    $intents[] = $intent;
                }
            }

            $this->audit->record('admin', $actorRef, 'user.disable', 'user', $id, 'success', [
                'slug' => $user['slug'],
                'revoked_devices' => \array_map(
                    static fn(array $i): array => [
                        'device_id' => $i['device_id'],
                        'public_key' => PublicKey::fingerprint((string)$i['public_key']),
                    ],
                    $intents
                ),
            ]);
            return $intents;
        });
    }

    /**
     * @return array<string, mixed>
     * @throws DomainException NOT_FOUND.
     */
    public function get(string $id): array
    {
        $rows = $this->db->query('SELECT * FROM users WHERE id = :id', [':id' => $id]);
        if ($rows === []) {
            throw new DomainException('NOT_FOUND', "User '$id' does not exist.");
        }
        return $rows[0];
    }
}
