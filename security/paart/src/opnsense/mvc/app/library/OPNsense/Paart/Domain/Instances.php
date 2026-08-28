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
 * Declared-instance registry (M03 validation over the M02 mirror table).
 *
 * The authoritative declaration lives in config.xml; the `instances` table
 * mirrors it under a stable ULID, synchronized at declaration time (Q13).
 * This service owns the declaration-time rules:
 *  - the managed range is contained in a single /24 (ADR 0005), refused
 *    otherwise with a message the UI reuses (M08);
 *  - the allocation pool must fit the range's usable host octets;
 *  - a new range must not overlap any already-declared range (RANGE_OVERLAP);
 *  - one mirror row per os-wireguard instance (wg_instance_ref unique).
 *
 * It also owns the withdrawal (undeclare): refused while non-revoked
 * devices remain UNLESS the caller states what becomes of their peers
 * (keep or delete — M08 makes the admin choose), after which a single
 * transaction purges the operational rows the RESTRICT foreign keys tie
 * to the instance — audit_log stays, as the durable history.
 *
 * It never touches WireGuard itself: declaring here only records what the
 * plugin is ALLOWED to manage (forbidden rule #3 works off this registry).
 */

namespace OPNsense\Paart\Domain;

use OPNsense\Paart\Store\Database;
use OPNsense\Paart\Support\Ulid;

final class Instances
{
    /**
     * What withdrawal does about the peers of the devices still in service
     * (M08 Networks: the admin chooses, explicitly, one or the other).
     * 'keep' leaves them running on an instance the plugin stops managing;
     * 'delete' says the caller already removed them. See undeclare().
     */
    public const PEER_DISPOSITIONS = ['keep', 'delete'];

    private Database $db;
    private AuditTrail $audit;

    /**
     * @param Database $db the plugin store (mirror rows, hosts, subnets).
     * @param AuditTrail $audit receives the instance.* entries; writes
     *        share the transaction of the mutation they describe.
     */
    public function __construct(Database $db, AuditTrail $audit)
    {
        $this->db = $db;
        $this->audit = $audit;
    }

    /**
     * Declare an instance: validate, insert the mirror row, audit.
     *
     * @param array{
     *   wg_instance_ref: string, label: string, endpoint: string,
     *   ip_range_cidr: string, pool_start_octet: int, pool_end_octet: int,
     *   dns_servers?: array<int, string>, match_domains?: array<int, string>,
     *   allow_full_tunnel?: bool, allow_subnet_toggle?: bool, enabled?: bool
     * } $decl
     * @param string $actorRef admin identity for the audit trail.
     * @return array<string, mixed> the stored row, id included.
     * @throws DomainException VALIDATION_FAILED | RANGE_OVERLAP.
     */
    public function declare(array $decl, string $actorRef): array
    {
        $range = self::parseCidr($decl['ip_range_cidr']);
        self::assertPoolFits($decl['pool_start_octet'], $decl['pool_end_octet'], $range);

        return $this->db->transaction(function (Database $db) use ($decl, $range, $actorRef): array {
            $this->assertNoOverlap($range, null);
            $this->assertRefFree($decl['wg_instance_ref'], null);

            $id = Ulid::generate();
            $now = Database::utcNow();
            $db->run(
                'INSERT INTO instances (id, wg_instance_ref, label, endpoint, ip_range_cidr,
                                        pool_start_octet, pool_end_octet, dns_servers_json,
                                        match_domains_json, allow_full_tunnel, allow_subnet_toggle,
                                        enabled, created_at, updated_at)
                 VALUES (:id, :ref, :label, :ep, :cidr, :ps, :pe, :dns, :domains, :full, :toggle,
                         :enabled, :now, :now)',
                [
                    ':id' => $id,
                    ':ref' => $decl['wg_instance_ref'],
                    ':label' => $decl['label'],
                    ':ep' => $decl['endpoint'],
                    ':cidr' => $decl['ip_range_cidr'],
                    ':ps' => $decl['pool_start_octet'],
                    ':pe' => $decl['pool_end_octet'],
                    ':dns' => \json_encode($decl['dns_servers'] ?? []),
                    ':domains' => \json_encode($decl['match_domains'] ?? []),
                    ':full' => (int)($decl['allow_full_tunnel'] ?? false),
                    ':toggle' => (int)($decl['allow_subnet_toggle'] ?? false),
                    ':enabled' => (int)($decl['enabled'] ?? true),
                    ':now' => $now,
                ]
            );
            $this->audit->record('admin', $actorRef, 'instance.declare', 'instance', $id, 'success', [
                'wg_instance_ref' => $decl['wg_instance_ref'],
                'ip_range_cidr' => $decl['ip_range_cidr'],
            ]);
            return $this->get($id);
        });
    }

    /**
     * Re-validate and update an existing declaration (mirror sync on change).
     *
     * Safety guards, both signalled rather than silently fixed:
     *  - the range cannot change while any octet is actively allocated;
     *  - the pool cannot shrink below an actively allocated octet.
     *
     * @param string $id declared instance ULID (mirror row).
     * @param array<string, mixed> $decl same shape as declare().
     * @param string $actorRef admin identity for the audit trail.
     * @return array<string, mixed> the updated row.
     * @throws DomainException NOT_FOUND | VALIDATION_FAILED | RANGE_OVERLAP.
     */
    public function updateDeclaration(string $id, array $decl, string $actorRef): array
    {
        $range = self::parseCidr($decl['ip_range_cidr']);
        self::assertPoolFits($decl['pool_start_octet'], $decl['pool_end_octet'], $range);

        return $this->db->transaction(function (Database $db) use ($id, $decl, $range, $actorRef): array {
            $current = $this->get($id);
            $this->assertNoOverlap($range, $id);
            $this->assertRefFree($decl['wg_instance_ref'], $id);

            $active = (int)$db->scalar(
                'SELECT COUNT(*) FROM ip_allocations
                 WHERE instance_id = :id AND released_at IS NULL',
                [':id' => $id]
            );
            if ($active > 0 && $decl['ip_range_cidr'] !== $current['ip_range_cidr']) {
                throw new DomainException(
                    'VALIDATION_FAILED',
                    "Cannot change the IP range of '{$current['label']}': $active address(es) are " .
                    'still allocated. Revoke the devices first, or declare a new instance. ' .
                    'Nothing was changed.'
                );
            }
            $outside = (int)$db->scalar(
                'SELECT COUNT(*) FROM ip_allocations
                 WHERE instance_id = :id AND released_at IS NULL
                   AND (host_octet < :ps OR host_octet > :pe)',
                [':id' => $id, ':ps' => $decl['pool_start_octet'], ':pe' => $decl['pool_end_octet']]
            );
            if ($outside > 0) {
                throw new DomainException(
                    'VALIDATION_FAILED',
                    "Cannot shrink the pool of '{$current['label']}': $outside allocated " .
                    'address(es) would fall outside the new bounds. Nothing was changed.'
                );
            }

            $db->run(
                'UPDATE instances SET wg_instance_ref = :ref, label = :label, endpoint = :ep,
                        ip_range_cidr = :cidr, pool_start_octet = :ps, pool_end_octet = :pe,
                        dns_servers_json = :dns, match_domains_json = :domains,
                        allow_full_tunnel = :full, allow_subnet_toggle = :toggle,
                        enabled = :enabled, updated_at = :now
                 WHERE id = :id',
                [
                    ':id' => $id,
                    ':ref' => $decl['wg_instance_ref'],
                    ':label' => $decl['label'],
                    ':ep' => $decl['endpoint'],
                    ':cidr' => $decl['ip_range_cidr'],
                    ':ps' => $decl['pool_start_octet'],
                    ':pe' => $decl['pool_end_octet'],
                    ':dns' => \json_encode($decl['dns_servers'] ?? []),
                    ':domains' => \json_encode($decl['match_domains'] ?? []),
                    ':full' => (int)($decl['allow_full_tunnel'] ?? false),
                    ':toggle' => (int)($decl['allow_subnet_toggle'] ?? false),
                    ':enabled' => (int)($decl['enabled'] ?? true),
                    ':now' => Database::utcNow(),
                ]
            );
            $this->audit->record('admin', $actorRef, 'instance.update', 'instance', $id, 'success', [
                'wg_instance_ref' => $decl['wg_instance_ref'],
                'ip_range_cidr' => $decl['ip_range_cidr'],
            ]);
            return $this->get($id);
        });
    }

    /**
     * Remove an instance from management (M08 Networks).
     *
     * Withdrawal never touches WireGuard from here — this service holds no
     * provisioner and the instance keeps existing on the firewall either
     * way. What it does own is the decision to proceed, and the record of
     * what the admin chose:
     *
     *  - **$peerDisposition null (the default)** — refused while any
     *    non-revoked device remains, with the count, so no caller can drop
     *    live accesses by forgetting a parameter. Every compensation that
     *    reverses a fresh declare in the Networks controller uses this
     *    form (delNetwork's own compensation runs the other way — a
     *    re-declare).
     *  - **'keep'** — the peers stay on the instance and keep working; the
     *    plugin simply stops knowing about them. They become peers it did
     *    not create and will never touch again.
     *  - **'delete'** — states that the caller has ALREADY removed those
     *    peers from the firewall, before this call, while the instance was
     *    still declared (deletePeer refuses an undeclared one, M06, and
     *    forbidden rule #3 forbids the reverse order). This service takes
     *    that statement at its word and only records it.
     *
     * Either explicit disposition is an intent, so forbidden rule #4 is
     * satisfied by the choice itself; what is never allowed is guessing one.
     *
     * The schema's foreign keys (RESTRICT, M02) make the removal explicit
     * about its cost: every operational row of the instance falls with it,
     * in one transaction and in dependency order — the rotations of its
     * devices, its enroll tokens, its IP allocations, its hosts and
     * subnets, then its devices — the revoked ones and, under an explicit
     * disposition, those that were still in service. The audit log has no such
     * reference by design and remains the durable history (M07).
     *
     * The 'removed' counts in that audit entry cover only devices and
     * enroll tokens, and they are taken BEFORE the deletes: they answer
     * "how much history did this remove", not "how many rows were
     * touched" — rotations, allocations, hosts and subnets are the
     * dependent detail of those two.
     *
     * The audit entry names the devices that were still in service, with
     * their key fingerprints (never a full key — M07): once the rows are
     * gone that entry is the only trace of which peers were left behind on
     * the instance ('keep') or cut off ('delete').
     *
     * @param string $id declared instance ULID (mirror row).
     * @param string $actorRef admin identity for the audit trail.
     * @param ?string $peerDisposition null, 'keep' or 'delete' — see above.
     * @throws DomainException NOT_FOUND | VALIDATION_FAILED (live devices
     *         with no disposition, or an unknown disposition).
     */
    public function undeclare(string $id, string $actorRef, ?string $peerDisposition = null): void
    {
        if ($peerDisposition !== null && !\in_array($peerDisposition, self::PEER_DISPOSITIONS, true)) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Unknown peer disposition '$peerDisposition': expected 'keep' or 'delete'. " .
                'Nothing was changed.'
            );
        }
        $this->db->transaction(function (Database $db) use ($id, $actorRef, $peerDisposition): void {
            $instance = $this->get($id);
            $liveDevices = $db->query(
                "SELECT id, label, public_key FROM devices
                 WHERE instance_id = :id AND status != 'revoked' ORDER BY id",
                [':id' => $id]
            );
            if ($liveDevices !== [] && $peerDisposition === null) {
                $live = \count($liveDevices);
                throw new DomainException(
                    'VALIDATION_FAILED',
                    "Cannot remove '{$instance['label']}' from management: $live device(s) still " .
                    'use it. Revoke them first, or keep the instance declared. Nothing was changed.'
                );
            }
            $counts = [
                'devices' => (int)$db->scalar(
                    'SELECT COUNT(*) FROM devices WHERE instance_id = :id',
                    [':id' => $id]
                ),
                'enroll_tokens' => (int)$db->scalar(
                    'SELECT COUNT(*) FROM enroll_tokens WHERE instance_id = :id',
                    [':id' => $id]
                ),
            ];
            $db->run(
                'DELETE FROM rotations WHERE device_id IN
                     (SELECT id FROM devices WHERE instance_id = :id)',
                [':id' => $id]
            );
            $db->run('DELETE FROM enroll_tokens WHERE instance_id = :id', [':id' => $id]);
            $db->run('DELETE FROM ip_allocations WHERE instance_id = :id', [':id' => $id]);
            $db->run('DELETE FROM hosts WHERE instance_id = :id', [':id' => $id]);
            $db->run('DELETE FROM subnets WHERE instance_id = :id', [':id' => $id]);
            $db->run('DELETE FROM devices WHERE instance_id = :id', [':id' => $id]);
            $db->run('DELETE FROM instances WHERE id = :id', [':id' => $id]);
            $this->audit->record('admin', $actorRef, 'instance.undeclare', 'instance', $id, 'success', [
                'wg_instance_ref' => $instance['wg_instance_ref'],
                'label' => $instance['label'],
                'removed' => $counts,
                // 'none' when nothing was in service: there was no choice
                // to make, and recording one would invent an intent.
                'peer_disposition' => $liveDevices === [] ? 'none' : $peerDisposition,
                'live_devices' => \array_map(
                    static fn(array $d): array => [
                        'device_id' => (string)$d['id'],
                        'label' => (string)$d['label'],
                        'public_key' => PublicKey::fingerprint((string)$d['public_key']),
                    ],
                    $liveDevices
                ),
            ]);
        });
    }

    /**
     * One declared instance's mirror row, as stored.
     *
     * @param string $id instance ULID.
     * @return array<string, mixed> the raw `instances` row.
     * @throws DomainException NOT_FOUND.
     */
    public function get(string $id): array
    {
        $rows = $this->db->query('SELECT * FROM instances WHERE id = :id', [':id' => $id]);
        if ($rows === []) {
            throw new DomainException('NOT_FOUND', "Declared instance '$id' does not exist.");
        }
        return $rows[0];
    }

    /**
     * Parse and validate a managed range against the v1 constraint.
     *
     * @return array{network: int, broadcast: int, first_octet: int, last_octet: int}
     *         first/last_octet: usable host octets (network and broadcast excluded).
     * @throws DomainException VALIDATION_FAILED.
     */
    public static function parseCidr(string $cidr): array
    {
        if (
            \preg_match('#^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$#', $cidr, $m) !== 1
            || ($ip = \ip2long($m[1])) === false
        ) {
            throw new DomainException('VALIDATION_FAILED', "Invalid IPv4 CIDR '$cidr'.");
        }
        $prefix = (int)$m[2];
        if ($prefix < 24) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Range '$cidr' is wider than a /24. In v1 the managed range must be contained " .
                'in a single /24 (ADR 0005); allocation reasons in host octets.'
            );
        }
        if ($prefix > 30) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Range '$cidr' has no usable host addresses."
            );
        }
        $mask = (~0 << (32 - $prefix)) & 0xFFFFFFFF;
        $ip &= 0xFFFFFFFF;
        if (($ip & $mask) !== $ip) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "'$cidr' is not a network address (host bits set)."
            );
        }
        $broadcast = $ip | (~$mask & 0xFFFFFFFF);
        return [
            'network' => $ip,
            'broadcast' => $broadcast,
            'first_octet' => ($ip & 0xFF) + 1,
            'last_octet' => ($broadcast & 0xFF) - 1,
        ];
    }

    /**
     * @param array{first_octet: int, last_octet: int} $range
     * @throws DomainException VALIDATION_FAILED when the pool leaves the range.
     */
    private static function assertPoolFits(int $start, int $end, array $range): void
    {
        if ($start > $end || $start < $range['first_octet'] || $end > $range['last_octet']) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Allocation pool .$start–.$end must lie within the usable host octets " .
                ".{$range['first_octet']}–.{$range['last_octet']} of the declared range."
            );
        }
    }

    /**
     * @param array{network: int, broadcast: int} $range
     * @throws DomainException RANGE_OVERLAP against any other declared instance.
     */
    private function assertNoOverlap(array $range, ?string $excludeId): void
    {
        $rows = $this->db->query(
            'SELECT id, label, ip_range_cidr FROM instances' .
            ($excludeId === null ? '' : ' WHERE id != :id'),
            $excludeId === null ? [] : [':id' => $excludeId]
        );
        foreach ($rows as $row) {
            $other = self::parseCidr($row['ip_range_cidr']);
            if ($range['network'] <= $other['broadcast'] && $other['network'] <= $range['broadcast']) {
                throw new DomainException(
                    'RANGE_OVERLAP',
                    "Declared range overlaps '{$row['ip_range_cidr']}' of instance " .
                    "'{$row['label']}'. Ranges of declared instances must be disjoint."
                );
            }
        }
    }

    /** @throws DomainException VALIDATION_FAILED when the ref is already declared. */
    private function assertRefFree(string $wgInstanceRef, ?string $excludeId): void
    {
        $existing = $this->db->scalar(
            'SELECT label FROM instances WHERE wg_instance_ref = :ref' .
            ($excludeId === null ? '' : ' AND id != :id'),
            $excludeId === null
                ? [':ref' => $wgInstanceRef]
                : [':ref' => $wgInstanceRef, ':id' => $excludeId]
        );
        if ($existing !== null) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "WireGuard instance '$wgInstanceRef' is already declared as '$existing'."
            );
        }
    }
}
