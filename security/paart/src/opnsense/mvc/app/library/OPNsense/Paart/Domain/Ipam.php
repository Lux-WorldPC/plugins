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
 * Per-instance IP allocation (M03). Pools are independent: every operation
 * is qualified by the instance; nothing here may assume a single pool.
 *
 * Rules implemented, from the spec:
 *  - sequential allocation on the first free octet of the instance pool;
 *  - an octet released by revocation stays quarantined for a configurable
 *    delay (default 90 days) before it can be reallocated;
 *  - before EVERY allocation the real peers of the instance are read
 *    (PeerSource) and their octets excluded — a pre-existing peer is never
 *    overwritten nor its address reallocated;
 *  - pool exhaustion is an explicit, actionable refusal (POOL_EXHAUSTED).
 *
 * Early release of quarantined octets on exhaustion is an open question
 * (Q11) — not implemented until decided.
 */

namespace OPNsense\Paart\Domain;

use OPNsense\Paart\Store\Database;

final class Ipam
{
    /** Days a released octet stays non-reallocatable (spec default). */
    public const DEFAULT_QUARANTINE_DAYS = 90;

    private Database $db;
    private PeerSource $peers;
    private int $quarantineDays;

    public function __construct(
        Database $db,
        PeerSource $peers,
        int $quarantineDays = self::DEFAULT_QUARANTINE_DAYS
    ) {
        $this->db = $db;
        $this->peers = $peers;
        $this->quarantineDays = $quarantineDays;
    }

    /**
     * Allocate the first free octet of the instance pool. The row starts
     * unbound (device_id NULL): the device row does not exist yet at this
     * point of the enrollment flow — call bindDevice() right after inserting
     * it. Run both inside one transaction so a failed enrollment never
     * leaks an allocation.
     *
     * @param string $instanceId declared instance ULID.
     * @return array{host_octet: int, ip_address: string}
     * @throws DomainException NOT_FOUND | POOL_EXHAUSTED.
     */
    public function allocate(string $instanceId): array
    {
        $instance = $this->instanceRow($instanceId);
        $now = Database::utcNow();
        $cutoff = self::cutoff($now, $this->quarantineDays);

        $taken = [];
        $quarantined = 0;
        $rows = $this->db->query(
            'SELECT host_octet, released_at FROM ip_allocations WHERE instance_id = :id',
            [':id' => $instanceId]
        );
        foreach ($rows as $row) {
            if ($row['released_at'] === null) {
                $taken[(int)$row['host_octet']] = true;
            } elseif ($row['released_at'] > $cutoff) {
                $taken[(int)$row['host_octet']] = true;
                $quarantined++;
            }
        }
        foreach ($this->peers->livePeers($instance['wg_instance_ref']) as $peer) {
            foreach ($peer['host_octets'] as $octet) {
                $taken[(int)$octet] = true;
            }
        }

        $start = (int)$instance['pool_start_octet'];
        $end = (int)$instance['pool_end_octet'];
        for ($octet = $start; $octet <= $end; $octet++) {
            if (!isset($taken[$octet])) {
                $this->db->run(
                    'INSERT INTO ip_allocations (instance_id, host_octet, device_id, allocated_at)
                     VALUES (:i, :o, NULL, :now)
                     ON CONFLICT (instance_id, host_octet) DO UPDATE
                     SET device_id = NULL, reserved_reason = NULL,
                         allocated_at = :now, released_at = NULL',
                    [':i' => $instanceId, ':o' => $octet, ':now' => $now]
                );
                return [
                    'host_octet' => $octet,
                    'ip_address' => self::address($instance['ip_range_cidr'], $octet),
                ];
            }
        }

        $hint = $quarantined > 0
            ? " $quarantined address(es) are in quarantine ({$this->quarantineDays} days after release)."
            : '';
        throw new DomainException(
            'POOL_EXHAUSTED',
            "No free address in pool .$start–.$end of instance '{$instance['label']}'.$hint " .
            'Revoke unused devices or widen the pool.'
        );
    }

    /**
     * Attach a freshly created device to its allocation (enrollment flow,
     * same transaction as allocate()).
     *
     * @param string $instanceId declared instance ULID.
     * @param int $hostOctet the octet allocate() just returned.
     * @param string $deviceId ULID of the device row inserted since.
     * @throws DomainException INTERNAL when no active unbound allocation
     *         matches — the enrollment flow was not followed.
     */
    public function bindDevice(string $instanceId, int $hostOctet, string $deviceId): void
    {
        $this->db->run(
            'UPDATE ip_allocations SET device_id = :d
             WHERE instance_id = :i AND host_octet = :o
               AND released_at IS NULL AND device_id IS NULL',
            [':d' => $deviceId, ':i' => $instanceId, ':o' => $hostOctet]
        );
        if ((int)$this->db->scalar('SELECT changes()') !== 1) {
            throw new DomainException(
                'INTERNAL',
                "No unbound allocation for octet .$hostOctet on instance '$instanceId'; " .
                'bindDevice() must follow allocate() in the same transaction. ' .
                'Store inconsistency, nothing was changed.'
            );
        }
    }

    /**
     * Release an allocated octet into quarantine (revocation path). The
     * device reference is kept on the row for traceability.
     *
     * @param string $instanceId declared instance ULID.
     * @param int $hostOctet allocated octet to quarantine.
     * @throws DomainException INTERNAL when no active allocation matches —
     *         an inconsistency to signal, never to paper over.
     */
    public function release(string $instanceId, int $hostOctet): void
    {
        $this->db->run(
            "UPDATE ip_allocations SET released_at = :now, reserved_reason = 'quarantine'
             WHERE instance_id = :i AND host_octet = :o AND released_at IS NULL",
            [':now' => Database::utcNow(), ':i' => $instanceId, ':o' => $hostOctet]
        );
        $changed = $this->db->scalar('SELECT changes()');
        if ((int)$changed !== 1) {
            throw new DomainException(
                'INTERNAL',
                "No active allocation for octet .$hostOctet on instance '$instanceId'; " .
                'store inconsistency, nothing was changed.'
            );
        }
    }

    /** Tunnel address for a host octet inside the instance's managed /24. */
    public static function address(string $cidr, int $hostOctet): string
    {
        $range = Instances::parseCidr($cidr);
        return \long2ip(($range['network'] & 0xFFFFFF00) | $hostOctet);
    }

    /** Oldest release timestamp still inside the quarantine window. */
    private static function cutoff(string $nowUtc, int $days): string
    {
        $ts = \strtotime($nowUtc);
        return \gmdate('Y-m-d\TH:i:s\Z', $ts - $days * 86400);
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
}
