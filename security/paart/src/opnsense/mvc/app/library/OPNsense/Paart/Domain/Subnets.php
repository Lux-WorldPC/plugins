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
 * Labeled subnets of a declared instance (M08 Networks, spec 01 bundle
 * `subnets[]`): the networks a managed device can route through the
 * tunnel, each with the label the admin chose and whether it is switched
 * on by default. They live in the store's `subnets` table — the
 * "dependent detail" of a declaration (like hosts): keyed by the mirror
 * ULID, purged with it by Instances::undeclare, never in config.xml.
 *
 * The admin edits the list as a whole and saves it as a whole; replace()
 * keeps the ULID of every row it recognises, because a device stores its
 * per-subnet switch state under that id (M11): a relabelled subnet keeps
 * its switch, a deleted-and-retyped one does not. One save = one audit
 * entry (`instance.subnets`, spec 07), whatever it changed.
 *
 * What a subnet means to a device is defined on the client side (M11,
 * M15's classic .conf derivation): the subnets switched on by default are
 * its routes; with none switched on, every declared subnet is; with none
 * declared, everything goes through the tunnel. Declaring the first
 * subnet therefore narrows what new enrollments route — the screen says
 * so, this class only stores.
 *
 * Nothing here touches WireGuard: subnets are routing hints for the
 * device's own AllowedIPs, the server's cryptokey routing is unchanged.
 */

namespace OPNsense\Paart\Domain;

use OPNsense\Paart\Store\Database;
use OPNsense\Paart\Support\Ulid;

final class Subnets
{
    /**
     * Upper bound per instance — a routing table an admin can still read
     * on the screen and a device can still show as switches (spec sets
     * none; this one is a sanity cap, not a product limit).
     */
    public const MAX_PER_INSTANCE = 32;

    /** Label length cap, the same as device labels (spec 01 device_name). */
    public const MAX_LABEL_LENGTH = 64;

    private Database $db;
    private AuditTrail $audit;

    /**
     * @param Database $db the plugin store (`subnets`, `instances`).
     * @param AuditTrail $audit receives the instance.subnets entry; the
     *        write shares the transaction of the replace it describes.
     */
    public function __construct(Database $db, AuditTrail $audit)
    {
        $this->db = $db;
        $this->audit = $audit;
    }

    /**
     * The declared list, in the admin's order — the same rows, in the
     * same order, that Enroll\Bundles serves.
     *
     * @param string $instanceId mirror ULID of the declared instance.
     * @return array<int, array{id: string, label: string, cidr: string, default_on: bool}>
     */
    public function list(string $instanceId): array
    {
        $rows = $this->db->query(
            'SELECT id, label, cidr, default_on FROM subnets
              WHERE instance_id = :i ORDER BY sort_order, id',
            [':i' => $instanceId]
        );
        return \array_map(static fn(array $r): array => [
            'id' => (string)$r['id'],
            'label' => (string)$r['label'],
            'cidr' => (string)$r['cidr'],
            'default_on' => (int)$r['default_on'] === 1,
        ], $rows);
    }

    /**
     * Replace the declared list with $rows, in that order.
     *
     * A row carrying the `id` of a subnet already declared on this
     * instance updates it in place (its ULID survives — device switch
     * states are keyed by it); a row without one is created; a declared
     * subnet absent from $rows is deleted. The whole list is validated
     * before anything is written, so a refused save changes nothing.
     *
     * @param string $instanceId mirror ULID of the declared instance.
     * @param array<int, array{id?: string, label: string, cidr: string, default_on?: mixed}> $rows
     *        the list as the admin left it; `default_on` accepts bools,
     *        ints and the '0'/'1' strings a form posts.
     * @param string $actorRef admin identity for the audit trail.
     * @return array{subnets: array<int, array<string, mixed>>, added: int, updated: int, removed: int}
     *         the list as stored (list() shape) and what the save did.
     * @throws DomainException NOT_FOUND (no such instance) |
     *         VALIDATION_FAILED (a row refused — the message names the row,
     *         1-based, and what to fix; nothing was changed).
     */
    public function replace(string $instanceId, array $rows, string $actorRef): array
    {
        $exists = $this->db->scalar('SELECT 1 FROM instances WHERE id = :i', [':i' => $instanceId]);
        if ($exists === null) {
            throw new DomainException('NOT_FOUND', "Declared instance '$instanceId' does not exist.");
        }
        $known = [];
        foreach ($this->db->query('SELECT id FROM subnets WHERE instance_id = :i', [':i' => $instanceId]) as $r) {
            $known[(string)$r['id']] = true;
        }
        $clean = self::validate($rows, $known);

        return $this->db->transaction(function (Database $db) use ($instanceId, $clean, $known, $actorRef): array {
            $keptIds = [];
            $added = 0;
            $updated = 0;
            foreach ($clean as $position => $row) {
                if ($row['id'] !== null) {
                    $db->run(
                        'UPDATE subnets SET label = :l, cidr = :c, default_on = :d, sort_order = :s
                          WHERE id = :id AND instance_id = :i',
                        [
                            ':l' => $row['label'], ':c' => $row['cidr'], ':d' => (int)$row['default_on'],
                            ':s' => $position, ':id' => $row['id'], ':i' => $instanceId,
                        ]
                    );
                    $keptIds[$row['id']] = true;
                    $updated++;
                    continue;
                }
                $db->run(
                    'INSERT INTO subnets (id, instance_id, label, cidr, default_on, sort_order)
                     VALUES (:id, :i, :l, :c, :d, :s)',
                    [
                        ':id' => Ulid::generate(), ':i' => $instanceId, ':l' => $row['label'],
                        ':c' => $row['cidr'], ':d' => (int)$row['default_on'], ':s' => $position,
                    ]
                );
                $added++;
            }
            $removed = 0;
            foreach (\array_keys($known) as $id) {
                if (!isset($keptIds[$id])) {
                    $db->run('DELETE FROM subnets WHERE id = :id', [':id' => $id]);
                    $removed++;
                }
            }
            $this->audit->record('admin', $actorRef, 'instance.subnets', 'instance', $instanceId, 'success', [
                'count' => \count($clean),
                'added' => $added,
                'updated' => $updated,
                'removed' => $removed,
            ]);
            return [
                'subnets' => $this->list($instanceId),
                'added' => $added,
                'updated' => $updated,
                'removed' => $removed,
            ];
        });
    }

    /**
     * Normalise an IPv4 subnet in CIDR notation.
     *
     * Refuses host bits set (10.7.1.5/24) rather than silently masking
     * them: an admin who typed a host address may have meant a /32, and
     * a routing entry should read exactly as it will be pushed. /0 is
     * refused too — "everything" is the full-tunnel policy, not a subnet.
     *
     * @param string $cidr IPv4 network in CIDR notation, `a.b.c.d/n`, as typed.
     * @return string the CIDR as typed, once accepted.
     * @throws DomainException VALIDATION_FAILED.
     */
    public static function normalizeCidr(string $cidr): string
    {
        if (
            \preg_match('#^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$#', $cidr, $m) !== 1
            || ($ip = \ip2long($m[1])) === false
        ) {
            throw new DomainException('VALIDATION_FAILED', "Invalid IPv4 CIDR '$cidr' (expected a.b.c.d/n).");
        }
        $prefix = (int)$m[2];
        if ($prefix < 1 || $prefix > 32) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Invalid prefix in '$cidr': /1 to /32 (everything through the tunnel is the " .
                'full-tunnel policy, not a subnet).'
            );
        }
        $mask = $prefix === 32 ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF;
        $network = $ip & $mask;
        if ($network !== $ip) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "'$cidr' has host bits set: did you mean " . \long2ip($network) . "/$prefix" .
                " (the network) or " . $m[1] . '/32 (this host)?'
            );
        }
        return $cidr;
    }

    /**
     * Check the whole list; return it cleaned (trimmed labels, bool
     * default_on, id or null).
     *
     * @param array<int, mixed> $rows as posted.
     * @param array<string, true> $known ids already declared on the instance.
     * @return array<int, array{id: ?string, label: string, cidr: string, default_on: bool}>
     * @throws DomainException VALIDATION_FAILED.
     */
    private static function validate(array $rows, array $known): array
    {
        if (\count($rows) > self::MAX_PER_INSTANCE) {
            throw new DomainException(
                'VALIDATION_FAILED',
                'At most ' . self::MAX_PER_INSTANCE . ' subnets per network. Nothing was changed.'
            );
        }
        $clean = [];
        $labels = [];
        $cidrs = [];
        $ids = [];
        $n = 0;
        foreach (\array_values($rows) as $row) {
            $n++;
            if (!\is_array($row)) {
                throw new DomainException('VALIDATION_FAILED', "Subnet $n: malformed entry. Nothing was changed.");
            }
            $label = \trim((string)($row['label'] ?? ''));
            if ($label === '' || \mb_strlen($label) > self::MAX_LABEL_LENGTH) {
                throw new DomainException(
                    'VALIDATION_FAILED',
                    "Subnet $n: the label is required (1 to " . self::MAX_LABEL_LENGTH .
                    ' characters). Nothing was changed.'
                );
            }
            $key = \mb_strtolower($label);
            if (isset($labels[$key])) {
                throw new DomainException(
                    'VALIDATION_FAILED',
                    "Subnet $n: label '$label' is used twice — a device shows one switch per label. " .
                    'Nothing was changed.'
                );
            }
            $labels[$key] = true;

            try {
                $cidr = self::normalizeCidr(\trim((string)($row['cidr'] ?? '')));
            } catch (DomainException $e) {
                throw new DomainException('VALIDATION_FAILED', "Subnet $n: " . $e->getMessage() . ' Nothing was changed.');
            }
            if (isset($cidrs[$cidr])) {
                throw new DomainException(
                    'VALIDATION_FAILED',
                    "Subnet $n: '$cidr' is declared twice. Nothing was changed."
                );
            }
            $cidrs[$cidr] = true;

            $id = isset($row['id']) && (string)$row['id'] !== '' ? (string)$row['id'] : null;
            if ($id !== null) {
                if (!isset($known[$id]) || isset($ids[$id])) {
                    throw new DomainException(
                        'VALIDATION_FAILED',
                        "Subnet $n: id '$id' is not a subnet of this network. Nothing was changed."
                    );
                }
                $ids[$id] = true;
            }
            $clean[] = [
                'id' => $id,
                'label' => $label,
                'cidr' => $cidr,
                'default_on' => self::truthy($row['default_on'] ?? false),
            ];
        }
        return $clean;
    }

    /** Form-tolerant boolean: true, 1, '1', 'true', 'on' are on; the rest off. */
    private static function truthy(mixed $value): bool
    {
        if (\is_bool($value)) {
            return $value;
        }
        return \in_array(\strtolower(\trim((string)$value)), ['1', 'true', 'on'], true);
    }
}
