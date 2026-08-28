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
 * Read-only projection for the Audit screen (M07 consultation, M08
 * screen conventions) — OFF-contract screen plumbing, like the Users,
 * Devices, Dashboard and Enrollment feeds. Two calls carry the screen:
 * overview() serves the filter pickers (every user and device, the
 * distinct actions the log actually holds, the retention setting with
 * its below-12-months warning flag) and search() serves one grid page.
 *
 * Filters are the spec's list: date range, user, device, action type,
 * outcome, plus the grid's text search. The user and device filters
 * match by relation, not by string: an audit entry belongs to a user
 * when its subject or actor is the user, one of their devices, or one
 * of their enrollment tokens — so a revocation is findable by user name
 * months later even though the entry only stores the device ULID
 * (M07 acceptance criterion).
 *
 * Entries are served newest first, always (spec: antichronological), and
 * paginated in SQL — 24 months of log must not transit whole per page.
 * ULID refs are enriched with the names behind them; detail_json is
 * decoded for the folded detail view and never truncated here.
 *
 * Never touches the firewall, and NEVER writes: there is no route that
 * modifies or deletes an entry (M07 integrity criterion) — the retention
 * purge lives in AuditTrail and is not reachable from this screen.
 */

namespace OPNsense\Paart\Admin;

use OPNsense\Paart\Store\Database;

final class AuditScreen
{
    /** Spec M07: warn in the UI below this many months of retention. */
    public const RETENTION_WARN_MONTHS = 12;

    private Database $db;
    private int $retentionMonths;

    /**
     * @param Database $db store handle (the log and the names behind refs).
     * @param int $retentionMonths configured horizon (Container resolves
     *        the default), surfaced with the warning flag.
     */
    public function __construct(Database $db, int $retentionMonths)
    {
        $this->db = $db;
        $this->retentionMonths = $retentionMonths;
    }

    /**
     * The filter pickers and the retention banner in one read.
     *
     * Users and devices are listed COMPLETE, disabled and revoked
     * included: the log is history, and "find the revocation six months
     * later" must keep working after the user is gone from every other
     * screen. Actions come from the log itself — the honest list of what
     * actually happened, not a catalog of what could.
     *
     * @return array{
     *   users: array<int, array{id: string, slug: string, display_name: string, status: string}>,
     *   devices: array<int, array{id: string, label: string, user_display_name: string, status: string}>,
     *   actions: array<int, string>,
     *   retention: array{months: int, warn: bool, warn_below_months: int},
     *   now: string
     * }
     */
    public function overview(): array
    {
        $users = [];
        foreach ($this->db->query('SELECT id, slug, display_name, status FROM users ORDER BY slug') as $row) {
            $users[] = [
                'id' => (string)$row['id'],
                'slug' => (string)$row['slug'],
                'display_name' => (string)$row['display_name'],
                'status' => (string)$row['status'],
            ];
        }
        $devices = [];
        $rows = $this->db->query(
            'SELECT d.id, d.label, d.status, u.display_name AS user_display_name
             FROM devices d JOIN users u ON u.id = d.user_id
             ORDER BY u.display_name, d.label'
        );
        foreach ($rows as $row) {
            $devices[] = [
                'id' => (string)$row['id'],
                'label' => (string)$row['label'],
                'user_display_name' => (string)$row['user_display_name'],
                'status' => (string)$row['status'],
            ];
        }
        $actions = \array_map(
            static fn(array $row): string => (string)$row['action'],
            $this->db->query('SELECT DISTINCT action FROM audit_log ORDER BY action')
        );
        return [
            'users' => $users,
            'devices' => $devices,
            'actions' => $actions,
            'retention' => [
                'months' => $this->retentionMonths,
                'warn' => $this->retentionMonths < self::RETENTION_WARN_MONTHS,
                'warn_below_months' => self::RETENTION_WARN_MONTHS,
            ],
            'now' => Database::utcNow(),
        ];
    }

    /**
     * One grid page, newest first.
     *
     * Filter keys (all optional, '' means absent): 'from' and 'to' are
     * dates or full timestamps — a bare date is widened to the whole day
     * it names, so from=to=today reads naturally; 'user_id' and
     * 'device_id' match by relation (see the header); 'action' and
     * 'outcome' are exact; 'q' searches action, refs and detail_json.
     *
     * @param array<string, string> $filters see above.
     * @param int $current 1-based page number.
     * @param int $rowCount page size; -1 serves everything (bootgrid
     *        convention), still capped at 1000 rows as a transit guard.
     * @return array{rows: array<int, array<string, mixed>>, rowCount: int,
     *               current: int, total: int}
     */
    public function search(array $filters, int $current = 1, int $rowCount = 25): array
    {
        [$clause, $params] = $this->whereClause($filters);
        $total = (int)$this->db->scalar("SELECT COUNT(*) FROM audit_log$clause", $params);

        $current = \max(1, $current);
        $size = $rowCount > 0 ? \min(1000, $rowCount) : 1000;
        $offset = $rowCount > 0 ? ($current - 1) * $size : 0;
        $rows = $this->db->query(
            // id is a ULID: ordering by it is ordering by time, with the
            // insert sequence breaking same-second ties (occurred_at alone
            // would leave those to chance).
            "SELECT * FROM audit_log$clause ORDER BY id DESC LIMIT :limit OFFSET :offset",
            $params + [':limit' => $size, ':offset' => $offset]
        );

        return [
            'rows' => $this->enrich($rows),
            'rowCount' => $rowCount,
            'current' => $current,
            'total' => $total,
        ];
    }

    // -------------------------------------------------------------- helpers

    /**
     * WHERE clause and bindings for the filter set.
     *
     * @param array<string, string> $filters
     * @return array{0: string, 1: array<string, string>}
     */
    private function whereClause(array $filters): array
    {
        $where = [];
        $params = [];

        $from = (string)($filters['from'] ?? '');
        if ($from !== '') {
            $where[] = 'occurred_at >= :from';
            $params[':from'] = self::dayStart($from);
        }
        $to = (string)($filters['to'] ?? '');
        if ($to !== '') {
            $where[] = 'occurred_at <= :to';
            $params[':to'] = self::dayEnd($to);
        }

        $refs = $this->relatedRefs(
            (string)($filters['user_id'] ?? ''),
            (string)($filters['device_id'] ?? '')
        );
        if ($refs === []) {
            $where[] = '0 = 1'; // disjoint user/device filters (see relatedRefs)
        } elseif ($refs !== null) {
            $names = [];
            foreach (\array_values($refs) as $i => $ref) {
                $names[] = ":ref$i";
                $params[":ref$i"] = $ref;
            }
            $in = \implode(', ', $names);
            $where[] = "(subject_ref IN ($in) OR actor_ref IN ($in))";
        }

        foreach (['action' => 'action', 'outcome' => 'outcome'] as $key => $column) {
            $value = (string)($filters[$key] ?? '');
            if ($value !== '') {
                $where[] = "$column = :$key";
                $params[":$key"] = $value;
            }
        }
        $q = (string)($filters['q'] ?? '');
        if ($q !== '') {
            $where[] = '(action LIKE :q OR actor_ref LIKE :q OR subject_ref LIKE :q OR detail_json LIKE :q)';
            $params[':q'] = '%' . $q . '%';
        }

        return [$where === [] ? '' : ' WHERE ' . \implode(' AND ', $where), $params];
    }

    /**
     * The refs an entry may carry when it is "about" the filtered user or
     * device: the user themselves, their devices, their enrollment tokens
     * (device actors use the device ULID as actor_ref, so the same list
     * serves both columns). A device filter on top of a user filter
     * narrows to that device — the intersection an admin would expect.
     *
     * @return ?array<int, string> null when neither filter is set.
     */
    private function relatedRefs(string $userId, string $deviceId): ?array
    {
        if ($deviceId !== '') {
            if ($userId === '') {
                return [$deviceId];
            }
            $owner = (string)$this->db->scalar(
                'SELECT user_id FROM devices WHERE id = :d',
                [':d' => $deviceId]
            );
            // Disjoint filters — a device that is not the user's — match
            // NOTHING: the empty list becomes a never-true clause, never
            // "no filter at all".
            return $owner === $userId ? [$deviceId] : [];
        }
        if ($userId === '') {
            return null;
        }
        $refs = [$userId];
        foreach ($this->db->query('SELECT id FROM devices WHERE user_id = :u', [':u' => $userId]) as $row) {
            $refs[] = (string)$row['id'];
        }
        foreach ($this->db->query('SELECT id FROM enroll_tokens WHERE user_id = :u', [':u' => $userId]) as $row) {
            $refs[] = (string)$row['id'];
        }
        return $refs;
    }

    /**
     * Grid rows with the names behind the ULIDs and the decoded detail.
     * Names are resolved per page in one query per referenced table —
     * never per row — and a ref the store cannot resolve yields a null
     * label, never a failure: the log outlives what it references (a
     * withdrawn instance's mirror row and its tokens are purged, the
     * entries about them stay).
     *
     * @param array<int, array<string, mixed>> $rows raw audit_log rows.
     * @return array<int, array<string, mixed>>
     */
    private function enrich(array $rows): array
    {
        $byTable = ['users' => [], 'devices' => [], 'enroll_tokens' => [], 'instances' => []];
        $tableFor = [
            'user' => 'users',
            'device' => 'devices',
            'enroll_token' => 'enroll_tokens',
            'instance' => 'instances',
        ];
        foreach ($rows as $row) {
            $table = $tableFor[(string)$row['subject_type']] ?? null;
            if ($table !== null) {
                $byTable[$table][(string)$row['subject_ref']] = true;
            }
            if ((string)$row['actor_type'] === 'device') {
                $byTable['devices'][(string)$row['actor_ref']] = true;
            }
        }
        $labels = [
            'users' => $this->labelMap('users', "display_name || ' (' || slug || ')'", $byTable['users']),
            'devices' => $this->deviceLabels($byTable['devices']),
            'enroll_tokens' => $this->labelMap('enroll_tokens', 'label', $byTable['enroll_tokens']),
            'instances' => $this->labelMap('instances', 'label', $byTable['instances']),
        ];

        $out = [];
        foreach ($rows as $row) {
            $subjectTable = $tableFor[(string)$row['subject_type']] ?? null;
            $detail = \json_decode((string)$row['detail_json'], true);
            $out[] = [
                'id' => (string)$row['id'],
                'occurred_at' => (string)$row['occurred_at'],
                'actor_type' => (string)$row['actor_type'],
                'actor_ref' => (string)$row['actor_ref'],
                'actor_label' => (string)$row['actor_type'] === 'device'
                    ? ($labels['devices'][(string)$row['actor_ref']] ?? null)
                    : null,
                'action' => (string)$row['action'],
                'subject_type' => (string)$row['subject_type'],
                'subject_ref' => (string)$row['subject_ref'],
                'subject_label' => $subjectTable !== null
                    ? ($labels[$subjectTable][(string)$row['subject_ref']] ?? null)
                    : null,
                'outcome' => (string)$row['outcome'],
                'source_ip' => $row['source_ip'] !== null ? (string)$row['source_ip'] : null,
                'detail' => \is_array($detail) ? $detail : [],
            ];
        }
        return $out;
    }

    /**
     * id => label for the given ids of one table; empty ids, empty map.
     *
     * @param string $labelSql SQL expression producing the label.
     * @param array<string, bool> $ids ids as keys.
     * @return array<string, string>
     */
    private function labelMap(string $table, string $labelSql, array $ids): array
    {
        if ($ids === []) {
            return [];
        }
        $params = [];
        foreach (\array_keys($ids) as $i => $id) {
            $params[":id$i"] = (string)$id;
        }
        $in = \implode(', ', \array_keys($params));
        $map = [];
        foreach ($this->db->query("SELECT id, $labelSql AS label FROM $table WHERE id IN ($in)", $params) as $row) {
            $map[(string)$row['id']] = (string)$row['label'];
        }
        return $map;
    }

    /**
     * Device labels carry their owner — "Laptop (Ada Lovelace)" — because
     * an audit line about "Laptop" alone names half the story.
     *
     * @param array<string, bool> $ids ids as keys.
     * @return array<string, string>
     */
    private function deviceLabels(array $ids): array
    {
        if ($ids === []) {
            return [];
        }
        $params = [];
        foreach (\array_keys($ids) as $i => $id) {
            $params[":id$i"] = (string)$id;
        }
        $in = \implode(', ', \array_keys($params));
        $map = [];
        $rows = $this->db->query(
            "SELECT d.id, d.label, u.display_name FROM devices d
             JOIN users u ON u.id = d.user_id WHERE d.id IN ($in)",
            $params
        );
        foreach ($rows as $row) {
            $map[(string)$row['id']] = (string)$row['label'] . ' (' . (string)$row['display_name'] . ')';
        }
        return $map;
    }

    /** A bare date opens at midnight UTC; timestamps pass through. */
    private static function dayStart(string $value): string
    {
        return \strlen($value) === 10 ? $value . 'T00:00:00Z' : $value;
    }

    /** A bare date closes at the end of its day; timestamps pass through. */
    private static function dayEnd(string $value): string
    {
        return \strlen($value) === 10 ? $value . 'T23:59:59Z' : $value;
    }
}
