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
 * Read-only projection for the M08 Dashboard — OFF-contract screen
 * plumbing, like the Users and Devices feeds. One call assembles the whole
 * screen: the five counters, the health block (AdminService::health(), so
 * the recetted contract shape stays the single source), the alert
 * conditions the spec lists, and the last audit entries.
 *
 * Degrades instead of failing. health() needs the firewall — a
 * reachability probe plus one reconciliation pass — and refuses
 * PROVISIONING_UNAVAILABLE when it is down; the dashboard then serves its
 * store-only half (counters, journal) with live=false, because the screen
 * an admin opens to diagnose an unreachable firewall must not be the one
 * that goes blank when the firewall is unreachable.
 *
 * Alerts carry codes and numbers, never sentences: M08 keeps every UI
 * string in the view, externalized for later translation.
 *
 * This class NEVER writes.
 */

namespace OPNsense\Paart\Admin;

use OPNsense\Paart\Provision\ProvisionException;
use OPNsense\Paart\Store\Database;

final class DashboardScreen
{
    /** Spec threshold: a pool above this percentage raises a banner. */
    public const POOL_ALERT_PCT = 80;
    /** Spec: the dashboard shows the last 20 journal entries. */
    public const AUDIT_ENTRIES = 20;

    private AdminService $admin;
    private Database $db;

    public function __construct(AdminService $admin, Database $db)
    {
        $this->admin = $admin;
        $this->db = $db;
    }

    /**
     * The whole screen in one read.
     *
     * counters.drift_findings is null — not zero — when the firewall is
     * unreachable: no reconciliation ran, and "no drift found" would be a
     * claim nobody verified.
     *
     * @return array{
     *   counters: array{active_users: int, active_devices: int,
     *                   rotating_devices: int, drift_findings: ?int},
     *   health: ?array<string, mixed>,
     *   alerts: array<int, array<string, mixed>>,
     *   audit: array<int, array<string, mixed>>,
     *   pool_alert_pct: int,
     *   live: bool
     * }
     */
    public function overview(): array
    {
        $health = null;
        try {
            $health = $this->admin->health();
        } catch (ProvisionException) {
            // Unreachable firewall: keep the store-only half (see header).
            $health = null;
        }

        return [
            'counters' => [
                'active_users' => $this->count("SELECT COUNT(*) FROM users WHERE status = 'active'"),
                'active_devices' => $this->count("SELECT COUNT(*) FROM devices WHERE status = 'active'"),
                // The managed half of the fleet — `full` devices, active or
                // rotating, the same number the bundle carries. Shown so an
                // administrator can see his fleet against the tier he bought:
                // a NUMBER, never a verdict (ADR 0018, D16).
                'managed_devices' => $this->count(
                    "SELECT COUNT(*) FROM devices
                      WHERE management_level = 'full' AND status IN ('active', 'rotating')"
                ),
                'rotating_devices' => $this->count("SELECT COUNT(*) FROM devices WHERE status = 'rotating'"),
                'drift_findings' => $health !== null ? self::driftTotal($health) : null,
            ],
            'health' => $health,
            'alerts' => $health !== null ? self::alerts($health) : [],
            'audit' => $this->recentAudit(),
            // Published so the view marks a filling pool on the same
            // threshold that raised the banner, instead of repeating it.
            'pool_alert_pct' => self::POOL_ALERT_PCT,
            'live' => $health !== null,
        ];
    }

    // -------------------------------------------------------------- helpers

    /**
     * Findings that mean something is wrong, summed over every instance:
     * expected peers missing, address conflicts, and revoked devices whose
     * peer is still live. Plain unmanaged peers are excluded — the plugin
     * is attached to instances it does not own (D8), and counting
     * hand-managed peers as drift would leave the dashboard permanently
     * alarmed about a normal situation.
     *
     * @param array<string, mixed> $health AdminService::health() payload.
     */
    private static function driftTotal(array $health): int
    {
        $total = 0;
        foreach ((array)($health['instances'] ?? []) as $instance) {
            $drift = $instance['drift'] ?? null;
            if (\is_array($drift)) {
                $total += (int)($drift['missing'] ?? 0)
                    + (int)($drift['conflict'] ?? 0)
                    + (int)($drift['stale_revoked'] ?? 0);
            }
        }
        return $total;
    }

    /**
     * The banner conditions of the spec, as codes the view renders:
     * unreachable instance, pool above POOL_ALERT_PCT, unhandled drift,
     * and rotations past their grace TTL. Order is severity-first so the
     * view can print them as they come.
     *
     * @param array<string, mixed> $health AdminService::health() payload.
     * @return array<int, array<string, mixed>> each with a level
     *         ('danger'|'warning') and a code, plus that code's numbers.
     */
    private static function alerts(array $health): array
    {
        $danger = [];
        $warning = [];

        foreach ((array)($health['instances'] ?? []) as $instance) {
            $label = (string)($instance['label'] ?? '');
            if (($instance['reachable'] ?? false) !== true) {
                $danger[] = ['level' => 'danger', 'code' => 'instance_unreachable', 'instance' => $label];
                // No drift or pool claim about an instance we could not read.
                continue;
            }

            $drift = \is_array($instance['drift'] ?? null) ? $instance['drift'] : [];
            $missing = (int)($drift['missing'] ?? 0);
            $conflict = (int)($drift['conflict'] ?? 0);
            $staleRevoked = (int)($drift['stale_revoked'] ?? 0);
            if ($missing + $conflict + $staleRevoked > 0) {
                $entry = [
                    // A revoked device still holding a live peer is access
                    // that was never actually cut: never merely a warning.
                    'level' => $staleRevoked > 0 ? 'danger' : 'warning',
                    'code' => 'drift',
                    'instance' => $label,
                    'missing' => $missing,
                    'conflict' => $conflict,
                    'stale_revoked' => $staleRevoked,
                ];
                if ($entry['level'] === 'danger') {
                    $danger[] = $entry;
                } else {
                    $warning[] = $entry;
                }
            }

            $pct = (int)($instance['pool']['occupancy_pct'] ?? 0);
            if ($pct > self::POOL_ALERT_PCT) {
                $warning[] = [
                    'level' => 'warning',
                    'code' => 'pool_high',
                    'instance' => $label,
                    'occupancy_pct' => $pct,
                ];
            }
        }

        $overdue = (int)($health['overdue_rotations'] ?? 0);
        if ($overdue > 0) {
            // M05: an expired grace never cuts access — it only asks the
            // admin to look. A warning, never a danger.
            $warning[] = ['level' => 'warning', 'code' => 'overdue_rotations', 'count' => $overdue];
        }

        return \array_merge($danger, $warning);
    }

    /**
     * The last AUDIT_ENTRIES journal entries, newest first, without their
     * 'detail' payload: a reconciliation report embeds a whole findings
     * dump, and the dashboard shows one line per entry. The Audit screen
     * (M07) is where details belong.
     *
     * @return array<int, array<string, mixed>>
     */
    private function recentAudit(): array
    {
        $out = [];
        foreach ($this->admin->queryAudit(['page_size' => self::AUDIT_ENTRIES])['entries'] as $entry) {
            $out[] = [
                'id' => (string)$entry['id'],
                'occurred_at' => (string)$entry['occurred_at'],
                'actor_type' => (string)$entry['actor_type'],
                'actor_ref' => (string)$entry['actor_ref'],
                'action' => (string)$entry['action'],
                'subject_type' => (string)$entry['subject_type'],
                'subject_ref' => (string)$entry['subject_ref'],
                'outcome' => (string)$entry['outcome'],
            ];
        }
        return $out;
    }

    private function count(string $sql): int
    {
        return (int)$this->db->scalar($sql);
    }
}
