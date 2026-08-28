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
 * Periodic maintenance (M10): the one entry point the plugin's cron job
 * and the "VPN Access maintenance" configd action run, over the four
 * housekeeping tasks the modules defined and left to a scheduler:
 *
 *   abandoned — reap 'pending' devices older than an hour, peer removed
 *               with explicit intent (M04, EnrollmentService);
 *   graces    — flag pending rotations whose grace elapsed, device left
 *               untouched (M05, RotationService);
 *   reconcile — compare live peers with the store and REPORT, never
 *               correct (M05, Reconciliation);
 *   purge     — delete audit entries past the retention horizon (M07,
 *               AuditTrail).
 *
 * Tasks run in this fixed order and are isolated: a task that throws is
 * reported under 'errors' and the next one still runs — an unreachable
 * firewall must not postpone the audit purge, nor the reverse. Every task
 * writes its own audit trail under its own system actor ('enroll',
 * 'rotation', 'reconciliation'; the purge takes ACTOR); this class
 * records nothing itself and returns a compact summary — counts and
 * identifiers, never a public key — fit for the configd output the cron
 * page shows. No sleep, no locking here: the cron line holds the flock.
 */

namespace OPNsense\Paart\App;

use OPNsense\Paart\Domain\AuditTrail;
use OPNsense\Paart\Enroll\EnrollmentService;
use OPNsense\Paart\Rotation\Reconciliation;
use OPNsense\Paart\Rotation\RotationService;

final class Maintenance
{
    /** Actor reference the purge records (AuditTrail::purgeExpired's actorRef). */
    public const ACTOR = 'scheduler';
    /** Task names in execution order; run() accepts any subset. */
    public const TASKS = ['abandoned', 'graces', 'reconcile', 'purge'];

    private EnrollmentService $enrollment;
    private RotationService $rotation;
    private Reconciliation $reconciliation;
    private AuditTrail $audit;
    private int $auditRetentionMonths;

    /**
     * @param int $auditRetentionMonths horizon of the purge task
     *        (Container::$auditRetentionMonths, already defaulted).
     */
    public function __construct(
        EnrollmentService $enrollment,
        RotationService $rotation,
        Reconciliation $reconciliation,
        AuditTrail $audit,
        int $auditRetentionMonths
    ) {
        $this->enrollment = $enrollment;
        $this->rotation = $rotation;
        $this->reconciliation = $reconciliation;
        $this->audit = $audit;
        $this->auditRetentionMonths = $auditRetentionMonths;
    }

    /**
     * Run the selected tasks, each isolated from the others' failures.
     *
     * @param array<int, string> $tasks subset of TASKS; [] runs them all.
     *        Always executed in TASKS order whatever the order given.
     * @return array{tasks: array<string, array<string, mixed>>,
     *               errors: array<string, string>, ok: bool}
     *         tasks: one summary per task that ran (see the private task
     *         methods); errors: task => "Class: message" for the ones that
     *         threw; ok: no error.
     * @throws \InvalidArgumentException on an unknown task name — a caller
     *         mistake, refused before anything runs.
     */
    public function run(array $tasks = []): array
    {
        $selected = $tasks === [] ? self::TASKS : \array_values(\array_unique($tasks));
        foreach ($selected as $task) {
            if (!\in_array($task, self::TASKS, true)) {
                throw new \InvalidArgumentException(
                    "Unknown maintenance task '$task'; known tasks: " . \implode(', ', self::TASKS) . '.'
                );
            }
        }

        $out = ['tasks' => [], 'errors' => []];
        foreach (self::TASKS as $task) {
            if (!\in_array($task, $selected, true)) {
                continue;
            }
            try {
                $out['tasks'][$task] = match ($task) {
                    'abandoned' => $this->abandoned(),
                    'graces' => $this->graces(),
                    'reconcile' => $this->reconcile(),
                    'purge' => $this->purge(),
                };
            } catch (\Throwable $e) {
                $out['errors'][$task] = \get_class($e) . ': ' . $e->getMessage();
            }
        }
        $out['ok'] = $out['errors'] === [];
        return $out;
    }

    /** @return array{cleaned: array<int, string>, skipped: array<int, string>} device ids. */
    private function abandoned(): array
    {
        $result = $this->enrollment->cleanupAbandoned();
        return ['cleaned' => $result['cleaned'], 'skipped' => $result['skipped']];
    }

    /** @return array{expired: array<int, string>} rotation ids flagged this run. */
    private function graces(): array
    {
        return ['expired' => $this->rotation->expireOverdueGraces()];
    }

    /**
     * Counts only — the full report (with public keys) stays with the
     * callers that need to match peers; the journal has the redacted copy.
     * The reason an instance was unavailable (unavailable_reasons, the
     * gateway's message, never a key) is kept: this summary is what the
     * Cron page and configd show, and nothing else says why — the health
     * payload (/admin/health) only carries the boolean `reachable`.
     *
     * @return array{instances: array<string, array{unmanaged: int, drift: int,
     *               conflict: int, alarming: int}>, unavailable: array<int, string>,
     *               unavailable_reasons: array<string, string>}
     *         keyed by wg_instance_ref; alarming = unmanaged keys that
     *         belong to a revoked device (the peer removal never took).
     */
    private function reconcile(): array
    {
        $report = $this->reconciliation->run();
        $instances = [];
        foreach ($report['instances'] as $ref => $findings) {
            $instances[$ref] = [
                'unmanaged' => \count($findings['unmanaged']),
                'drift' => \count($findings['drift']),
                'conflict' => \count($findings['conflict']),
                'alarming' => \count(\array_filter(
                    $findings['unmanaged'],
                    static fn(array $f): bool => isset($f['device_id'])
                )),
            ];
        }
        return [
            'instances' => $instances,
            'unavailable' => $report['unavailable'],
            'unavailable_reasons' => $report['unavailable_reasons'],
        ];
    }

    /** @return array{deleted: int, retention_months: int} */
    private function purge(): array
    {
        return [
            'deleted' => $this->audit->purgeExpired($this->auditRetentionMonths, self::ACTOR),
            'retention_months' => $this->auditRetentionMonths,
        ];
    }
}
