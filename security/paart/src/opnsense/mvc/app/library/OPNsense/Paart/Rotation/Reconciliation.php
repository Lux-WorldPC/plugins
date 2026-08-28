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
 * Periodic reconciliation (M05): compare the peers actually configured on
 * each declared instance with the devices the store expects, and REPORT.
 *
 * This job never corrects anything — no write to the firewall, no write to
 * device state. An automatic "fix" could delete a legitimate peer; the
 * admin decides (spec rule). Findings, matched on the PUBLIC KEY only
 * (forbidden rule #5):
 *
 *   unmanaged — peer on the firewall, unknown to the store. Normal for a
 *               hand-managed peer; alarming when the key belongs to a
 *               REVOKED device (its removal never took — access is NOT
 *               cut), so those carry the device id and are what makes the
 *               run alert-worthy.
 *   drift     — device expected ('active'/'rotating'), key absent from the
 *               firewall: the peer was removed out of band.
 *   conflict  — key present but under a different address than allocated.
 *
 * 'pending' devices are ignored on both sides: mid-enrollment is a normal
 * transient and cleanupAbandoned() (M04) owns the stale ones.
 *
 * The audit log tracks the anomaly STATE, not the runs: an entry is
 * written when the set of anomalies (drift, conflict, or a revoked key
 * still live) differs from the one last recorded — the first time they
 * appear, each time they change, and once more (outcome success) when a
 * run finds them cleared. The cron job of M10 runs every 15 minutes: a
 * persisting anomaly is signalled once, not 96 times a day, and plain
 * unmanaged peers never count (M07 noise rule) — they are in the returned
 * report only. The journal copy is redacted to key fingerprints (M07):
 * only the RETURNED report carries full public keys, because callers
 * match live peers by key.
 */

namespace OPNsense\Paart\Rotation;

use OPNsense\Paart\Domain\AuditTrail;
use OPNsense\Paart\Domain\PublicKey;
use OPNsense\Paart\Provision\PeerProvisioner;
use OPNsense\Paart\Provision\ProvisionException;
use OPNsense\Paart\Store\Database;

final class Reconciliation
{
    private Database $db;
    private PeerProvisioner $provisioner;
    private AuditTrail $audit;

    /**
     * @param Database $db the plugin store (devices, instances).
     * @param PeerProvisioner $provisioner read-only here: listPeers() only,
     *        a pass never writes to the firewall.
     * @param AuditTrail $audit receives the reconcile.report entry (redacted
     *        copy, see run()).
     */
    public function __construct(Database $db, PeerProvisioner $provisioner, AuditTrail $audit)
    {
        $this->db = $db;
        $this->provisioner = $provisioner;
        $this->audit = $audit;
    }

    /**
     * Run one reconciliation pass over every declared instance. An instance
     * whose peers cannot be listed (gone from the firewall, API down) is
     * reported under 'unavailable' and its devices are NOT flagged as drift
     * — absence of evidence is not evidence of removal.
     *
     * @return array{
     *   instances: array<string, array{
     *     unmanaged: array<int, array<string, mixed>>,
     *     drift: array<int, array<string, mixed>>,
     *     conflict: array<int, array<string, mixed>>
     *   }>,
     *   unavailable: array<int, string>,
     *   unavailable_reasons: array<string, string>
     * } keyed by wg_instance_ref; unavailable_reasons carries the cause
     *   per unavailable ref (additive, so the report says WHY).
     */
    public function run(): array
    {
        $report = ['instances' => [], 'unavailable' => [], 'unavailable_reasons' => []];
        $anomalies = 0;

        $instances = $this->db->query('SELECT * FROM instances ORDER BY id');
        foreach ($instances as $instance) {
            $ref = (string)$instance['wg_instance_ref'];
            try {
                $peers = $this->provisioner->listPeers($ref);
            } catch (ProvisionException $e) {
                $report['unavailable'][] = $ref;
                $report['unavailable_reasons'][$ref] = $e->getMessage();
                continue;
            }

            $findings = $this->compare((string)$instance['id'], $peers);
            $report['instances'][$ref] = $findings;
            $anomalies += \count($findings['drift']) + \count($findings['conflict'])
                + \count(\array_filter($findings['unmanaged'], fn(array $f): bool => isset($f['device_id'])));
        }

        // The journal copy is redacted: the RETURNED report keeps full
        // public keys (callers match live peers by key), the audit log
        // never stores one (M07 — fingerprints only). Recorded only when
        // the anomaly set changed since the last entry ('' = none).
        $redacted = self::fingerprintKeys($report);
        $signature = $anomalies > 0 ? \hash('sha256', (string)\json_encode(self::anomaliesOf($redacted))) : '';
        if ($signature !== $this->lastSignature()) {
            $this->audit->record(
                'system',
                'reconciliation',
                'reconcile.report',
                'store',
                'devices',
                $anomalies > 0 ? 'failure' : 'success',
                ['report' => $redacted, 'anomalies' => $anomalies, 'signature' => $signature]
            );
        }
        return $report;
    }

    /**
     * The anomalies alone, per instance — what decides whether a run is
     * worth a journal entry. Unavailable instances are not anomalies
     * (absence of evidence) and plain unmanaged peers are not either.
     *
     * @param array<string, mixed> $report a (redacted) run() report.
     * @return array<string, array{drift: mixed, conflict: mixed, alarming: array<int, mixed>}>
     */
    private static function anomaliesOf(array $report): array
    {
        $out = [];
        foreach ($report['instances'] as $ref => $findings) {
            $out[$ref] = [
                'drift' => $findings['drift'],
                'conflict' => $findings['conflict'],
                'alarming' => \array_values(\array_filter(
                    $findings['unmanaged'],
                    static fn(array $f): bool => isset($f['device_id'])
                )),
            ];
        }
        return $out;
    }

    /**
     * Signature stored by the last reconcile.report entry; '' when there is
     * none or it recorded no anomaly. An entry written before signatures
     * existed reads '' too, so a still-standing anomaly is recorded once
     * more after the upgrade — a one-off, accepted.
     */
    private function lastSignature(): string
    {
        $last = $this->db->query(
            "SELECT detail_json FROM audit_log WHERE action = 'reconcile.report' ORDER BY rowid DESC LIMIT 1"
        );
        if ($last === []) {
            return '';
        }
        $detail = \json_decode((string)$last[0]['detail_json'], true);
        return \is_array($detail) ? (string)($detail['signature'] ?? '') : '';
    }

    /**
     * Deep copy of a report with every 'public_key' value fingerprinted,
     * whatever its nesting — findings move (M05 evolves the shapes) and a
     * missed path here would put a full key back in the journal.
     *
     * @param array<string, mixed> $node report (or sub-tree) to redact.
     * @return array<string, mixed>
     */
    private static function fingerprintKeys(array $node): array
    {
        foreach ($node as $key => $value) {
            if (\is_array($value)) {
                $node[$key] = self::fingerprintKeys($value);
            } elseif ($key === 'public_key' && \is_string($value)) {
                $node[$key] = PublicKey::fingerprint($value);
            }
        }
        return $node;
    }

    /**
     * Compare one instance's live peers with its expected devices.
     *
     * @param string $instanceId instances ULID.
     * @param array<int, array<string, mixed>> $peers listPeers() rows.
     * @return array{
     *   unmanaged: array<int, array<string, mixed>>,
     *   drift: array<int, array<string, mixed>>,
     *   conflict: array<int, array<string, mixed>>
     * }
     */
    private function compare(string $instanceId, array $peers): array
    {
        $expected = [];   // public_key => devices row ('active' | 'rotating')
        $revoked = [];    // public_key => device id, to flag failed removals
        $rows = $this->db->query(
            "SELECT * FROM devices WHERE instance_id = :i AND status != 'pending'",
            [':i' => $instanceId]
        );
        foreach ($rows as $device) {
            if ($device['status'] === 'revoked') {
                $revoked[(string)$device['public_key']] = (string)$device['id'];
            } else {
                $expected[(string)$device['public_key']] = $device;
            }
        }

        $findings = ['unmanaged' => [], 'drift' => [], 'conflict' => []];
        foreach ($peers as $peer) {
            $key = (string)$peer['public_key'];
            $device = $expected[$key] ?? null;
            if ($device === null) {
                $finding = [
                    'public_key' => $key,
                    'peer_name' => (string)$peer['name'],
                ];
                if (isset($revoked[$key])) {
                    // The dangerous case: revoked in the store, still live.
                    $finding['device_id'] = $revoked[$key];
                    $finding['device_status'] = 'revoked';
                }
                $findings['unmanaged'][] = $finding;
                continue;
            }
            unset($expected[$key]); // seen — whatever remains is drift
            $wanted = $device['ip_address'] . '/32';
            if (!\in_array($wanted, (array)$peer['tunnel_addresses'], true)) {
                $findings['conflict'][] = [
                    'device_id' => (string)$device['id'],
                    'public_key' => $key,
                    'expected_address' => $wanted,
                    'found_addresses' => (array)$peer['tunnel_addresses'],
                ];
            }
        }
        foreach ($expected as $key => $device) {
            $findings['drift'][] = [
                'device_id' => (string)$device['id'],
                'public_key' => $key,
                'device_status' => (string)$device['status'],
            ];
        }
        return $findings;
    }
}
