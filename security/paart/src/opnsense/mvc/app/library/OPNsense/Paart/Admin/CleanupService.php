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
 * The cleanup action (M10 — uninstall, "purge" behaviour).
 *
 * Uninstalling a management tool must not cut a company's VPNs, so the
 * package script only ever KEEPS: +PRE_DEINSTALL removes nothing, says
 * what it leaves behind, and points here. Purging is the other behaviour,
 * and it cannot live in that script — pkg runs with no terminal, and a
 * destructive default nobody can be asked about is exactly what forbidden
 * rule #4 exists to prevent. So it is an action of the plugin's own
 * interface, taken while the plugin is still installed and can still
 * reach the firewall.
 *
 * This service destroys accesses on purpose. Three properties make that
 * defensible, and each is a design constraint, not a comment:
 *
 *   1. It invents NO deletion path. Managed peers go through
 *      AdminService::withdrawInstance('delete'), the same call the
 *      Networks screen uses — which deletes by public key, in one batch
 *      per instance, and records the single audit entry carrying those
 *      keys. Peers this plugin does not manage are never named, never
 *      touched (D8, forbidden rule #3).
 *   2. Nothing is destroyed before the export is safe. With
 *      'export' the snapshot is written FIRST, and outside the store's
 *      own directory, so it survives what follows. A failure to write it
 *      aborts the purge with nothing removed.
 *   3. The order is the reverse of the damage. Exposure first (stop
 *      accepting enrollments), then peers instance by instance, then —
 *      and only from the controller, after config.xml is saved — the
 *      store. Any step that fails stops the sequence and reports what
 *      already went, because a half-purge the admin cannot see is worse
 *      than a refused one.
 *
 * What this service deliberately does NOT do: write config.xml. That
 * belongs to CleanupController, which detaches the plugin's whole node —
 * declarations, settings, WireGuard API credentials and TLS pins alike —
 * and saves the DOM afterwards, reloading it first when a peer batch went
 * through, since that batch rewrote config.xml from another process (the
 * trap of session 16, documented on NetworksController::delNetworkAction).
 *
 * The store is destroyed at the end, which means the audit entries of the
 * purge itself die with it. That is why every run also goes to syslog
 * under the paart program name: the trace of a destruction must outlive
 * what it destroyed.
 */

namespace OPNsense\Paart\Admin;

use OPNsense\Paart\Domain\AuditTrail;
use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Exposure\ExposureService;
use OPNsense\Paart\Store\Database;
use OPNsense\Paart\Store\ExportImport;
use OPNsense\Paart\Store\Migrator;
use OPNsense\Paart\Store\StoreException;

final class CleanupService
{
    /**
     * The admin's choice for the store's contents. No default anywhere:
     * a caller that forgets the parameter gets VALIDATION_FAILED, never
     * a silent destruction (forbidden rule #4, as withdrawInstance).
     */
    public const EXPORT_DISPOSITIONS = ['export', 'skip'];

    /** Export directory name: this prefix plus a UTC stamp, beside the store, never inside it. */
    private const EXPORT_PREFIX = 'paart-export-';

    public function __construct(
        private readonly Database $db,
        private readonly Migrator $migrator,
        private readonly AuditTrail $audit,
        private readonly AdminService $admin,
        private readonly ExposureService $exposure,
        /** Absolute path of the SQLite store — the file this purge ends by removing. */
        private readonly string $dbPath
    ) {
    }

    /**
     * What a purge would destroy, so the admin decides on figures rather
     * than on a warning. Read-only: it changes nothing, and it is the
     * screen's only source — no count is computed twice.
     *
     * `live_peers` counts the devices whose peers the purge would target —
     * the non-revoked ones, exactly the predicate withdrawInstance deletes
     * on, so what is shown here and what is acted on are one question. It
     * is an upper bound, not a promise: withdrawInstance reports the peers
     * the firewall actually lost, which is fewer when one was already gone
     * (drift). Showing the smaller figure here would need a peer-by-peer
     * read of every instance to answer a question the admin asks before
     * deciding — the bound is the honest cheap answer, and the result
     * screen carries the real count.
     * Revoked devices have no peer left to delete and counting them would
     * inflate the harm. A `pending` device counts: its public key is in
     * the store (the column is NOT NULL), and deleting a peer the firewall
     * does not have is a no-op, not an error.
     *
     * @return array{
     *   instances: array<int, array{id: string, label: string,
     *                               wg_instance_ref: string, live_peers: int}>,
     *   totals: array{users: int, devices_live: int, devices_revoked: int,
     *                 tokens_active: int, audit_entries: int},
     *   exposure: array{mode: string, objects: int, reachable: bool, error: ?string},
     *   store: array{path: string, bytes: ?int},
     *   export_target: string
     * }
     */
    public function impact(): array
    {
        $instances = [];
        foreach ($this->db->query('SELECT id, label, wg_instance_ref FROM instances ORDER BY label, id') as $row) {
            $instances[] = [
                'id' => (string)$row['id'],
                'label' => (string)$row['label'],
                'wg_instance_ref' => (string)$row['wg_instance_ref'],
                'live_peers' => $this->count(
                    "SELECT COUNT(*) FROM devices WHERE instance_id = :id AND status != 'revoked'",
                    [':id' => (string)$row['id']]
                ),
            ];
        }

        // The exposure half must never turn a read-only impact call into
        // an error: HAProxy being unreachable is something the admin needs
        // to SEE here (the purge would stop on it), not a failure of the
        // question itself.
        $mode = 'internal_only';
        $objects = 0;
        $reachable = true;
        $error = null;
        try {
            $status = $this->exposure->status();
            $mode = (string)($status['mode'] ?? 'internal_only');
            $objects = \count((array)($status['objects'] ?? []));
        } catch (\Throwable $e) {
            $reachable = false;
            $error = $e->getMessage();
        }

        $bytes = \is_file($this->dbPath) ? (\filesize($this->dbPath) ?: null) : null;

        return [
            'instances' => $instances,
            'totals' => [
                'users' => $this->count('SELECT COUNT(*) FROM users'),
                'devices_live' => $this->count("SELECT COUNT(*) FROM devices WHERE status != 'revoked'"),
                'devices_revoked' => $this->count("SELECT COUNT(*) FROM devices WHERE status = 'revoked'"),
                'tokens_active' => $this->count(
                    'SELECT COUNT(*) FROM enroll_tokens WHERE consumed_at IS NULL'
                ),
                'audit_entries' => $this->count('SELECT COUNT(*) FROM audit_log'),
            ],
            'exposure' => [
                'mode' => $mode,
                'objects' => $objects,
                'reachable' => $reachable,
                'error' => $error,
            ],
            'store' => ['path' => $this->dbPath, 'bytes' => $bytes],
            'export_target' => $this->exportTarget(),
        ];
    }

    /**
     * Run the purge, everything but the store file itself.
     *
     * Returns before the store is removed on purpose: the controller has
     * to remove the plugin's node from config.xml and save it first, and a
     * save that fails while the store is already gone would leave
     * declarations pointing at nothing, with no rows left to say what
     * happened. dropStore() is the last step, and the controller's.
     *
     * @param string $exportDisposition 'export' or 'skip' — no default,
     *        the admin's choice is the whole point.
     * @param string $actorRef authenticated admin identity for the audit trail.
     * @return array{export_path: ?string, exposure_removed: int,
     *               instances: array<int, array{label: string, wg_instance_ref: string,
     *                                           peers_deleted: int}>,
     *               peers_deleted: int}
     * @throws DomainException VALIDATION_FAILED (unknown disposition — nothing
     *         was done) | PROVISIONING_UNAVAILABLE | INSTANCE_UNAVAILABLE |
     *         INTERNAL, propagated from withdrawInstance with the instances
     *         already withdrawn named in the message.
     * @throws StoreException when the export cannot be written — deliberately
     *         fatal and first, so a purge never runs without the backup it
     *         was asked for.
     * @throws \OPNsense\Paart\Exposure\ExposureException when the generated
     *         HAProxy objects cannot be removed. Nothing else has run yet:
     *         leaving twelve orphaned objects behind would be worse than
     *         refusing, since after uninstall no code owns them any more.
     */
    public function purge(string $exportDisposition, string $actorRef): array
    {
        if (!\in_array($exportDisposition, self::EXPORT_DISPOSITIONS, true)) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Purging needs an explicit choice for the store's contents: 'export' " .
                "(a snapshot is written beside the store first) or 'skip'. Nothing was changed."
            );
        }

        $exportPath = null;
        if ($exportDisposition === 'export') {
            $dir = $this->exportTarget();
            ExportImport::export($this->db, $this->migrator, $dir);
            $exportPath = $dir;
        }

        $exposureRemoved = 0;
        $status = $this->exposure->status();
        if ((array)($status['objects'] ?? []) !== []) {
            $removal = $this->exposure->remove($actorRef);
            $exposureRemoved = \count((array)($removal['removed'] ?? []));
        }

        $withdrawn = [];
        $peersDeleted = 0;
        $rows = $this->db->query('SELECT id, label, wg_instance_ref FROM instances ORDER BY label, id');
        foreach ($rows as $row) {
            try {
                $result = $this->admin->withdrawInstance((string)$row['id'], 'delete', $actorRef);
            } catch (\Throwable $e) {
                // Name what already went. The admin is mid-uninstall: a
                // bare error here would leave them guessing which
                // instances still hold peers.
                throw $this->annotated($e, $withdrawn, $exportPath);
            }
            $peersDeleted += (int)$result['peers_deleted'];
            $withdrawn[] = [
                'label' => (string)$result['label'],
                'wg_instance_ref' => (string)$row['wg_instance_ref'],
                'peers_deleted' => (int)$result['peers_deleted'],
            ];
        }

        $summary = \sprintf(
            'cleanup: %d instance(s) withdrawn, %d managed peer(s) deleted, %d exposure object(s) removed, ' .
            'export %s',
            \count($withdrawn),
            $peersDeleted,
            $exposureRemoved,
            $exportPath ?? 'skipped'
        );
        $this->audit->record('admin', $actorRef, 'plugin.cleanup', 'plugin', 'cleanup', 'success', [
            'instances' => \count($withdrawn),
            'peers_deleted' => $peersDeleted,
            'exposure_objects_removed' => $exposureRemoved,
            'export_path' => $exportPath,
        ]);
        $this->log($summary, $actorRef);

        return [
            'export_path' => $exportPath,
            'exposure_removed' => $exposureRemoved,
            'instances' => $withdrawn,
            'peers_deleted' => $peersDeleted,
        ];
    }

    /**
     * Remove the store — the purge's last step, called by the controller
     * once config.xml is saved.
     *
     * The directory is kept: the plugin is still installed, and its
     * bootstrap recreates an empty store there at the next boot. Only the
     * database goes, with the two files SQLite may leave beside it.
     * Anything the purge exported lives in a sibling directory and is
     * never touched here.
     *
     * @return array{removed: array<int, string>, path: string}
     */
    public function dropStore(): array
    {
        $removed = [];
        foreach ([$this->dbPath, $this->dbPath . '-wal', $this->dbPath . '-shm'] as $file) {
            if (\is_file($file) && @\unlink($file)) {
                $removed[] = $file;
            }
        }
        $this->log(\sprintf('cleanup: store removed (%d file(s)) at %s', \count($removed), $this->dbPath), '-');
        return ['removed' => $removed, 'path' => $this->dbPath];
    }

    // -------------------------------------------------------------- internals

    /** Sibling of the store's directory, never inside it — the purge removes what is inside. */
    private function exportTarget(): string
    {
        return \rtrim(\dirname($this->dbPath), '/') . '-export-' . \gmdate('Ymd\THis\Z');
    }

    /**
     * @param array<string, string|int> $bind
     */
    private function count(string $sql, array $bind = []): int
    {
        $rows = $this->db->query($sql, $bind);
        return $rows === [] ? 0 : (int)\array_values($rows[0])[0];
    }

    /**
     * Re-throw a withdrawal failure with the ground already covered named
     * in it. Same class, same code — only the message grows, because the
     * API contract of the failure must not change with the caller.
     *
     * @param array<int, array{label: string, wg_instance_ref: string, peers_deleted: int}> $withdrawn
     */
    private function annotated(\Throwable $e, array $withdrawn, ?string $exportPath): \Throwable
    {
        $done = $withdrawn === []
            ? 'No instance had been withdrawn yet'
            : 'Already withdrawn, and not undone: ' .
              \implode(', ', \array_map(static fn(array $w): string => $w['label'], $withdrawn));
        $note = ' ' . $done . '. The generated HAProxy objects were already removed.' .
            ($exportPath !== null ? " The export is at $exportPath." : '');
        if ($e instanceof DomainException) {
            // Same class, same apiCode: the HTTP layer must map this
            // exactly as it would map the bare withdrawal failure.
            return new DomainException($e->apiCode(), $e->getMessage() . $note);
        }
        return $e;
    }

    /**
     * Syslog under the paart program name, as the bootstrap and
     * maintenance scripts do — the filter of plugins.inc.d routes it to
     * /var/log/paart/. This is the only trace of the purge that survives
     * the store it removes.
     */
    private function log(string $message, string $actorRef): void
    {
        \openlog('paart', LOG_PID, LOG_USER);
        \syslog(LOG_NOTICE, $message . ' (by ' . $actorRef . ')');
        \closelog();
    }
}
