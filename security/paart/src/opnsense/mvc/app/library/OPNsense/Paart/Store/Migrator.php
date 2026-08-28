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
 * Schema migrator for the plugin store (M02).
 *
 * Migrations are plain SQL files named 'NNNN-description.sql' (NNNN zero-padded
 * digits, strictly increasing; description lowercase [0-9a-z-] only) applied in
 * order inside one transaction each. Rules from the spec, enforced here:
 *  - numbered, non-reversible, never destructive without a prior backup:
 *    a snapshot of the database is written before an upgrade is applied
 *    (skipped for a fresh store, where there is nothing to protect);
 *  - migrate() checks schema_version first: a database NEWER than the code
 *    refuses to run (SCHEMA_MISMATCH), so a downgraded package cannot
 *    corrupt newer data;
 *  - re-running is idempotent (already-applied migrations are skipped).
 */

namespace OPNsense\Paart\Store;

final class Migrator
{
    private Database $db;
    private string $migrationsDir;

    /**
     * @param Database $db store handle the migrations run against.
     * @param string $migrationsDir directory holding the 'NNNN-description.sql'
     *        files (naming rules in the file header).
     */
    public function __construct(Database $db, string $migrationsDir)
    {
        $this->db = $db;
        $this->migrationsDir = $migrationsDir;
    }

    /** Schema version currently recorded in the database; 0 for a fresh store. */
    public function currentVersion(): int
    {
        $this->ensureMetaTable();
        $value = $this->db->scalar(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        );
        return $value === null ? 0 : (int)$value;
    }

    /** Highest migration number shipped with this code; 0 if none found. */
    public function latestVersion(): int
    {
        $files = $this->migrationFiles();
        return $files === [] ? 0 : \max(\array_keys($files));
    }

    /**
     * Bring the store up to the code's schema version.
     *
     * @return int[] versions applied by this call, in order (empty = up to date).
     * @throws StoreException when the database is newer than the code, or a
     *                        migration fails (the failing one is rolled back).
     */
    public function migrate(): array
    {
        $current = $this->currentVersion();
        $files = $this->migrationFiles();
        $latest = $files === [] ? 0 : \max(\array_keys($files));

        if ($current > $latest) {
            throw new StoreException(
                "Store schema version $current is newer than this code (latest known: $latest). " .
                'Refusing to start: upgrade the plugin package instead of downgrading the data.',
                'SCHEMA_MISMATCH'
            );
        }
        if ($current === $latest) {
            return [];
        }

        // One snapshot per migration run, taken before anything changes.
        if ($current > 0) {
            $this->db->backupTo($this->backupPath($current));
        }

        $applied = [];
        foreach ($files as $version => $path) {
            if ($version <= $current) {
                continue;
            }
            $sql = \file_get_contents($path);
            if ($sql === false) {
                // Migrations 1..N-1 of this run are already committed one by
                // one above; say where the store actually stands.
                $reached = $applied === [] ? $current : (int)\end($applied);
                throw new StoreException(
                    "Cannot read migration file '$path'. The store stays at schema version " .
                    "$reached; migrations already applied by this run remain applied, " .
                    'none was half-applied.'
                );
            }
            $this->db->transaction(function (Database $db) use ($sql, $version): void {
                $db->exec($sql);
                $db->run(
                    "INSERT INTO schema_meta (key, value) VALUES ('schema_version', :v)
                     ON CONFLICT (key) DO UPDATE SET value = :v",
                    [':v' => (string)$version]
                );
            });
            $applied[] = $version;
        }
        return $applied;
    }

    /**
     * Migration files indexed by version, sorted ascending.
     *
     * @return array<int, string> version => absolute path.
     * @throws StoreException on unreadable directory or duplicate version.
     */
    private function migrationFiles(): array
    {
        $entries = @\scandir($this->migrationsDir);
        if ($entries === false) {
            throw new StoreException(
                "Cannot read migrations directory '{$this->migrationsDir}'. No migration was applied."
            );
        }
        $files = [];
        foreach ($entries as $entry) {
            if (\preg_match('/^(\d{4})-[0-9a-z-]+\.sql$/', $entry, $m) !== 1) {
                continue;
            }
            $version = (int)$m[1];
            if (isset($files[$version])) {
                throw new StoreException(
                    "Duplicate migration version $version in '{$this->migrationsDir}'. " .
                    'No migration was applied.'
                );
            }
            $files[$version] = $this->migrationsDir . '/' . $entry;
        }
        \ksort($files);
        return $files;
    }

    /** schema_meta is owned by the migrator; safe to call repeatedly. */
    private function ensureMetaTable(): void
    {
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)'
        );
    }

    /** Backup file placed next to the store, named after schema version and time. */
    private function backupPath(int $fromVersion): string
    {
        return $this->db->path() . '.pre-migration-v' . $fromVersion . '-' . \gmdate('Ymd\THis\Z');
    }
}
