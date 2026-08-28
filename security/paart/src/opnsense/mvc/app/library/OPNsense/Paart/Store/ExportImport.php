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
 * Store export / import (M02 — backup & restore).
 *
 * The SQLite store is NOT part of the OPNsense configuration backup; losing it
 * means losing the device-to-IP mapping. This service produces a portable
 * export (consistent database snapshot + version manifest) and restores it
 * with a schema version check. The M08 UI will wrap these primitives into a
 * downloadable archive; the on-disk layout here is the stable contract:
 *
 *   <dir>/store.db        consistent snapshot (online backup API)
 *   <dir>/manifest.json   {"format":1,"schema_version":N,"exported_at":...}
 */

namespace OPNsense\Paart\Store;

final class ExportImport
{
    /** Layout version of the export directory itself. */
    private const FORMAT = 1;

    /**
     * Export a consistent snapshot of $db into $dir (created 0700 if needed).
     *
     * @return string path of the written manifest.
     * @throws StoreException when the directory or snapshot cannot be written.
     */
    public static function export(Database $db, Migrator $migrator, string $dir): string
    {
        if (!\is_dir($dir) && !@\mkdir($dir, 0700, true)) {
            throw new StoreException("Cannot create export directory '$dir'.");
        }

        $db->backupTo($dir . '/store.db');

        $manifest = [
            'format' => self::FORMAT,
            'schema_version' => $migrator->currentVersion(),
            'exported_at' => Database::utcNow(),
        ];
        $manifestPath = $dir . '/manifest.json';
        $json = \json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (\file_put_contents($manifestPath, $json . "\n") === false) {
            throw new StoreException("Cannot write manifest '$manifestPath'.");
        }
        return $manifestPath;
    }

    /**
     * Restore an export produced by export() to $destDbPath.
     *
     * Version rules: an export NEWER than the running code is refused (same
     * protection as Migrator); an OLDER one is accepted — the next migrate()
     * call brings it up to date. Refuses to overwrite an existing database:
     * restoring over live data must be an explicit two-step admin action
     * (export or delete first), never a silent overwrite.
     *
     * @param int $codeLatestVersion highest schema version this code knows.
     * @throws StoreException on missing/invalid export or version mismatch.
     */
    public static function import(string $dir, string $destDbPath, int $codeLatestVersion): void
    {
        $manifestPath = $dir . '/manifest.json';
        $raw = @\file_get_contents($manifestPath);
        if ($raw === false) {
            throw new StoreException("Export manifest '$manifestPath' is missing or unreadable.");
        }
        $manifest = \json_decode($raw, true);
        if (!\is_array($manifest) || ($manifest['format'] ?? null) !== self::FORMAT) {
            throw new StoreException("Export manifest '$manifestPath' has an unsupported format.");
        }

        $exportVersion = (int)($manifest['schema_version'] ?? -1);
        if ($exportVersion < 0) {
            throw new StoreException("Export manifest '$manifestPath' lacks a schema_version.");
        }
        if ($exportVersion > $codeLatestVersion) {
            throw new StoreException(
                "Export schema version $exportVersion is newer than this code " .
                "(latest known: $codeLatestVersion). Upgrade the plugin before importing."
            );
        }

        $srcDb = $dir . '/store.db';
        if (!\is_file($srcDb)) {
            throw new StoreException("Export database '$srcDb' is missing.");
        }
        if (\file_exists($destDbPath)) {
            throw new StoreException(
                "A store already exists at '$destDbPath'. Refusing to overwrite it; " .
                'export or remove the current store explicitly first.'
            );
        }

        $destDir = \dirname($destDbPath);
        if (!\is_dir($destDir) && !@\mkdir($destDir, 0700, true)) {
            throw new StoreException("Cannot create store directory '$destDir'.");
        }
        if (!@\copy($srcDb, $destDbPath)) {
            throw new StoreException("Cannot copy '$srcDb' to '$destDbPath'.");
        }
        @\chmod($destDbPath, 0600);
    }
}
