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
 * SQLite access layer for the plugin store (M02).
 *
 * Built on the SQLite3 extension, NOT on PDO: the target OPNsense PHP ships
 * sqlite3 without pdo_sqlite (verified on the target firewall, see
 * docs/verifications/2026-08-22-campagne-v1-v3.md). Dependency-free so the
 * layer runs identically under the OPNsense MVC, CLI scripts and tests.
 *
 * Invariants enforced here for every connection:
 *  - WAL journal mode (verified available on the target),
 *  - foreign keys ON (SQLite defaults them OFF per connection),
 *  - synchronous=NORMAL — safe under WAL (a power loss can only lose the
 *    tail of the log, never corrupt the base) and avoids one fsync per
 *    transaction on the appliance's storage,
 *  - busy timeout, so concurrent admin/API access degrades to waiting,
 *    never to immediate SQLITE_BUSY failures.
 */

namespace OPNsense\Paart\Store;

final class Database
{
    /** Milliseconds a writer waits on a locked database before failing. */
    private const BUSY_TIMEOUT_MS = 5000;

    private \SQLite3 $handle;
    private string $path;
    private int $transactionDepth = 0;

    /**
     * Fail fast, with an actionable message, when the runtime cannot provide
     * SQLite (M02 acceptance: availability is checked at startup with a clear
     * message). Call before any store usage.
     *
     * @throws StoreException when the SQLite3 extension is missing.
     */
    public static function assertAvailable(): void
    {
        if (!\extension_loaded('sqlite3')) {
            throw new StoreException(
                'The PHP SQLite3 extension is not available on this system. ' .
                'The plugin store cannot operate without it; no data has been touched. ' .
                'Install/enable the php-sqlite3 package matching the firmware PHP version.'
            );
        }
    }

    /**
     * Open (creating if needed) the store database at $path and apply the
     * connection invariants. The parent directory is created mode 0700: the
     * store holds hashed secrets and audit data, root-only by design.
     *
     * @throws StoreException on unavailability or failure to open.
     */
    public function __construct(string $path)
    {
        self::assertAvailable();

        $dir = \dirname($path);
        if (!\is_dir($dir) && !@\mkdir($dir, 0700, true)) {
            throw new StoreException("Cannot create store directory '$dir'. No data has been touched.");
        }

        try {
            $this->handle = new \SQLite3($path);
        } catch (\Exception $e) {
            throw new StoreException(
                "Cannot open store database '$path': " . $e->getMessage() . ' No data has been touched.',
                0,
                $e
            );
        }

        $this->path = $path;
        $this->handle->enableExceptions(true);
        $this->handle->busyTimeout(self::BUSY_TIMEOUT_MS);
        $this->handle->exec('PRAGMA journal_mode=WAL');
        $this->handle->exec('PRAGMA foreign_keys=ON');
        $this->handle->exec('PRAGMA synchronous=NORMAL');
    }

    /** Absolute path of the underlying database file. */
    public function path(): string
    {
        return $this->path;
    }

    /**
     * Execute one or more statements that return no rows (DDL, INSERT…).
     * For parameterized single statements prefer run().
     *
     * @throws StoreException wrapping the SQLite error; the message states
     *         whether a transaction was open to roll back.
     */
    public function exec(string $sql): void
    {
        try {
            $this->handle->exec($sql);
        } catch (\Exception $e) {
            throw new StoreException(
                'SQL execution failed: ' . $e->getMessage() . self::failureStateSuffix($this->transactionDepth > 0),
                0,
                $e
            );
        }
    }

    /**
     * Run a single parameterized statement returning no rows.
     *
     * @param array<string|int, mixed> $params ':name' => value bindings.
     * @throws StoreException wrapping the SQLite error; the message states
     *         whether a transaction was open to roll back.
     */
    public function run(string $sql, array $params = []): void
    {
        $stmt = $this->prepare($sql, $params);
        try {
            $stmt->execute()->finalize();
        } catch (\Exception $e) {
            throw new StoreException(
                'SQL execution failed: ' . $e->getMessage() . self::failureStateSuffix($this->transactionDepth > 0),
                0,
                $e
            );
        } finally {
            $stmt->close();
        }
    }

    /**
     * Run a parameterized query and return all rows as associative arrays.
     *
     * @param array<string|int, mixed> $params ':name' => value bindings.
     * @return array<int, array<string, mixed>>
     * @throws StoreException wrapping the SQLite error.
     */
    public function query(string $sql, array $params = []): array
    {
        $stmt = $this->prepare($sql, $params);
        try {
            $result = $stmt->execute();
            $rows = [];
            while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
                $rows[] = $row;
            }
            return $rows;
        } catch (\Exception $e) {
            throw new StoreException(
                'SQL query failed: ' . $e->getMessage() . ' Nothing was changed.',
                0,
                $e
            );
        } finally {
            $stmt->close();
        }
    }

    /**
     * Run a query expected to yield a single scalar (first column of first
     * row); null when there is no row.
     *
     * @param array<string|int, mixed> $params ':name' => value bindings.
     * @throws StoreException wrapping the SQLite error (via query()).
     */
    public function scalar(string $sql, array $params = []): mixed
    {
        $rows = $this->query($sql, $params);
        return $rows === [] ? null : \array_values($rows[0])[0];
    }

    /**
     * Resulting-state sentence for write failures (M08 rule: every error
     * states the resulting state). exec()/run() are called both inside and
     * outside transactions — Migrator bootstrap, rotation-artifact cleanup
     * after a firewall batch — so whether a rollback follows must be read
     * from the live transaction depth, never asserted.
     */
    private static function failureStateSuffix(bool $inTransaction): string
    {
        return $inTransaction
            ? ' The failing statement did not persist; the surrounding transaction is rolled back.'
            : ' The failing statement did not persist; no transaction was open, earlier writes stand.';
    }

    /**
     * Execute $fn atomically. Nested calls join the outermost transaction
     * (SQLite has no true nested transactions; savepoints are not needed at
     * the plugin's volumes). Rolls back and rethrows on any exception.
     *
     * @template T
     * @param callable(Database): T $fn
     * @return T
     * @throws StoreException from BEGIN/COMMIT/ROLLBACK; anything $fn throws
     *         is rethrown unchanged after the rollback.
     */
    public function transaction(callable $fn): mixed
    {
        if ($this->transactionDepth > 0) {
            $this->transactionDepth++;
            try {
                return $fn($this);
            } finally {
                $this->transactionDepth--;
            }
        }

        $this->exec('BEGIN IMMEDIATE');
        $this->transactionDepth = 1;
        try {
            $result = $fn($this);
            $this->exec('COMMIT');
            return $result;
        } catch (\Throwable $e) {
            $this->exec('ROLLBACK');
            throw $e;
        } finally {
            $this->transactionDepth = 0;
        }
    }

    /**
     * Write a consistent snapshot of the live database to $destPath using the
     * SQLite online backup API — safe while the database is in use, WAL
     * included. Used for pre-migration backups and exports.
     *
     * @throws StoreException when the snapshot cannot be written.
     */
    public function backupTo(string $destPath): void
    {
        $dest = null;
        try {
            $dest = new \SQLite3($destPath);
            $dest->enableExceptions(true);
            if (!$this->handle->backup($dest)) {
                throw new StoreException(
                    "Backup to '$destPath' failed. " .
                    'The live database is untouched; the destination file may be incomplete.'
                );
            }
        } catch (\Exception $e) {
            throw new StoreException(
                "Backup to '$destPath' failed: " . $e->getMessage() .
                ' The live database is untouched; the destination file may be incomplete.',
                0,
                $e
            );
        } finally {
            $dest?->close();
        }
    }

    /** Current UTC timestamp in the canonical storage format (RFC 3339, Z). */
    public static function utcNow(): string
    {
        return \gmdate('Y-m-d\TH:i:s\Z');
    }

    /** Close the underlying handle; the object must not be used afterwards. */
    public function close(): void
    {
        $this->handle->close();
    }

    /**
     * @param array<string|int, mixed> $params
     * @throws StoreException when preparation or binding fails.
     */
    private function prepare(string $sql, array $params): \SQLite3Stmt
    {
        try {
            $stmt = $this->handle->prepare($sql);
        } catch (\Exception $e) {
            throw new StoreException(
                'SQL preparation failed: ' . $e->getMessage() . ' Nothing was changed.',
                0,
                $e
            );
        }
        foreach ($params as $name => $value) {
            $type = match (true) {
                \is_int($value) => SQLITE3_INTEGER,
                \is_float($value) => SQLITE3_FLOAT,
                $value === null => SQLITE3_NULL,
                default => SQLITE3_TEXT,
            };
            $stmt->bindValue(\is_int($name) ? $name + 1 : $name, $value, $type);
        }
        return $stmt;
    }
}
