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
 * ULID generator (Universally Unique Lexicographically Sortable Identifier).
 *
 * Every entity in the plugin is keyed by a ULID (project convention: UTC in
 * storage, ULID for all entities). Kept dependency-free on purpose: this file
 * must be usable from tests and scripts without the OPNsense framework.
 *
 * Generation is MONOTONIC within a millisecond, and that is a correctness
 * requirement here, not a nicety. Timestamps in the store are second-grained
 * (Database::utcNow), so the id is the only tiebreaker chronology has, and
 * the code orders by it: the audit screen reads `ORDER BY id DESC`, and
 * RotationService finds the current rotation with `ORDER BY id DESC LIMIT 1`.
 * With fresh randomness on every call, two rows written in the same
 * millisecond sorted at random — an audit journal showing an effect before
 * its cause, and, seen in the reissue path, "the latest rotation" resolving
 * to the older row. Within one millisecond the random field is therefore
 * incremented rather than redrawn.
 *
 * The guarantee is per process. Two PHP workers writing in the same
 * millisecond can still tie; SQLite serializes the writes but not the id
 * generation. Closing that would take a store-side sequence, which no
 * ordering in this plugin currently needs.
 */

namespace OPNsense\Paart\Support;

final class Ulid
{
    /** Crockford base32 alphabet — no I, L, O, U to avoid misreadings. */
    private const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    /** Millisecond of the last id handed out, and the random field it carried. */
    private static ?int $lastMs = null;
    private static ?string $lastRandom = null;

    /**
     * Generate a 26-character ULID: 10 chars of millisecond timestamp,
     * 16 chars (80 bits) of randomness, incremented instead of redrawn
     * when the previous id fell in the same millisecond.
     *
     * @param int|null $timestampMs Unix time in milliseconds; null = now.
     *                              Exposed for deterministic tests only.
     * @return string 26-character identifier, sorting by time and, within
     *         a millisecond, by order of generation.
     */
    public static function generate(?int $timestampMs = null): string
    {
        $ms = $timestampMs ?? (int)floor(microtime(true) * 1000);

        $random = ($ms === self::$lastMs && self::$lastRandom !== null)
            ? self::increment(self::$lastRandom)
            : self::randomField();
        self::$lastMs = $ms;
        self::$lastRandom = $random;

        $time = '';
        $rest = $ms;
        for ($i = 0; $i < 10; $i++) {
            $time = self::ALPHABET[$rest % 32] . $time;
            $rest = intdiv($rest, 32);
        }

        return $time . $random;
    }

    /** 16 Crockford characters of cryptographic randomness. */
    private static function randomField(): string
    {
        $random = '';
        for ($i = 0; $i < 16; $i++) {
            $random .= self::ALPHABET[random_int(0, 31)];
        }
        return $random;
    }

    /**
     * Add one to a base32 field, right to left, carrying through 'Z'.
     *
     * Overflow needs 2^80 identifiers inside one millisecond, so it cannot
     * happen — and if the impossible did occur, silently wrapping would
     * hand out an id that sorts BEFORE its predecessor, which is the one
     * thing this function exists to prevent. It refuses instead.
     */
    private static function increment(string $field): string
    {
        for ($i = \strlen($field) - 1; $i >= 0; $i--) {
            $pos = \strpos(self::ALPHABET, $field[$i]);
            if ($pos < 31) {
                $field[$i] = self::ALPHABET[$pos + 1];
                return $field;
            }
            $field[$i] = self::ALPHABET[0];
        }
        throw new \RuntimeException('ULID randomness exhausted within a single millisecond.');
    }

    /**
     * Check that a string is a well-formed ULID (charset and length only —
     * this does not prove the value was generated by us).
     */
    public static function isValid(string $value): bool
    {
        return preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/', $value) === 1;
    }
}
