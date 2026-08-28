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
 * Server-side ordering for the hand-written bootgrid feeds (M08 Users and
 * Devices). Those screens are backed by SQLite rows the façade already
 * loads in full before the controller slices out one page, so the sort
 * belongs here — between loading and slicing — and never in the browser,
 * which only ever holds one page and would sort it against itself.
 *
 * The requested column is matched against a whitelist supplied by the
 * caller; anything else — unknown column, unknown direction — leaves the
 * order untouched rather than guessing. The column name arrives from the
 * client's request, so that whitelist is the only thing standing between a
 * query parameter and an arbitrary array key.
 *
 * Three comparison kinds, because "sorted" means something different per
 * column (see the constants). Two rules hold across all of them:
 *
 *  - **Absent values sort last, in both directions.** A device that never
 *    completed a handshake is not the one with the oldest handshake, and a
 *    person who never connected is not the one who connected longest ago:
 *    they have no value at all, and a reader scanning from the top should
 *    not meet them first when reversing the order.
 *  - **Equal values keep the store's order.** PHP's sort is stable, so the
 *    feed's fixed order (users by slug, devices by creation) survives as
 *    the implicit secondary key.
 */

namespace OPNsense\Paart\Support;

final class GridSort
{
    /**
     * Human-facing text: names, labels, slugs, IP addresses. Compared
     * case-insensitively, accent-folded, and *naturally* — which is what
     * makes `10.0.0.9` precede `10.0.0.10`, and `Laptop 2` precede
     * `Laptop 10`, the way the reader expects rather than the way bytes do.
     */
    public const TEXT = 'text';

    /** Integers and floats: device counts, handshake ages in seconds. */
    public const NUMBER = 'number';

    /**
     * ISO-8601 UTC instants as the store writes them (`Database::utcNow`).
     * Fixed width and zero-padded, so plain byte order is chronological —
     * no parsing, and no timezone to get wrong.
     */
    public const TIMESTAMP = 'timestamp';

    /**
     * Order rows by one whitelisted column.
     *
     * @param array<int, array<string, mixed>> $rows the full result set,
     *        before pagination.
     * @param array<string, string> $sortable column name => one of TEXT,
     *        NUMBER, TIMESTAMP. Columns absent from this map are refused.
     * @param string $column the column the client asked for; '' or unknown
     *        leaves $rows untouched.
     * @param string $direction 'asc' or 'desc', case-insensitive; anything
     *        else leaves $rows untouched.
     * @return array<int, array<string, mixed>> reindexed from 0.
     */
    public static function apply(
        array $rows,
        array $sortable,
        string $column,
        string $direction
    ): array {
        $kind = $sortable[$column] ?? null;
        $direction = \strtolower($direction);
        if ($kind === null || ($direction !== 'asc' && $direction !== 'desc')) {
            return \array_values($rows);
        }

        $descending = $direction === 'desc';
        \usort($rows, static function (array $a, array $b) use ($column, $kind, $descending): int {
            $left = $a[$column] ?? null;
            $right = $b[$column] ?? null;

            // Absent last, whichever way the column is pointing — so the
            // direction is deliberately NOT applied to this branch.
            $leftAbsent = self::isAbsent($left, $kind);
            $rightAbsent = self::isAbsent($right, $kind);
            if ($leftAbsent || $rightAbsent) {
                return $leftAbsent <=> $rightAbsent;
            }

            $order = self::compare($left, $right, $kind);
            return $descending ? -$order : $order;
        });

        return $rows;
    }

    // -------------------------------------------------------------- helpers

    /**
     * Whether a cell carries no value. null always counts; so does the
     * empty string for the two textual kinds, where "" is how a missing
     * name or a missing timestamp reaches us. For NUMBER, absence is
     * anything not numeric — so 0 is a value and '' is not, which is the
     * distinction the handshake column depends on.
     *
     * @param mixed $value
     */
    private static function isAbsent($value, string $kind): bool
    {
        if ($value === null) {
            return true;
        }
        if ($kind === self::NUMBER) {
            return !\is_numeric($value);
        }
        return (string)$value === '';
    }

    /**
     * @param mixed $left
     * @param mixed $right
     */
    private static function compare($left, $right, string $kind): int
    {
        if ($kind === self::NUMBER) {
            return (float)$left <=> (float)$right;
        }
        if ($kind === self::TIMESTAMP) {
            return \strcmp((string)$left, (string)$right);
        }
        return \strnatcasecmp(self::foldAccents((string)$left), self::foldAccents((string)$right));
    }

    /**
     * Fold accented letters onto their ASCII base so that "Émile" sorts
     * between "Edgar" and "Fabien" rather than after "Zoé". Byte order
     * puts every multi-byte character after "z", which is the single most
     * visible way a French-language name list can look broken.
     *
     * Done with an explicit table rather than a library call: the target
     * runtime (OPNsense 26.1, PHP 8.3) ships **neither ext/iconv nor
     * ext/intl**, so `iconv('ASCII//TRANSLIT')` and `Transliterator` are
     * both unavailable — a fatal error, not a graceful failure. mbstring
     * is present but only converts encodings; it does not transliterate.
     * A table costs nothing at this size, behaves identically on every
     * host, and cannot be silently disabled by a build option.
     *
     * The map covers Latin-1 Supplement and the common Latin Extended-A
     * letters. Anything outside it keeps its bytes and therefore sorts
     * after "z" — visible, and correctable by extending the table.
     */
    private static function foldAccents(string $value): string
    {
        return \strtr($value, self::ASCII_FOLD);
    }

    /**
     * Accented letter => ASCII base, both cases (the comparison folds
     * ASCII case on its own, so 'É' maps to 'E' and 'é' to 'e').
     * Ligatures and eszett expand to the letter pair a reader expects to
     * sort by: "Œuvre" among the O's, "Straße" as "Strasse".
     */
    private const ASCII_FOLD = [
        'À' => 'A', 'Á' => 'A', 'Â' => 'A', 'Ã' => 'A', 'Ä' => 'A', 'Å' => 'A', 'Ā' => 'A', 'Ă' => 'A', 'Ą' => 'A',
        'à' => 'a', 'á' => 'a', 'â' => 'a', 'ã' => 'a', 'ä' => 'a', 'å' => 'a', 'ā' => 'a', 'ă' => 'a', 'ą' => 'a',
        'Ç' => 'C', 'Ć' => 'C', 'Č' => 'C', 'ç' => 'c', 'ć' => 'c', 'č' => 'c',
        'Ď' => 'D', 'Đ' => 'D', 'Ð' => 'D', 'ď' => 'd', 'đ' => 'd', 'ð' => 'd',
        'È' => 'E', 'É' => 'E', 'Ê' => 'E', 'Ë' => 'E', 'Ē' => 'E', 'Ę' => 'E', 'Ě' => 'E',
        'è' => 'e', 'é' => 'e', 'ê' => 'e', 'ë' => 'e', 'ē' => 'e', 'ę' => 'e', 'ě' => 'e',
        'Ì' => 'I', 'Í' => 'I', 'Î' => 'I', 'Ï' => 'I', 'Ī' => 'I', 'Į' => 'I',
        'ì' => 'i', 'í' => 'i', 'î' => 'i', 'ï' => 'i', 'ī' => 'i', 'į' => 'i',
        'Ĺ' => 'L', 'Ľ' => 'L', 'Ł' => 'L', 'ĺ' => 'l', 'ľ' => 'l', 'ł' => 'l',
        'Ñ' => 'N', 'Ń' => 'N', 'Ň' => 'N', 'ñ' => 'n', 'ń' => 'n', 'ň' => 'n',
        'Ò' => 'O', 'Ó' => 'O', 'Ô' => 'O', 'Õ' => 'O', 'Ö' => 'O', 'Ø' => 'O', 'Ō' => 'O', 'Ő' => 'O',
        'ò' => 'o', 'ó' => 'o', 'ô' => 'o', 'õ' => 'o', 'ö' => 'o', 'ø' => 'o', 'ō' => 'o', 'ő' => 'o',
        'Ŕ' => 'R', 'Ř' => 'R', 'ŕ' => 'r', 'ř' => 'r',
        'Ś' => 'S', 'Š' => 'S', 'Ş' => 'S', 'ś' => 's', 'š' => 's', 'ş' => 's',
        'Ť' => 'T', 'Ţ' => 'T', 'ť' => 't', 'ţ' => 't',
        'Ù' => 'U', 'Ú' => 'U', 'Û' => 'U', 'Ü' => 'U', 'Ū' => 'U', 'Ů' => 'U', 'Ű' => 'U',
        'ù' => 'u', 'ú' => 'u', 'û' => 'u', 'ü' => 'u', 'ū' => 'u', 'ů' => 'u', 'ű' => 'u',
        'Ý' => 'Y', 'Ÿ' => 'Y', 'ý' => 'y', 'ÿ' => 'y',
        'Ź' => 'Z', 'Ż' => 'Z', 'Ž' => 'Z', 'ź' => 'z', 'ż' => 'z', 'ž' => 'z',
        'Æ' => 'AE', 'æ' => 'ae', 'Œ' => 'OE', 'œ' => 'oe',
        'Þ' => 'TH', 'þ' => 'th', 'ß' => 'ss',
    ];
}
