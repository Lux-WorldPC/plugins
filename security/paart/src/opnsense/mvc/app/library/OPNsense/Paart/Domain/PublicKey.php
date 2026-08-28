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
 * WireGuard public key validation (M03 rule: base64, 44 characters,
 * decoding to exactly 32 bytes — rejected otherwise). Validation only:
 * the plugin never generates, stores or transmits PRIVATE keys (forbidden
 * rule #1); nothing in this class or namespace may ever handle one.
 */

namespace OPNsense\Paart\Domain;

final class PublicKey
{
    /** Well-formed Curve25519 public key: 43 base64 chars plus '=' padding. */
    public static function isValid(string $key): bool
    {
        if (\preg_match('#^[A-Za-z0-9+/]{43}=$#', $key) !== 1) {
            return false;
        }
        $raw = \base64_decode($key, true);
        return $raw !== false && \strlen($raw) === 32;
    }

    /**
     * Journal-safe fingerprint (M07): the first 8 characters plus an
     * ellipsis — enough to correlate entries with a device, useless to
     * collect. The audit log NEVER stores a full public key (spec M07);
     * every audit detail carrying a key goes through here. Same shape as
     * the provisioner's error-message fingerprints.
     */
    public static function fingerprint(string $key): string
    {
        return \substr($key, 0, 8) . '…';
    }

    /** @throws DomainException VALIDATION_FAILED when the key is malformed. */
    public static function assertValid(string $key): void
    {
        if (!self::isValid($key)) {
            throw new DomainException(
                'VALIDATION_FAILED',
                'Invalid WireGuard public key: expected 44 base64 characters decoding to 32 bytes.'
            );
        }
    }
}
