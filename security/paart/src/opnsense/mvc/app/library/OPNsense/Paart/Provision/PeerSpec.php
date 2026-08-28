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
 * Immutable description of ONE peer to write (M06). Carries exactly what a
 * peer is allowed to contain: public key, a single /32 tunnel address, and
 * a human-facing name. No PresharedKey (ADR 0002), no Endpoint (roaming
 * clients), and obviously no private key (forbidden rule #1).
 *
 * Name convention: `paart.<user>.<device>.<pubkey8>` — dot-separated because
 * the os-wireguard client model enforces /^[0-9a-zA-Z._-]{1,64}$/ on names
 * (measured, V3 raw/Client.xml); the colon convention originally sketched in
 * M06 is not representable. The name is for humans only — reconciliation
 * always keys on the public key, never on the name (forbidden rule #5).
 */

namespace OPNsense\Paart\Provision;

use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Domain\PublicKey;

final class PeerSpec
{
    public readonly string $publicKey;
    /** Bare IPv4 tunnel address; always written as <address>/32. */
    public readonly string $address;
    public readonly string $name;

    /** @throws DomainException VALIDATION_FAILED on any malformed field. */
    public function __construct(string $publicKey, string $address, string $name)
    {
        PublicKey::assertValid($publicKey);
        if (\filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new DomainException('VALIDATION_FAILED', "Invalid peer IPv4 address '$address'.");
        }
        if (\preg_match('/^[0-9a-zA-Z._-]{1,64}$/', $name) !== 1) {
            throw new DomainException(
                'VALIDATION_FAILED',
                "Invalid peer name '$name': allowed are [0-9a-zA-Z._-], 1 to 64 characters."
            );
        }
        $this->publicKey = $publicKey;
        $this->address = $address;
        $this->name = $name;
    }

    /**
     * Build a spec with the conventional name for a device, truncating the
     * device part so the whole name fits the 64-character model limit.
     */
    public static function forDevice(
        string $userSlug,
        string $deviceLabel,
        string $publicKey,
        string $address
    ): self {
        $key8 = \substr(\preg_replace('/[^0-9a-zA-Z]/', '', $publicKey), 0, 8);
        $prefix = 'paart.' . $userSlug . '.';
        $suffix = '.' . $key8;

        $device = \trim(\preg_replace('/[^0-9a-zA-Z._-]+/', '-', $deviceLabel), '-.');
        if ($device === '') {
            $device = 'device';
        }
        $room = 64 - \strlen($prefix) - \strlen($suffix);
        $device = \rtrim(\substr($device, 0, \max(1, $room)), '-.');

        return new self($publicKey, $address, $prefix . $device . $suffix);
    }

    /** Value for the os-wireguard `tunneladdress` field. */
    public function tunnelAddress(): string
    {
        return $this->address . '/32';
    }
}
