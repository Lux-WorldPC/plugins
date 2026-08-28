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
 * Single exception type for the persistence layer (M02). Messages are meant
 * to be actionable for an administrator; they never contain secrets.
 *
 * Like DomainException (M03), it carries a stable API error code from
 * protocol/error-codes.md so HTTP layers can map 1:1 without parsing
 * messages. Most store failures are plain 'INTERNAL' (the default); pass a
 * more specific registry code only where the registry defines one (e.g.
 * SCHEMA_MISMATCH from the migrator). Never invent a code here without
 * adding it to the registry first.
 */

namespace OPNsense\Paart\Store;

class StoreException extends \RuntimeException
{
    private string $apiCode;

    public function __construct(string $message, string $apiCode = 'INTERNAL')
    {
        parent::__construct($message);
        $this->apiCode = $apiCode;
    }

    /** Stable error code from the M01 registry ('INTERNAL' unless more specific). */
    public function apiCode(): string
    {
        return $this->apiCode;
    }
}
