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
 * HTTP projection of the M01 error registry (protocol/error-codes.md):
 * status and retryable flag per stable code, plus the uniform error
 * envelope. The registry is add-only; any code missing from the map is a
 * defect and falls back to INTERNAL (500, not retryable) rather than
 * leaking a raw exception. Framework-free so the mapping is testable on
 * the target runtime.
 */

namespace OPNsense\Paart\Admin;

final class HttpError
{
    /** @var array<string, array{0: int, 1: bool}> code => [HTTP status, retryable] */
    private const MAP = [
        'VALIDATION_FAILED' => [400, false],
        'ENROLLMENT_REJECTED' => [403, false],
        'PUBLIC_KEY_IN_USE' => [409, false],
        'PAYLOAD_TOO_LARGE' => [413, false],
        'RATE_LIMITED' => [429, true],
        'PROVISIONING_UNAVAILABLE' => [503, true],
        'DEVICE_TOKEN_INVALID' => [401, false],
        'ROTATION_NOT_PENDING' => [409, false],
        'NOT_FOUND' => [404, false],
        'USER_DISABLED' => [409, false],
        'DEVICE_NOT_ACTIVE' => [409, false],
        'DEVICE_LIMIT_REACHED' => [409, false],
        'POOL_EXHAUSTED' => [409, false],
        'RANGE_OVERLAP' => [409, false],
        'INSTANCE_NOT_DECLARED' => [409, false],
        'INSTANCE_UNAVAILABLE' => [503, true],
        'SCHEMA_MISMATCH' => [500, false],
        'EXPOSURE_UNAVAILABLE' => [503, true],
        'EXPOSURE_CONFLICT' => [409, false],
        // The registry says "maybe" (whether state changed is unknown); the
        // envelope needs a boolean, and false is the safe projection — a
        // client must never auto-retry an operation whose effect is unknown.
        'INTERNAL' => [500, false],
    ];

    /** HTTP status for a registry code; unknown codes project as INTERNAL (500). */
    public static function status(string $code): int
    {
        return (self::MAP[$code] ?? self::MAP['INTERNAL'])[0];
    }

    /** Retryable flag for a registry code; unknown codes project as INTERNAL (false). */
    public static function retryable(string $code): bool
    {
        return (self::MAP[$code] ?? self::MAP['INTERNAL'])[1];
    }

    /**
     * The uniform error envelope every non-2xx response carries (M01).
     *
     * @return array{error: array{code: string, message: string, retryable: bool}}
     */
    public static function envelope(string $code, string $message): array
    {
        return ['error' => [
            'code' => isset(self::MAP[$code]) ? $code : 'INTERNAL',
            'message' => $message,
            'retryable' => self::retryable($code),
        ]];
    }
}
