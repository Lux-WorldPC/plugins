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
 * ExposureProbe over curl: CURLOPT_RESOLVE pins the public host to the
 * frontend's local address, so the request carries the real Host and
 * SNI while staying on the firewall; peer verification is off because
 * the certificate is what the probe INSPECTS (validity, names, pin) —
 * the clients do the real verification. CURLINFO_CERTINFO yields the
 * chain, of which the leaf is returned.
 */

namespace OPNsense\Paart\Exposure;

final class CurlExposureProbe implements ExposureProbe
{
    /** Seconds; the frontend is local, anything slower is a fault. */
    private const TIMEOUT_S = 10;

    /** {@inheritDoc} */
    public function fetch(string $url, string $host, string $ip, int $port): array
    {
        $ch = \curl_init($url);
        \curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => self::TIMEOUT_S,
            CURLOPT_RESOLVE => ["$host:$port:$ip"],
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_CERTINFO => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $raw = \curl_exec($ch);
        $errno = \curl_errno($ch);
        $error = \curl_error($ch);
        $status = (int)\curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $info = \curl_getinfo($ch, CURLINFO_CERTINFO);
        \curl_close($ch);

        $cert = null;
        if (\is_array($info) && isset($info[0]['Cert'])) {
            $cert = (string)$info[0]['Cert'];
        }
        if ($raw === false || $errno !== 0) {
            if ($errno === CURLE_COULDNT_CONNECT || $errno === CURLE_OPERATION_TIMEDOUT) {
                throw new ExposureException(
                    'EXPOSURE_UNAVAILABLE',
                    "Nothing answered on $ip:$port ($error). Nothing was changed. " .
                    'Check that the HAProxy service is running and that the bind address is right.'
                );
            }
            // TLS-level failures still tell something (a certificate came
            // back or not); report them as a failed probe, not a fault.
            return ['status' => 0, 'body' => $error, 'cert' => $cert];
        }
        return ['status' => $status, 'body' => (string)$raw, 'cert' => $cert];
    }
}
