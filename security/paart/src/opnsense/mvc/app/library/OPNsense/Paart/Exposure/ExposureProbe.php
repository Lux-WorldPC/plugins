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
 * The "Verify my configuration" client side (M09): one HTTPS request from
 * the firewall itself toward the exposed frontend, answering with the
 * status, the body and the certificate the frontend presented. Injected
 * so the verification logic is testable without a listening HAProxy;
 * CurlExposureProbe is the production one.
 */

namespace OPNsense\Paart\Exposure;

interface ExposureProbe
{
    /**
     * @param string $url full https URL, whose host is the public
     *        enrollment host (so SNI and Host are the real ones).
     * @param string $host the URL's host, pinned to $ip:$port below —
     *        the request never leaves the firewall.
     * @param string $ip the address to connect to instead of resolving.
     * @param int $port the port to connect to.
     * @return array{status: int, body: string, cert: ?string} HTTP status
     *         (0 when no HTTP answer came), body, leaf certificate as PEM
     *         (null when the handshake failed).
     * @throws ExposureException EXPOSURE_UNAVAILABLE when no connection
     *         could be made at all (nothing listens, refused, or no answer
     *         within the probe's timeout).
     */
    public function fetch(string $url, string $host, string $ip, int $port): array;
}
