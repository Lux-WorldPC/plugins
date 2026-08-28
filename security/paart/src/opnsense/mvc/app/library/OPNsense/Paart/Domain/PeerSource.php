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
 * Read-only view of the peers actually present on a declared WireGuard
 * instance. Implemented by the provisioner (M06) over the os-wireguard
 * API; stubbed in tests. M03 consults it before every allocation and
 * every enrollment (spec: collisions with pre-existing peers are detected
 * against the real instance, not against the store alone).
 *
 * Reading only — any write toward WireGuard belongs to M06 exclusively.
 */

namespace OPNsense\Paart\Domain;

interface PeerSource
{
    /**
     * Peers currently configured on the instance, managed by the plugin
     * or not.
     *
     * @param string $wgInstanceRef os-wireguard server uuid (instances.wg_instance_ref).
     * @return array<int, array{public_key: string, host_octets: array<int, int>}>
     *         host_octets: last octets of the peer's tunnel addresses that
     *         fall inside the instance's managed /24 (empty when none do).
     */
    public function livePeers(string $wgInstanceRef): array;
}
