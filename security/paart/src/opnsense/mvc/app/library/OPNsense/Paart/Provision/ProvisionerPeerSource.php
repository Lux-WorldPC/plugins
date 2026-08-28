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
 * Adapter giving the M03 domain its live-peer view (Domain\PeerSource)
 * through the provisioner (M06). Translates peer tunnel addresses into
 * host octets of the instance's managed /24, so the IPAM can exclude
 * pre-existing peers before every allocation. Read-only by construction.
 */

namespace OPNsense\Paart\Provision;

use OPNsense\Paart\Domain\Instances;
use OPNsense\Paart\Domain\PeerSource;
use OPNsense\Paart\Store\Database;

final class ProvisionerPeerSource implements PeerSource
{
    private PeerProvisioner $provisioner;
    private Database $db;

    public function __construct(PeerProvisioner $provisioner, Database $db)
    {
        $this->provisioner = $provisioner;
        $this->db = $db;
    }

    public function livePeers(string $wgInstanceRef): array
    {
        $cidr = $this->db->scalar(
            'SELECT ip_range_cidr FROM instances WHERE wg_instance_ref = :ref',
            [':ref' => $wgInstanceRef]
        );
        $base24 = Instances::parseCidr((string)$cidr)['network'] & 0xFFFFFF00;

        $out = [];
        foreach ($this->provisioner->listPeers($wgInstanceRef) as $peer) {
            $octets = [];
            foreach ($peer['tunnel_addresses'] as $address) {
                $ip = \ip2long((string)\strtok($address, '/'));
                if ($ip !== false && (($ip & 0xFFFFFF00) === $base24)) {
                    $octets[] = $ip & 0xFF;
                }
            }
            $out[] = ['public_key' => $peer['public_key'], 'host_octets' => $octets];
        }
        return $out;
    }
}
