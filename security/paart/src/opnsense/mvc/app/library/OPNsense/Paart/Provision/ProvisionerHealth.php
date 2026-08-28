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
 * Snapshot returned by PeerProvisioner::healthCheck() (M06): availability
 * of every DECLARED instance on the firewall, plus the number of applied
 * but not yet committed changes. Purely informational — health checking
 * never modifies anything.
 */

namespace OPNsense\Paart\Provision;

final class ProvisionerHealth
{
    /** @var array<int, array{wg_instance_ref: string, label: string, available: bool}> */
    public readonly array $instances;
    /** Changes written to the config but awaiting a commit() (reconfigure). */
    public readonly int $pendingChanges;

    /** @param array<int, array{wg_instance_ref: string, label: string, available: bool}> $instances */
    public function __construct(array $instances, int $pendingChanges)
    {
        $this->instances = $instances;
        $this->pendingChanges = $pendingChanges;
    }

    public function allAvailable(): bool
    {
        foreach ($this->instances as $instance) {
            if (!$instance['available']) {
                return false;
            }
        }
        return true;
    }
}
