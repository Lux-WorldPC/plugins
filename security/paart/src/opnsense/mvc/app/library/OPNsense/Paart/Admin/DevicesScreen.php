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
 * Read-only projections for the M08 Devices screen — OFF-contract screen
 * plumbing, not /admin/* operations. Rows start from AdminService's
 * contract device payloads (so the recetted shapes stay the single
 * source), then add what the grid displays: user and network names from
 * the store, and the live tunnel state (handshake age, peer status) read
 * from the firewall's runtime view (`service/show`, V3-verified shapes).
 *
 * Live rows are matched by (instance name, public key) — never by peer
 * name (forbidden rule #5); the instance name comes from listServers()
 * keyed by the declared wg_instance_ref, so undeclared instances are
 * never consulted. An unreachable firewall degrades, never fails: the
 * grid then carries store data only and says so (live=false).
 *
 * This class NEVER writes — screen writes go through the recetted
 * /api/paart/admin/* contract routes.
 */

namespace OPNsense\Paart\Admin;

use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Provision\ProvisionException;
use OPNsense\Paart\Provision\WireguardGateway;
use OPNsense\Paart\Store\Database;

final class DevicesScreen
{
    private AdminService $admin;
    private Database $db;
    private WireguardGateway $gateway;

    public function __construct(AdminService $admin, Database $db, WireguardGateway $gateway)
    {
        $this->admin = $admin;
        $this->db = $db;
        $this->gateway = $gateway;
    }

    /**
     * Declared instances for the grid's network filter, lightest possible
     * read (no reachability probe, unlike AdminService::health()).
     *
     * @return array{instances: array<int, array{id: string, label: string}>}
     */
    public function instances(): array
    {
        $out = [];
        foreach ($this->db->query('SELECT id, label FROM instances ORDER BY label') as $row) {
            $out[] = ['id' => (string)$row['id'], 'label' => (string)$row['label']];
        }
        return ['instances' => $out];
    }

    /**
     * Grid rows: contract device payloads + user_slug / user_display_name /
     * instance_label + live handshake_age (seconds) and peer_status
     * (online|stale|offline). Live fields are null for a device without a
     * runtime peer (revoked, or pending enrollment) and for every device
     * when the firewall is unreachable — each row also repeats the global
     * 'live' flag so the grid formatters can label an Active row honestly
     * ("Active, live state unknown" vs "Inactive").
     *
     * @param ?string $instanceId filter on one declared instance (ULID).
     * @param ?string $q case-insensitive substring over device label,
     *                   user name, user slug and IP address.
     * @return array{devices: array<int, array<string, mixed>>, live: bool}
     */
    public function rows(?string $instanceId = null, ?string $q = null): array
    {
        $devices = $this->admin->listDevices(null, $instanceId, null)['devices'];

        $users = [];
        foreach ($this->db->query('SELECT id, slug, display_name FROM users') as $row) {
            $users[(string)$row['id']] = $row;
        }
        $instances = [];
        foreach ($this->db->query('SELECT id, label, wg_instance_ref FROM instances') as $row) {
            $instances[(string)$row['id']] = $row;
        }
        // The contract payload carries only a fingerprint; live matching
        // needs the full public key, which stays server-side here.
        $pubkeys = [];
        foreach ($this->db->query('SELECT id, public_key FROM devices') as $row) {
            $pubkeys[(string)$row['id']] = (string)$row['public_key'];
        }

        $runtime = $this->runtime();

        foreach ($devices as $i => $device) {
            $user = $users[(string)$device['user_id']] ?? null;
            $instance = $instances[(string)$device['instance_id']] ?? null;
            $device['user_slug'] = $user !== null ? (string)$user['slug'] : '';
            $device['user_display_name'] = $user !== null ? (string)$user['display_name'] : '';
            $device['instance_label'] = $instance !== null ? (string)$instance['label'] : '';

            $device['live'] = $runtime !== null;
            $device['handshake_age'] = null;
            $device['peer_status'] = null;
            if ($runtime !== null && $instance !== null) {
                $serverName = $runtime['names'][(string)$instance['wg_instance_ref']] ?? null;
                $peer = $serverName !== null
                    ? ($runtime['peers'][$serverName . '|' . ($pubkeys[(string)$device['id']] ?? '')] ?? null)
                    : null;
                if ($peer !== null) {
                    $age = $peer['latest-handshake-age'] ?? null;
                    $device['handshake_age'] = \is_numeric($age) ? (int)$age : null;
                    $status = $peer['peer-status'] ?? null;
                    $device['peer_status'] = \is_string($status) && $status !== '' ? $status : null;
                }
            }
            $devices[$i] = $device;
        }

        if ($q !== null && $q !== '') {
            $devices = \array_values(\array_filter(
                $devices,
                fn(array $d): bool => \stripos(
                    $d['label'] . ' ' . $d['user_display_name'] . ' ' . $d['user_slug']
                        . ' ' . ($d['ip_address'] ?? ''),
                    $q
                ) !== false
            ));
        }

        return ['devices' => $devices, 'live' => $runtime !== null];
    }

    /**
     * The folded "Technical details" of one device: full public key
     * (store), peer name (firewall config, matched by public key) and last
     * endpoint (runtime). Config/runtime fields are null when the peer no
     * longer exists (revoked) or when the firewall is unreachable
     * (then live=false).
     *
     * @param string $id device ULID.
     * @return array{technical: array{public_key: string, peer_name: ?string,
     *               last_endpoint: ?string}, live: bool}
     * @throws DomainException NOT_FOUND.
     */
    public function detail(string $id): array
    {
        $rows = $this->db->query(
            'SELECT d.public_key, i.wg_instance_ref
               FROM devices d JOIN instances i ON i.id = d.instance_id
              WHERE d.id = :id',
            [':id' => $id]
        );
        if ($rows === []) {
            throw new DomainException('NOT_FOUND', "Device '$id' does not exist.");
        }
        $publicKey = (string)$rows[0]['public_key'];
        $wgRef = (string)$rows[0]['wg_instance_ref'];

        $peerName = null;
        $endpoint = null;
        $live = false;
        try {
            foreach ($this->gateway->searchClients($wgRef) as $client) {
                if ((string)($client['pubkey'] ?? '') === $publicKey) {
                    $peerName = (string)$client['name'];
                    break;
                }
            }
            $runtime = $this->liveRuntime();
            $serverName = $runtime['names'][$wgRef] ?? null;
            if ($serverName !== null) {
                $peer = $runtime['peers'][$serverName . '|' . $publicKey] ?? null;
                $value = $peer['endpoint'] ?? null;
                // The runtime view reports "(none)" for a peer that never
                // connected; the screen wants an honest null instead.
                if (\is_string($value) && $value !== '' && $value !== '(none)') {
                    $endpoint = $value;
                }
            }
            $live = true;
        } catch (ProvisionException $e) {
            $peerName = null;
            $endpoint = null;
        }

        return [
            'technical' => [
                'public_key' => $publicKey,
                'peer_name' => $peerName,
                'last_endpoint' => $endpoint,
            ],
            'live' => $live,
        ];
    }

    // -------------------------------------------------------------- helpers

    /** liveRuntime(), degraded to null when the firewall is unreachable. */
    private function runtime(): ?array
    {
        try {
            return $this->liveRuntime();
        } catch (ProvisionException $e) {
            return null;
        }
    }

    /**
     * One snapshot of the firewall's view: server names keyed by uuid
     * (wg_instance_ref) and runtime peer rows keyed by
     * "<instance name>|<public key>" — `service/show` names its rows by
     * instance NAME (ifname), while the store declares instances by uuid.
     * A duplicate (name, key) pair keeps the last row; the schema's
     * UNIQUE (instance_id, public_key) makes that a non-case for managed
     * peers.
     *
     * @return array{names: array<string, string>,
     *               peers: array<string, array<string, mixed>>}
     * @throws ProvisionException PROVISIONING_UNAVAILABLE.
     */
    private function liveRuntime(): array
    {
        $names = [];
        foreach ($this->gateway->listServers() as $server) {
            $names[(string)$server['uuid']] = (string)$server['name'];
        }
        $peers = [];
        foreach ((array)($this->gateway->show()['rows'] ?? []) as $row) {
            if (($row['type'] ?? '') !== 'peer') {
                continue;
            }
            $peers[(string)($row['ifname'] ?? '') . '|' . (string)($row['public-key'] ?? '')] = $row;
        }
        return ['names' => $names, 'peers' => $peers];
    }
}
