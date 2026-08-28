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
 * os-wireguard implementation of the provisioner (M06).
 *
 * Guards enforced on every operation, reads included — the one deliberate
 * exception is listInstances(), which must see undeclared instances to feed
 * the declaration UI (M08) and therefore applies no guard:
 *  - the target must be a DECLARED instance (forbidden rule #3): refusal is
 *    INSTANCE_NOT_DECLARED, audited — it is always a bug or a stale reference;
 *  - a declared instance missing from the firewall is INSTANCE_UNAVAILABLE;
 *    other declared instances keep working (the check is per-instance);
 *  - a write outside the declared range of the target instance is refused
 *    and audited (last barrier against an IPAM defect), and a live peer
 *    outside that range is never modified nor deleted — it is not ours;
 *  - a live peer attached to any OTHER firewall instance is never modified
 *    nor deleted either: plugin-managed peers are single-instance by
 *    construction (one device = one instance, M02 schema), and setClient is
 *    a full replacement that would silently drop other attachments.
 *
 * Idempotence: searchClient before every write, matching on the PUBLIC KEY
 * only (forbidden rule #5). Replays are no-ops; divergences are signalled
 * (INTERNAL), never silently corrected.
 *
 * Batching: add/set/del stage config changes; commit() runs ONE global
 * reconfigure (measured V3: reconfigure has no per-instance scope). Measured
 * V2: the global reload took ~0.9 s and dropped no packets on a live client
 * tunnel of the written instance (docs/verifications/); batching stays the
 * rule — one reconfigure per batch, never per peer.
 *
 * The firewall server list is cached for the write-path availability checks
 * (fetched once per object, refreshed once on a negative hit before
 * failing); listInstances() and healthCheck() are diagnostic views and
 * always fetch fresh state instead of serving the cache.
 */

namespace OPNsense\Paart\Provision;

use OPNsense\Paart\Domain\AuditTrail;
use OPNsense\Paart\Domain\Instances;
use OPNsense\Paart\Store\Database;

final class OpnsenseProvisioner implements PeerProvisioner
{
    private Database $db;
    private WireguardGateway $gateway;
    private AuditTrail $audit;
    private int $pendingChanges = 0;
    /** @var ?array<string, string> firewall server uuid => name (lazy cache). */
    private ?array $servers = null;

    public function __construct(Database $db, WireguardGateway $gateway, AuditTrail $audit)
    {
        $this->db = $db;
        $this->gateway = $gateway;
        $this->audit = $audit;
    }

    /**
     * {@inheritDoc}
     *
     * Deliberately unguarded (the one exception, see the header): the
     * declaration UI must see undeclared instances. Always fetches fresh
     * state, bypassing the write-path cache.
     */
    public function listInstances(): array
    {
        $out = [];
        foreach ($this->serverMap(true) as $uuid => $name) {
            $out[] = ['uuid' => $uuid, 'name' => $name];
        }
        return $out;
    }

    /**
     * {@inheritDoc}
     *
     * Rows are normalized from searchClient (V3 shapes): comma-separated
     * 'tunneladdress' / 'servers' become the tunnel_addresses / server_refs
     * lists.
     */
    public function listPeers(string $instanceRef): array
    {
        $this->declared($instanceRef);
        $this->assertAvailable($instanceRef);
        $peers = [];
        foreach ($this->gateway->searchClients($instanceRef) as $row) {
            $peers[] = [
                'uuid' => (string)$row['uuid'],
                'name' => (string)$row['name'],
                'public_key' => (string)$row['pubkey'],
                'tunnel_addresses' => \array_values(\array_filter(\array_map(
                    'trim',
                    \explode(',', (string)$row['tunneladdress'])
                ))),
                'server_refs' => \array_values(\array_filter(\array_map(
                    'trim',
                    \explode(',', (string)$row['servers'])
                ))),
            ];
        }
        return $peers;
    }

    /**
     * {@inheritDoc}
     *
     * One addClient POST (V3: the controller syncs the server's peer list
     * itself); staged until commit().
     */
    public function createPeer(string $instanceRef, PeerSpec $spec): void
    {
        $instance = $this->declared($instanceRef);
        $this->assertAvailable($instanceRef);
        $this->assertInRange($instance, $spec->address);

        $existing = $this->findByKey($instanceRef, $spec->publicKey);
        if ($existing !== null) {
            if (\in_array($spec->tunnelAddress(), $existing['tunnel_addresses'], true)) {
                return; // replay of an applied create: nothing to do
            }
            $this->refuse(
                $instance,
                'INTERNAL',
                "Peer '{$this->key8($spec->publicKey)}' already exists on " .
                "'{$instance['label']}' with address(es) " .
                \implode(',', $existing['tunnel_addresses']) .
                " instead of {$spec->tunnelAddress()}. Conflict signalled, nothing changed."
            );
        }

        $response = $this->gateway->addClient($this->payload($instanceRef, $spec));
        $this->assertSaved($response, "creating peer on '{$instance['label']}'");
        $this->pendingChanges++;
    }

    /**
     * {@inheritDoc}
     *
     * setClient on the entry matched by $oldPubKey — a full replacement,
     * which assertManagedPeer() makes safe (single-instance peers only).
     */
    public function replacePeer(string $instanceRef, string $oldPubKey, PeerSpec $spec): void
    {
        $instance = $this->declared($instanceRef);
        $this->assertAvailable($instanceRef);
        $this->assertInRange($instance, $spec->address);

        $old = $this->findByKey($instanceRef, $oldPubKey);
        if ($old === null) {
            $new = $this->findByKey($instanceRef, $spec->publicKey);
            if ($new !== null && \in_array($spec->tunnelAddress(), $new['tunnel_addresses'], true)) {
                return; // replay of an applied swap: nothing to do
            }
            $this->refuse(
                $instance,
                'INTERNAL',
                "Peer to replace ('{$this->key8($oldPubKey)}') is missing on " .
                "'{$instance['label']}' — drift to reconcile, nothing changed."
            );
        }
        $this->assertManagedPeer($instance, $old, 'replace');

        $response = $this->gateway->setClient($old['uuid'], $this->payload($instanceRef, $spec));
        $this->assertSaved($response, "replacing peer on '{$instance['label']}'");
        $this->pendingChanges++;
    }

    /**
     * {@inheritDoc}
     *
     * delClient cleans the server-side peer references itself (V3) —
     * deletion is one call, staged until commit().
     */
    public function deletePeer(string $instanceRef, string $publicKey): bool
    {
        $instance = $this->declared($instanceRef);
        $this->assertAvailable($instanceRef);

        $peer = $this->findByKey($instanceRef, $publicKey);
        if ($peer === null) {
            return false; // already absent: deletion replayed or drifted, nothing to do
        }
        $this->assertManagedPeer($instance, $peer, 'delete');

        $response = $this->gateway->delClient($peer['uuid']);
        if (($response['result'] ?? '') !== 'deleted') {
            throw new ProvisionException(
                'PROVISIONING_UNAVAILABLE',
                "Deleting peer on '{$instance['label']}' failed: " . \json_encode($response) .
                '. The peer was NOT removed.'
            );
        }
        $this->pendingChanges++;
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * Fail-closed: only the explicit success shape clears the batch (see
     * inline note on the measured response).
     */
    public function commit(): void
    {
        if ($this->pendingChanges === 0) {
            return;
        }
        $response = $this->gateway->reconfigure();
        // Fail closed on the applied-or-not question: only the explicit success
        // shape clears the batch; any unknown response is treated as NOT applied.
        // Measured V2 (2026-08-22): the controller returns {"result":"ok"} on
        // success and {"result":"failed"} otherwise — it does not itself check
        // the configd outcome, so this is a weak confirmation, hence fail-closed.
        if (\strtolower((string)($response['result'] ?? '')) !== 'ok') {
            throw new ProvisionException(
                'PROVISIONING_UNAVAILABLE',
                'WireGuard reconfigure did not confirm success (' .
                \json_encode($response) . '); staged changes are in the config ' .
                'but must be treated as NOT applied. Retry commit().'
            );
        }
        $this->pendingChanges = 0;
    }

    /** {@inheritDoc} Always fetches a fresh server list (diagnostic view). */
    public function healthCheck(): ProvisionerHealth
    {
        $servers = $this->serverMap(true);
        $entries = [];
        foreach ($this->db->query('SELECT wg_instance_ref, label FROM instances') as $row) {
            $entries[] = [
                'wg_instance_ref' => $row['wg_instance_ref'],
                'label' => $row['label'],
                'available' => isset($servers[$row['wg_instance_ref']]),
            ];
        }
        return new ProvisionerHealth($entries, $this->pendingChanges);
    }

    /**
     * @return array<string, mixed> instances row.
     * @throws ProvisionException INSTANCE_NOT_DECLARED (audited).
     */
    private function declared(string $instanceRef): array
    {
        $rows = $this->db->query(
            'SELECT * FROM instances WHERE wg_instance_ref = :ref',
            [':ref' => $instanceRef]
        );
        if ($rows === []) {
            $this->audit->record(
                'system',
                'provisioner',
                'provision.refused',
                'instance',
                $instanceRef,
                'failure',
                ['reason' => 'not declared']
            );
            throw new ProvisionException(
                'INSTANCE_NOT_DECLARED',
                "Instance '$instanceRef' is not declared to the plugin; refusing to touch it. " .
                'Nothing was changed.'
            );
        }
        return $rows[0];
    }

    /** @throws ProvisionException INSTANCE_UNAVAILABLE after one cache refresh. */
    private function assertAvailable(string $instanceRef): void
    {
        if (isset($this->serverMap(false)[$instanceRef]) || isset($this->serverMap(true)[$instanceRef])) {
            return;
        }
        throw new ProvisionException(
            'INSTANCE_UNAVAILABLE',
            "Declared instance '$instanceRef' no longer exists on the firewall. " .
            'Operations on it are refused; other declared instances keep working.'
        );
    }

    /**
     * Last barrier: the address must lie inside the usable hosts of the
     * instance's declared range. @throws ProvisionException INTERNAL (audited).
     */
    private function assertInRange(array $instance, string $address): void
    {
        $range = Instances::parseCidr($instance['ip_range_cidr']);
        $ip = \ip2long($address) & 0xFFFFFFFF;
        if ($ip <= $range['network'] || $ip >= $range['broadcast']) {
            $this->refuse(
                $instance,
                'INTERNAL',
                "Address $address is outside the declared range " .
                "{$instance['ip_range_cidr']} of '{$instance['label']}'. " .
                'IPAM defect suspected; write refused, nothing changed.'
            );
        }
    }

    /**
     * A live peer is only ours to touch when every one of its addresses is
     * inside the declared range AND it is attached to the target instance
     * only — plugin peers are single-instance by construction, and a write
     * (full replacement) would drop any other attachment.
     * @throws ProvisionException INTERNAL (audited).
     */
    private function assertManagedPeer(array $instance, array $peer, string $verb): void
    {
        $others = \array_diff($peer['server_refs'], [$instance['wg_instance_ref']]);
        if ($others !== []) {
            $this->refuse(
                $instance,
                'INTERNAL',
                "Refusing to $verb peer '{$peer['name']}' on '{$instance['label']}': " .
                'it is also attached to other firewall instance(s) — pre-existing ' .
                'peer, not managed by the plugin. Nothing changed.'
            );
        }
        $range = Instances::parseCidr($instance['ip_range_cidr']);
        foreach ($peer['tunnel_addresses'] as $cidr) {
            $ip = \ip2long((string)\strtok($cidr, '/')) & 0xFFFFFFFF;
            if ($ip <= $range['network'] || $ip >= $range['broadcast']) {
                $this->refuse(
                    $instance,
                    'INTERNAL',
                    "Refusing to $verb peer '{$peer['name']}' on '{$instance['label']}': " .
                    "address $cidr is outside the declared range — pre-existing peer, " .
                    'not managed by the plugin. Nothing changed.'
                );
            }
        }
    }

    /** Audit a refusal, then throw it. */
    private function refuse(array $instance, string $code, string $message): never
    {
        $this->audit->record(
            'system',
            'provisioner',
            'provision.refused',
            'instance',
            $instance['wg_instance_ref'],
            'failure',
            ['reason' => $message]
        );
        throw new ProvisionException($code, $message);
    }

    /** @return ?array{uuid: string, name: string, public_key: string, tunnel_addresses: array<int, string>, server_refs: array<int, string>} */
    private function findByKey(string $instanceRef, string $publicKey): ?array
    {
        foreach ($this->listPeers($instanceRef) as $peer) {
            if ($peer['public_key'] === $publicKey) {
                return $peer;
            }
        }
        return null;
    }

    /**
     * os-wireguard client payload for $spec. 'servers' takes a comma-separated
     * uuid list (V3); we always send exactly ONE — a plugin peer belongs to a
     * single instance (one device = one instance, M02 schema), which is what
     * makes setClient's full-replacement semantics safe on peers we manage.
     * @return array<string, string>
     */
    private function payload(string $instanceRef, PeerSpec $spec): array
    {
        return [
            'enabled' => '1',
            'name' => $spec->name,
            'pubkey' => $spec->publicKey,
            'tunneladdress' => $spec->tunnelAddress(),
            'servers' => $instanceRef,
        ];
    }

    /** @throws ProvisionException PROVISIONING_UNAVAILABLE unless result=saved. */
    private function assertSaved(array $response, string $doing): void
    {
        if (($response['result'] ?? '') !== 'saved') {
            throw new ProvisionException(
                'PROVISIONING_UNAVAILABLE',
                \ucfirst($doing) . ' failed: ' . \json_encode($response) .
                '. Nothing was applied; the operation may be retried.'
            );
        }
    }

    /** @return array<string, string> uuid => name. */
    private function serverMap(bool $refresh): array
    {
        if ($this->servers === null || $refresh) {
            $map = [];
            foreach ($this->gateway->listServers() as $server) {
                $map[(string)$server['uuid']] = (string)$server['name'];
            }
            $this->servers = $map;
        }
        return $this->servers;
    }

    /** Short key prefix for messages — never log a full key needlessly. */
    private function key8(string $publicKey): string
    {
        return \substr($publicKey, 0, 8) . '…';
    }
}
