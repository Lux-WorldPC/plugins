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
 * Provisioner abstraction (M06). One implementation today (os-wireguard);
 * the interface exists so bare `wg`, pfSense or MikroTik become possible
 * without rewriting callers.
 *
 * Every operation is qualified by the target instance — no signature may
 * write without naming it. Implementations MUST refuse instances that are
 * not declared to the plugin (forbidden rule #3) and peers outside the
 * declared range of the target instance (last barrier against an IPAM
 * defect). Write operations stage config changes; nothing is applied until
 * commit(), which runs ONE global reconfigure for the whole batch — never
 * one per peer.
 */

namespace OPNsense\Paart\Provision;

interface PeerProvisioner
{
    /**
     * Instances available on the firewall (declared or not) — for the
     * declaration UI (M08) and availability checks. Read-only.
     *
     * @return array<int, array{uuid: string, name: string}>
     */
    public function listInstances(): array;

    /**
     * Peers currently configured on a DECLARED instance. server_refs lists
     * every firewall instance the peer is attached to — callers use it to
     * refuse writes on multi-attached peers (they are not ours alone).
     *
     * @return array<int, array{uuid: string, name: string, public_key: string,
     *                          tunnel_addresses: array<int, string>,
     *                          server_refs: array<int, string>}>
     * @throws ProvisionException INSTANCE_NOT_DECLARED | INSTANCE_UNAVAILABLE.
     */
    public function listPeers(string $instanceRef): array;

    /**
     * Create one peer. Idempotent: replaying with an identical spec is a
     * no-op; the same key with a DIFFERENT address is refused (signalled,
     * never silently corrected).
     *
     * @throws ProvisionException INSTANCE_NOT_DECLARED | INSTANCE_UNAVAILABLE |
     *         PROVISIONING_UNAVAILABLE | INTERNAL.
     */
    public function createPeer(string $instanceRef, PeerSpec $spec): void;

    /**
     * Atomically swap a peer's key: the entry matched by $oldPubKey is
     * rewritten to $spec in one config write (same address — rotation M05).
     * Idempotent: replaying after success (old key gone, new spec present)
     * is a no-op.
     *
     * @throws ProvisionException same codes as createPeer.
     */
    public function replacePeer(string $instanceRef, string $oldPubKey, PeerSpec $spec): void;

    /**
     * Delete the peer matched by $publicKey — the caller's explicit intent
     * (forbidden rule #4). Idempotent: an absent key is a no-op. A peer
     * whose address lies outside the declared range is NEVER deleted, even
     * on key match: it is not ours.
     *
     * @return bool true when a peer was actually staged for deletion,
     *         false when the key was already absent (deletion replayed, or
     *         the peer removed outside the plugin). Callers that report a
     *         count to an administrator MUST count this, not the number of
     *         devices they targeted: the two differ under drift, and the
     *         same difference tells whether commit() will reconfigure at
     *         all — hence whether config.xml was rewritten from another
     *         process (see NetworksController::delNetworkAction).
     * @throws ProvisionException same codes as createPeer.
     */
    public function deletePeer(string $instanceRef, string $publicKey): bool;

    /**
     * Apply all staged changes with ONE global reconfigure. No-op when
     * nothing is staged. @throws ProvisionException PROVISIONING_UNAVAILABLE.
     */
    public function commit(): void;

    /**
     * Availability snapshot of every DECLARED instance plus the count of
     * staged-but-uncommitted changes. Read-only, never throws on an
     * unavailable instance — that is exactly what it reports.
     */
    public function healthCheck(): ProvisionerHealth;
}
