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
 * Thin transport over the os-wireguard API (M06). Methods mirror the
 * endpoints verified in the V3 campaign one to one (see
 * docs/verifications/2026-08-22-campagne-v1-v3.md); NO business rules
 * here — guards, idempotence and batching all live in OpnsenseProvisioner,
 * so tests exercise them against a fake gateway.
 *
 * Implementations throw ProvisionException on transport failure —
 * PROVISIONING_UNAVAILABLE when the request provably never took effect,
 * INTERNAL when the effect is unknown (see HttpWireguardGateway) —
 * and return decoded payloads verbatim otherwise —
 * except getServer, which returns a narrow projection (its raw response
 * carries the server's PRIVATE key; see the method). Response shapes come
 * from the controller sources read in V3 and were validated live in the
 * V2/V3 window.
 */

namespace OPNsense\Paart\Provision;

interface WireguardGateway
{
    /**
     * Servers (instances) present on the firewall.
     * @return array<int, array{uuid: string, name: string}>
     */
    public function listServers(): array;

    /**
     * One server's facts for bundle assembly (M04), as a NARROW projection:
     * the raw getServer response also serves the server's PRIVATE key,
     * which must never leave the gateway (forbidden rule #1) — so
     * implementations extract these fields and discard everything else,
     * this method never returning the payload verbatim. Selection-map
     * fields (tunneladdress) are flattened to their selected values; ''
     * scalars become null. Shape verified live on the bench.
     *
     * @return array{name: string, public_key: string, port: ?int,
     *               mtu: ?int, tunnel_addresses: array<int, string>}
     */
    public function getServer(string $serverUuid): array;

    /**
     * Raw searchClient rows for one server uuid — each row carries at least
     * uuid, name, pubkey, tunneladdress (comma-separated), servers.
     * @return array<int, array<string, mixed>>
     */
    public function searchClients(string $serverUuid): array;

    /**
     * @param array<string, string> $client os-wireguard client payload.
     * @return array<string, mixed> decoded response: result 'saved' (+ the
     *         created 'uuid') on success, anything else is a failure.
     */
    public function addClient(array $client): array;

    /**
     * @param array<string, string> $client FULL replacement payload — fields
     *        left out are cleared, attachments not listed in 'servers' drop.
     * @return array<string, mixed> decoded response: result 'saved' on
     *         success, anything else is a failure.
     */
    public function setClient(string $uuid, array $client): array;

    /**
     * @return array<string, mixed> decoded response: result 'deleted' on
     *         success, anything else is a failure.
     */
    public function delClient(string $uuid): array;

    /**
     * Global service reconfigure — applies every staged config change.
     * @return array<string, mixed> decoded response: status 'ok' on success;
     *         callers must treat any other shape as NOT applied (fail closed).
     */
    public function reconfigure(): array;

    /** Runtime state (`service/show`): handshakes, transfer, peer status. */
    public function show(): array;
}
