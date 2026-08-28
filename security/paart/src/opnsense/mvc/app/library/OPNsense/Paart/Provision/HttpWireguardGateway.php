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
 * WireguardGateway over the OPNsense HTTP API (key/secret basic auth).
 * Targets the local API in production (https://127.0.0.1) and the test
 * firewall during development (.env). Read AND write endpoints were
 * verified live on the target firewall (V3 campaign, then the V2/V3 write
 * window — full create/replace/delete/reconfigure cycle; results in
 * docs/verifications/). reconfigure returns {"result":"ok"} on success.
 *
 * Transport only: no business rules, no retries, no state. Failures split
 * by what can be said about the resulting state: when the request provably
 * never took effect (connection refused, TLS, HTTP >= 400) they become
 * PROVISIONING_UNAVAILABLE, which by contract means "nothing was changed";
 * when the effect is unknown (timeout after the request may have gone out,
 * non-JSON body from an endpoint that accepted the request) they become
 * INTERNAL, whose registry entry requires the message to state exactly
 * that — and which HttpError projects as not retryable, so no client
 * auto-retries an operation whose effect is unknown.
 */

namespace OPNsense\Paart\Provision;

final class HttpWireguardGateway implements WireguardGateway
{
    /**
     * Seconds before a hung API call fails the operation. Chosen far above
     * the measured worst case (global reconfigure ~0.9 s, V2 window) while
     * still failing a hung configd before the admin gives up on the UI.
     */
    private const TIMEOUT_S = 15;

    private string $baseUrl;
    private string $apiKey;
    private string $apiSecret;
    private bool $verifyTls;

    /** @param bool $verifyTls disable ONLY toward 127.0.0.1 / lab targets. */
    public function __construct(string $baseUrl, string $apiKey, string $apiSecret, bool $verifyTls = true)
    {
        $this->baseUrl = \rtrim($baseUrl, '/');
        $this->apiKey = $apiKey;
        $this->apiSecret = $apiSecret;
        $this->verifyTls = $verifyTls;
    }

    public function listServers(): array
    {
        $response = $this->call('GET', '/api/wireguard/client/listServers');
        $out = [];
        // The measured target returns 'rows'; 'servers' is tolerated in case
        // another os-wireguard build names the collection after the entity.
        foreach (($response['rows'] ?? $response['servers'] ?? []) as $row) {
            $out[] = ['uuid' => (string)$row['uuid'], 'name' => (string)$row['name']];
        }
        return $out;
    }

    public function getServer(string $serverUuid): array
    {
        $row = $this->call('GET', '/api/wireguard/server/getServer/' . \rawurlencode($serverUuid));
        $row = \is_array($row['server'] ?? null) ? $row['server'] : [];
        // Selection-map fields ({key: {value, selected}}) carry the chosen
        // entries under their keys; scalars come as strings, '' when unset.
        // The raw row also serves 'privkey': it is dropped right here and
        // never propagated, logged or stored (forbidden rule #1).
        $addresses = [];
        foreach ((array)($row['tunneladdress'] ?? []) as $cidr => $option) {
            if (!empty($option['selected'])) {
                $addresses[] = (string)$cidr;
            }
        }
        return [
            'name' => (string)($row['name'] ?? ''),
            'public_key' => (string)($row['pubkey'] ?? ''),
            'port' => \is_numeric($row['port'] ?? null) ? (int)$row['port'] : null,
            'mtu' => \is_numeric($row['mtu'] ?? null) ? (int)$row['mtu'] : null,
            'tunnel_addresses' => $addresses,
        ];
    }

    public function searchClients(string $serverUuid): array
    {
        $response = $this->call('POST', '/api/wireguard/client/searchClient', [
            'current' => 1,
            'rowCount' => -1,
            'servers' => [$serverUuid],
        ]);
        return $response['rows'] ?? [];
    }

    public function addClient(array $client): array
    {
        return $this->call('POST', '/api/wireguard/client/addClient', ['client' => $client]);
    }

    public function setClient(string $uuid, array $client): array
    {
        return $this->call('POST', '/api/wireguard/client/setClient/' . \rawurlencode($uuid), [
            'client' => $client,
        ]);
    }

    public function delClient(string $uuid): array
    {
        return $this->call('POST', '/api/wireguard/client/delClient/' . \rawurlencode($uuid));
    }

    public function reconfigure(): array
    {
        return $this->call('POST', '/api/wireguard/service/reconfigure');
    }

    public function show(): array
    {
        return $this->call('GET', '/api/wireguard/service/show');
    }

    /**
     * @param ?array<string, mixed> $body JSON-encoded when present.
     * @return array<string, mixed> decoded JSON response.
     * @throws ProvisionException PROVISIONING_UNAVAILABLE when the request
     *         provably never took effect (unreachable, TLS, HTTP >= 400);
     *         INTERNAL when the effect is unknown (timeout, non-JSON body).
     */
    private function call(string $method, string $path, ?array $body = null): array
    {
        $ch = \curl_init($this->baseUrl . $path);
        $headers = [];
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERPWD => $this->apiKey . ':' . $this->apiSecret,
            CURLOPT_TIMEOUT => self::TIMEOUT_S,
            CURLOPT_SSL_VERIFYPEER => $this->verifyTls,
            CURLOPT_SSL_VERIFYHOST => $this->verifyTls ? 2 : 0,
            CURLOPT_CUSTOMREQUEST => $method,
        ];
        if ($body !== null) {
            $options[CURLOPT_POSTFIELDS] = \json_encode($body, JSON_UNESCAPED_SLASHES);
            $headers[] = 'Content-Type: application/json';
        }
        if ($headers !== []) {
            $options[CURLOPT_HTTPHEADER] = $headers;
        }
        \curl_setopt_array($ch, $options);

        $raw = \curl_exec($ch);
        $errno = \curl_errno($ch);
        $error = \curl_error($ch);
        $status = (int)\curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        \curl_close($ch);

        if ($raw === false || $errno !== 0) {
            // A timeout can fire after the request went out (curl cannot say
            // which side of the wire it died on), so unlike the other curl
            // errors it cannot promise that nothing was changed.
            if ($errno === CURLE_OPERATION_TIMEDOUT) {
                throw new ProvisionException(
                    'INTERNAL',
                    "WireGuard API timed out after " . self::TIMEOUT_S . "s ($method $path). " .
                    'Whether the call took effect is unknown — check the instance state before retrying.'
                );
            }
            throw new ProvisionException(
                'PROVISIONING_UNAVAILABLE',
                "WireGuard API unreachable ($method $path): $error. Nothing was changed."
            );
        }
        if ($status >= 400) {
            throw new ProvisionException(
                'PROVISIONING_UNAVAILABLE',
                "WireGuard API error $status on $method $path. Nothing was changed."
            );
        }
        $decoded = \json_decode((string)$raw, true);
        if (!\is_array($decoded)) {
            // The endpoint accepted the request and answered garbage: the
            // call may well have taken effect, so this cannot be the
            // "nothing was changed" code (PROVISIONING_UNAVAILABLE).
            throw new ProvisionException(
                'INTERNAL',
                "WireGuard API returned a non-JSON response on $method $path. " .
                'Whether the call took effect is unknown — check the instance state before retrying.'
            );
        }
        return $decoded;
    }
}
