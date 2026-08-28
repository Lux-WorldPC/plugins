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
 * HaproxyGateway over the OPNsense HTTP API (key/secret basic auth),
 * against the local API the WireGuard gateway already uses — same
 * credentials, so the API user needs the HAProxy privileges too. The
 * os-haproxy endpoints: settings/search<Object>s, settings/{get,add,set,
 * del}<Object>,
 * settings/{get,set} for the general node, service/{status,configtest,
 * reconfigure}. Verified on the target firewall (26.1): without the
 * plugin every /api/haproxy/* call answers 404 {"errorMessage":
 * "Endpoint not found"}, which is what installed() reads.
 *
 * Transport only. Failure mapping follows HttpWireguardGateway: a request
 * that provably never took effect (unreachable, TLS, HTTP >= 400) is
 * EXPOSURE_UNAVAILABLE and says "nothing was changed"; an unknown effect
 * (timeout, non-JSON reply) is INTERNAL and says so — as is a refused
 * enableService(), the one write here with no input to fix. A 401/403
 * points at the HAProxy privilege family, the one setup mistake this
 * path can diagnose.
 */

namespace OPNsense\Paart\Exposure;

final class HttpHaproxyGateway implements HaproxyGateway
{
    /** Seconds before a hung call fails; a reconfigure normally takes < 2 s. */
    private const TIMEOUT_S = 20;

    /** collection => [endpoint object name, payload key] */
    private const OBJECTS = [
        'frontends' => ['Frontend', 'frontend'],
        'backends' => ['Backend', 'backend'],
        'servers' => ['Server', 'server'],
        'acls' => ['Acl', 'acl'],
        'actions' => ['Action', 'action'],
    ];

    private string $baseUrl;
    private string $apiKey;
    private string $apiSecret;
    private bool $verifyTls;

    /**
     * @param string $baseUrl https://host[:port] of the local API, no path.
     * @param string $apiKey API user key (System > Access > Users).
     * @param string $apiSecret its secret.
     * @param bool $verifyTls disable ONLY toward 127.0.0.1 / lab targets.
     */
    public function __construct(string $baseUrl, string $apiKey, string $apiSecret, bool $verifyTls = true)
    {
        $this->baseUrl = \rtrim($baseUrl, '/');
        $this->apiKey = $apiKey;
        $this->apiSecret = $apiSecret;
        $this->verifyTls = $verifyTls;
    }

    /** {@inheritDoc} */
    public function installed(): bool
    {
        [$status] = $this->raw('GET', '/api/haproxy/service/status');
        return $status !== 404;
    }

    /** {@inheritDoc} */
    public function search(string $collection): array
    {
        [$object] = self::object($collection);
        $payload = $this->call('POST', "/api/haproxy/settings/search{$object}s", ['current' => 1, 'rowCount' => -1]);
        $rows = $payload['rows'] ?? [];
        return \is_array($rows) ? \array_values($rows) : [];
    }

    /** {@inheritDoc} */
    public function get(string $collection, string $uuid): array
    {
        [$object, $key] = self::object($collection);
        $payload = $this->call('GET', "/api/haproxy/settings/get{$object}/" . \rawurlencode($uuid));
        $node = $payload[$key] ?? null;
        return \is_array($node) ? $node : [];
    }

    /** {@inheritDoc} */
    public function add(string $collection, array $fields): array
    {
        [$object, $key] = self::object($collection);
        return $this->call('POST', "/api/haproxy/settings/add{$object}", [$key => $fields]);
    }

    /** {@inheritDoc} */
    public function set(string $collection, string $uuid, array $fields): array
    {
        [$object, $key] = self::object($collection);
        return $this->call('POST', "/api/haproxy/settings/set{$object}/" . \rawurlencode($uuid), [$key => $fields]);
    }

    /** {@inheritDoc} */
    public function del(string $collection, string $uuid): array
    {
        [$object] = self::object($collection);
        return $this->call('POST', "/api/haproxy/settings/del{$object}/" . \rawurlencode($uuid), []);
    }

    /** {@inheritDoc} */
    public function serviceEnabled(): bool
    {
        $payload = $this->call('GET', '/api/haproxy/settings/get');
        return (string)($payload['haproxy']['general']['enabled'] ?? '0') === '1';
    }

    /** {@inheritDoc} */
    public function enableService(): void
    {
        $payload = $this->call('POST', '/api/haproxy/settings/set', ['haproxy' => ['general' => ['enabled' => '1']]]);
        if (($payload['result'] ?? '') !== 'saved') {
            throw new ExposureException(
                'INTERNAL',
                'HAProxy refused to enable its service: ' . \json_encode($payload['validations'] ?? $payload) .
                '. The service stays as it was; nothing else was changed by this call.'
            );
        }
    }

    /** {@inheritDoc} */
    public function serviceStatus(): string
    {
        $payload = $this->call('GET', '/api/haproxy/service/status');
        return (string)($payload['status'] ?? 'unknown');
    }

    /** {@inheritDoc} */
    public function configtest(): string
    {
        $payload = $this->call('POST', '/api/haproxy/service/configtest', []);
        return (string)($payload['result'] ?? '');
    }

    /** {@inheritDoc} */
    public function reconfigure(): string
    {
        $payload = $this->call('POST', '/api/haproxy/service/reconfigure', []);
        return (string)($payload['status'] ?? 'failed');
    }

    /**
     * @return array{0: string, 1: string} endpoint object name, payload key.
     * @throws \InvalidArgumentException on a collection outside OBJECTS — a
     *         programming error (the service names its collections), never an input.
     */
    private static function object(string $collection): array
    {
        if (!isset(self::OBJECTS[$collection])) {
            throw new \InvalidArgumentException("Unknown HAProxy collection '$collection'.");
        }
        return self::OBJECTS[$collection];
    }

    /**
     * One decoded API call.
     *
     * @param ?array<string, mixed> $body JSON-encoded when present.
     * @return array<string, mixed>
     * @throws ExposureException EXPOSURE_UNAVAILABLE (unreachable, TLS,
     *         HTTP >= 400 — 404 meaning "plugin absent", 403 "privileges");
     *         INTERNAL (timeout, non-JSON).
     */
    private function call(string $method, string $path, ?array $body = null): array
    {
        [$status, $raw] = $this->raw($method, $path, $body);
        if ($status === 404) {
            throw new ExposureException(
                'EXPOSURE_UNAVAILABLE',
                'The os-haproxy plugin is not installed on this firewall, so no exposure can be managed. ' .
                'Nothing was changed by this call. Install it from System > Firmware > Plugins, or keep enrollment internal-only.'
            );
        }
        if ($status === 401 || $status === 403) {
            throw new ExposureException(
                'EXPOSURE_UNAVAILABLE',
                "HAProxy API refused the plugin's API user ($status on $method $path). Nothing was changed by this call. " .
                'Grant that user the HAProxy privileges (System > Access > Users), the same key manages WireGuard.'
            );
        }
        if ($status >= 400) {
            throw new ExposureException(
                'EXPOSURE_UNAVAILABLE',
                "HAProxy API error $status on $method $path. Nothing was changed by this call."
            );
        }
        $decoded = \json_decode((string)$raw, true);
        if (!\is_array($decoded)) {
            throw new ExposureException(
                'INTERNAL',
                "HAProxy API returned a non-JSON response on $method $path. " .
                'Whether the call took effect is unknown — check Services > HAProxy before retrying.'
            );
        }
        return $decoded;
    }

    /**
     * Raw transport: status and body, with only the curl-level failures
     * mapped (they say nothing about the API's answer).
     *
     * @param ?array<string, mixed> $body
     * @return array{0: int, 1: string}
     * @throws ExposureException INTERNAL on a timeout (effect unknown),
     *         EXPOSURE_UNAVAILABLE on any other curl failure.
     */
    private function raw(string $method, string $path, ?array $body = null): array
    {
        $ch = \curl_init($this->baseUrl . $path);
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
            $options[CURLOPT_HTTPHEADER] = ['Content-Type: application/json'];
        }
        \curl_setopt_array($ch, $options);
        $raw = \curl_exec($ch);
        $errno = \curl_errno($ch);
        $error = \curl_error($ch);
        $status = (int)\curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        \curl_close($ch);

        if ($raw === false || $errno !== 0) {
            if ($errno === CURLE_OPERATION_TIMEDOUT) {
                throw new ExposureException(
                    'INTERNAL',
                    'HAProxy API timed out after ' . self::TIMEOUT_S . "s ($method $path). " .
                    'Whether the call took effect is unknown — check Services > HAProxy before retrying.'
                );
            }
            throw new ExposureException(
                'EXPOSURE_UNAVAILABLE',
                "HAProxy API unreachable ($method $path): $error. Nothing was changed by this call."
            );
        }
        return [$status, (string)$raw];
    }
}
