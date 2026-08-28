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
 * Bundle assembly (M04): builds the EnrollResponse payload — everything an
 * enrolled device needs, never any private key (D4), never any preshared
 * key (ADR 0002). The HTTP layer prefetches the target instance's server
 * facts BEFORE EnrollmentService acts (serverForToken): a firewall that is
 * unreachable right now refuses retryable with nothing consumed, instead
 * of stranding a completed enrollment whose config can no longer be
 * assembled. Assembly itself (response/forDevice) is store reads plus
 * those prefetched facts — no gateway call left on the success path.
 *
 * Site identity (D1: one install = one site): site.label arrives resolved
 * from the settings (siteLabel with hostname fallback — Paart::libSettings());
 * site.id is a ULID minted once into the store's meta table on first use —
 * machine identity is operational data, so it lives in the store, never in
 * config.xml (M02 separation). site.instance_url is the in-tunnel control
 * plane (ADR 0003): the instance's own tunnel address on the web GUI port
 * INCLUDING this plugin's API prefix, so a client appends `/device/bundle`
 * and needs to know nothing about how OPNsense routes (the public paths of
 * M09 are rewritten by the frontend; in-tunnel there is no frontend, and
 * the GUI serves the plugin's own routes),
 * and site.pin_sha256 pins THAT certificate — the web GUI's, not the public
 * enrollment endpoint's, which is a different certificate on a different
 * host (the enrollment link's `fp=` carries the latter). A client with no
 * pin has nothing to validate an in-tunnel address with, so an unset
 * control-plane pin publishes an empty list and the device refuses the
 * control plane rather than skipping validation (M12, spec 12).
 * Last of the block, and of a different nature: site.managed_devices is a
 * COUNT, not an identity — how many devices this site manages right now.
 * It is here because the device surface is four in-tunnel routes and an app
 * holds no admin credentials, so the bundle it already polls is the only
 * place it can read one (ADR 0019, D22). The plugin publishes the number
 * and stops there: it reads no licence and issues no verdict (ADR 0018,
 * D16; forbidden rule #10).
 * And beside the count, of the same nature: site.site_key is the site key
 * the administrator typed into the settings, republished verbatim. The key
 * is bought per FIREWALL, so it belongs on the firewall — asking every
 * employee to retype 230 characters for a licence they did not buy was the
 * decision that lived two hours (ADR 0024 replacing ADR 0023). The bundle
 * an enrolled device already polls is the only in-tunnel surface that can
 * carry it.
 *
 * This plugin CARRIES it and never reads it, and the line is meant to be
 * checkable by reading the code: nothing here base64-decodes a segment,
 * verifies an Ed25519 signature, or names a field the token carries. A
 * string goes in, the same string comes out (ADR 0024, D38; forbidden rule
 * #10, which gained that frontier rather than losing it). Omitted when
 * unset, so "this server has no key" and "this server predates the field"
 * reach the client as the same thing — which they are.
 */

namespace OPNsense\Paart\Enroll;

use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Provision\WireguardGateway;
use OPNsense\Paart\Store\Database;
use OPNsense\Paart\Support\Ulid;

final class Bundles
{
    /** Pushed in every bundle: the WireGuard convention keeping NATed tunnels alive. */
    public const PERSISTENT_KEEPALIVE_S = 25;
    /** Frozen at 1 for the whole /api/v1 lifetime (COMPATIBILITY.md). */
    public const SCHEMA_VERSION = 1;
    /**
     * API prefix of this plugin's own routes, appended to site.instance_url
     * so the device surface is reachable at `<instance_url>/device/…`. The
     * public enrollment paths carry `/api/v1` because the M09 frontend
     * rewrites them; nothing rewrites anything in the tunnel.
     */
    public const CONTROL_PLANE_PREFIX = '/api/paart';

    private Database $db;
    private WireguardGateway $gateway;
    private string $siteLabel;
    private string $controlPlanePin;
    private string $controlPort;
    private string $siteKey;

    /**
     * @param string $siteLabel resolved site.label (never empty in
     *        production — Paart::libSettings() falls back to the hostname).
     * @param string $controlPlanePin SPKI SHA-256 pin of the web GUI
     *        certificate, published as site.pin_sha256 (ADR 0003/0004);
     *        '' publishes an empty list.
     * @param string $controlPort web GUI port for site.instance_url;
     *        '' or '443' add no suffix.
     * @param string $siteKey the site key setting, published as
     *        site.site_key and NEVER parsed here (ADR 0024, D36/D38);
     *        '' publishes no field at all.
     */
    public function __construct(
        Database $db,
        WireguardGateway $gateway,
        string $siteLabel,
        string $controlPlanePin = '',
        string $controlPort = '',
        string $siteKey = ''
    ) {
        $this->db = $db;
        $this->gateway = $gateway;
        $this->siteLabel = $siteLabel;
        $this->controlPlanePin = $controlPlanePin;
        $this->controlPort = $controlPort;
        $this->siteKey = $siteKey;
    }

    /**
     * Server facts for the instance a validated token targets — called
     * BEFORE the enrollment so a gateway failure aborts with the token
     * intact (see file header). Routes on purpose: an enroll token names
     * its instance, a rekey token names its device (ADR 0006).
     *
     * @param array<string, mixed> $token valid enroll_tokens row.
     * @return array{name: string, public_key: string, port: ?int,
     *               mtu: ?int, tunnel_addresses: array<int, string>}
     * @throws DomainException PROVISIONING_UNAVAILABLE (gateway down, or a
     *         server row unusable for bundles) | NOT_FOUND (broken
     *         reference — unreachable through the domain layer).
     */
    public function serverForToken(array $token): array
    {
        $instanceId = (string)($token['instance_id'] ?? '');
        if (($token['purpose'] ?? 'enroll') === 'rekey') {
            $instanceId = (string)$this->db->scalar(
                'SELECT instance_id FROM devices WHERE id = :id',
                [':id' => (string)($token['device_id'] ?? '')]
            );
        }
        return $this->serverForInstance($instanceId);
    }

    /**
     * Same facts keyed by the declared instance ULID — the defensive
     * re-fetch path when the prefetch was skipped.
     *
     * @return array{name: string, public_key: string, port: ?int,
     *               mtu: ?int, tunnel_addresses: array<int, string>}
     * @throws DomainException PROVISIONING_UNAVAILABLE | NOT_FOUND.
     */
    public function serverForInstance(string $instanceId): array
    {
        $ref = $this->db->scalar(
            'SELECT wg_instance_ref FROM instances WHERE id = :id',
            [':id' => $instanceId]
        );
        if ($ref === null) {
            throw new DomainException('NOT_FOUND', "Declared instance '$instanceId' does not exist.");
        }
        $server = $this->gateway->getServer((string)$ref);
        // Both facts are load-bearing for the bundle; a server row missing
        // them is the same refusal as an unreachable firewall — retryable,
        // and nothing consumed since callers fetch before the service acts.
        if ($server['public_key'] === '' || $server['tunnel_addresses'] === []) {
            throw new DomainException(
                'PROVISIONING_UNAVAILABLE',
                'The VPN service configuration is temporarily unavailable. ' .
                'Nothing was changed; retry later with the same token.'
            );
        }
        return $server;
    }

    /**
     * The EnrollResponse payload (M01).
     *
     * @param array{device: array<string, mixed>, device_token: ?string}
     *        $enrollResult EnrollmentService::enroll() result;
     *        device_token is null for a rekey completion — the device
     *        keeps its existing token (ADR 0006), and the contract marks
     *        the field nullable for exactly that case.
     * @param array<string, mixed> $server serverForToken() facts.
     * @return array{device_id: string, device_token: ?string,
     *               bundle: array<string, mixed>}
     */
    public function response(array $enrollResult, array $server): array
    {
        $device = $enrollResult['device'];
        return [
            'device_id' => (string)$device['id'],
            'device_token' => $enrollResult['device_token'],
            'bundle' => $this->forDevice($device, $server),
        ];
    }

    /**
     * The Bundle (M01 schema) for one enrolled device.
     *
     * @param array<string, mixed> $device contract device payload — id,
     *        label, instance_id and ip_address are read.
     * @param array<string, mixed> $server serverForToken() facts.
     * @param ?array<string, mixed> $rotation the device's open rotations
     *        row (RotationService::currentRotation), or null: the bundle's
     *        `rotation` block says 'pending' / 'applied' with the grace
     *        deadline, or 'none'. Enrollment passes nothing — a fresh
     *        enrollment has nothing pending, and a completed rekey just
     *        made the submitted key current; the device poll (M05) passes
     *        what is actually open.
     * @return array<string, mixed>
     * @throws DomainException NOT_FOUND when the device references a
     *         missing instance (unreachable through the domain layer).
     */
    public function forDevice(array $device, array $server, ?array $rotation = null): array
    {
        $instanceId = (string)$device['instance_id'];
        $rows = $this->db->query('SELECT * FROM instances WHERE id = :id', [':id' => $instanceId]);
        if ($rows === []) {
            throw new DomainException('NOT_FOUND', "Declared instance '$instanceId' does not exist.");
        }
        $instance = $rows[0];

        $tunnel = [
            'server_public_key' => (string)$server['public_key'],
            'endpoint' => (string)$instance['endpoint'],
            'address' => (string)$device['ip_address'] . '/32',
            'persistent_keepalive' => self::PERSISTENT_KEEPALIVE_S,
        ];
        if ($server['mtu'] !== null) {
            // Optional in the contract: omitted when the instance sets none,
            // so clients keep their platform default.
            $tunnel['mtu'] = (int)$server['mtu'];
        }

        $site = [
            'id' => $this->siteId(),
            'label' => $this->siteLabel,
            'instance_url' => $this->instanceUrl($server),
            'pin_sha256' => $this->controlPlanePin !== '' ? [$this->controlPlanePin] : [],
            'managed_devices' => $this->managedDevices(),
        ];
        if ($this->siteKey !== '') {
            // Verbatim, and last: whatever the administrator pasted, down to
            // a stray space. Trimming would be a first opinion about a
            // format this side does not know (ADR 0024, D38), and the client
            // already tolerates a key a mail client folded.
            $site['site_key'] = $this->siteKey;
        }

        return [
            'schema_version' => self::SCHEMA_VERSION,
            'site' => $site,
            'network' => [
                'id' => $instanceId,
                'label' => (string)$instance['label'],
            ],
            // The device's own identity as the ADMINISTRATOR sees it. The
            // app shows this label read-only and says to ask the admin to
            // change it (spec 13, "Réglages"): the device surface has four
            // routes and none renames anything, so the only honest source
            // is the server, re-read on every poll. Sent back rather than
            // remembered from the enrollment request because renameDevice
            // is an admin route — a label kept from enrollment goes stale
            // the day it is used, without saying so.
            'device' => [
                'id' => (string)$device['id'],
                'label' => (string)$device['label'],
            ],
            'tunnel' => $tunnel,
            'subnets' => $this->subnets($instanceId),
            'dns' => [
                'servers' => self::jsonList((string)$instance['dns_servers_json']),
                'match_domains' => self::jsonList((string)$instance['match_domains_json']),
            ],
            'policies' => [
                'allow_full_tunnel' => (bool)(int)$instance['allow_full_tunnel'],
                'allow_subnet_toggle' => (bool)(int)$instance['allow_subnet_toggle'],
            ],
            'hosts' => $this->hosts($instanceId),
            'rotation' => $rotation === null
                ? ['state' => 'none', 'deadline' => null]
                : ['state' => (string)$rotation['state'], 'deadline' => (string)$rotation['grace_until']],
        ];
    }

    /**
     * How many devices this site manages, right now. A NUMBER, and nothing
     * else: the plugin carries no licence, reads no key and issues no
     * verdict (ADR 0018, D16; forbidden rule #10). What the client does
     * with it — comparing it to the tier its site key carries, and
     * refusing `full` mode past it — is decided in a binary this
     * repository does not contain.
     *
     * `full` only, because the number counts devices this site actively
     * manages (ADR 0018, D17): a `manual` device holds a peer but polls
     * nothing, so the server manages nothing for it. `rotating` counts
     * with `active` — such a device has a live peer and a tunnel that comes up;
     * excluding it would make the number fall during a fleet rotation and
     * climb back afterwards, moving without a single device being added.
     */
    private function managedDevices(): int
    {
        return (int)$this->db->scalar(
            "SELECT COUNT(*) FROM devices
              WHERE management_level = 'full' AND status IN ('active', 'rotating')"
        );
    }

    /**
     * Lazy singleton site id (meta table). INSERT OR IGNORE + re-read so
     * two concurrent first enrollments converge on the same ULID.
     */
    private function siteId(): string
    {
        $id = $this->db->scalar("SELECT value FROM meta WHERE key = 'site_id'");
        if ($id === null) {
            $this->db->run(
                "INSERT OR IGNORE INTO meta (key, value, updated_at) VALUES ('site_id', :v, :now)",
                [':v' => Ulid::generate(), ':now' => Database::utcNow()]
            );
            $id = $this->db->scalar("SELECT value FROM meta WHERE key = 'site_id'");
        }
        return (string)$id;
    }

    /**
     * In-tunnel control-plane URL (ADR 0003): the instance's own tunnel
     * address — devices reach the plugin's device API through the tunnel —
     * on the web GUI port, preferring IPv4. Always https: enrollment
     * pinning (ADR 0004) is meaningless over plain http, which the web
     * GUI API is not served on here.
     */
    private function instanceUrl(array $server): string
    {
        $chosen = null;
        foreach ($server['tunnel_addresses'] as $cidr) {
            $ip = \strtok((string)$cidr, '/');
            if ($ip === false || $ip === '') {
                continue;
            }
            if (\strpos($ip, ':') === false) {
                $chosen = $ip; // first IPv4 wins
                break;
            }
            $chosen ??= '[' . $ip . ']';
        }
        // serverForInstance() guaranteed at least one address.
        $port = ($this->controlPort !== '' && $this->controlPort !== '443')
            ? ':' . $this->controlPort
            : '';
        return 'https://' . $chosen . $port . self::CONTROL_PLANE_PREFIX;
    }

    /** @return array<int, array<string, mixed>> ordered as the admin sorted them. */
    private function subnets(string $instanceId): array
    {
        $out = [];
        $rows = $this->db->query(
            'SELECT id, label, cidr, default_on FROM subnets
              WHERE instance_id = :i ORDER BY sort_order, id',
            [':i' => $instanceId]
        );
        foreach ($rows as $row) {
            $out[] = [
                'id' => (string)$row['id'],
                'label' => (string)$row['label'],
                'cidr' => (string)$row['cidr'],
                'default_on' => (bool)(int)$row['default_on'],
            ];
        }
        return $out;
    }

    /**
     * The instance's named hosts as the bundle carries them (`hosts[]`,
     * M14) — public for GET /device/hosts, the lightweight refresh that
     * serves exactly this block.
     *
     * @return array<int, array<string, mixed>> ordered as the admin sorted them.
     */
    public function hosts(string $instanceId): array
    {
        $out = [];
        $rows = $this->db->query(
            'SELECT id, label, address, probe_port FROM hosts
              WHERE instance_id = :i ORDER BY sort_order, id',
            [':i' => $instanceId]
        );
        foreach ($rows as $row) {
            $out[] = [
                'id' => (string)$row['id'],
                'label' => (string)$row['label'],
                'address' => (string)$row['address'],
                // null keeps the M14 ICMP fallback semantics.
                'probe_port' => $row['probe_port'] !== null ? (int)$row['probe_port'] : null,
            ];
        }
        return $out;
    }

    /** @return array<int, string> decoded JSON list column; malformed becomes []. */
    private static function jsonList(string $json): array
    {
        $decoded = \json_decode($json, true);
        return \is_array($decoded) ? \array_values(\array_map('\strval', $decoded)) : [];
    }
}
