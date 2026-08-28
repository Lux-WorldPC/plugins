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
 * Production composition root — still framework-free: it receives plain
 * settings values (read from the config.xml model by the MVC controllers,
 * M08), a WireguardGateway and — optionally, defaulting to the production
 * ones — the HAProxy gateway and probe of M09, and wires the full
 * delivered service graph
 * (M02 store, M03 domain — instances, subnets, users, devices, IPAM —,
 * M06 provisioner, M04 enrollment, M05 rotation,
 * M07 audit trail and its retention setting, M09 exposure, M15 portal,
 * admin façade, M10 maintenance). Tests wire the same graph by hand; this class
 * only exists so every controller — and the scripts under
 * scripts/OPNsense/Paart, which build it the same way — composes the exact
 * same production graph.
 *
 * Construction opens the store and brings the schema up to date (Migrator
 * backs the base up first and refuses a store newer than the code, M02).
 * The bootstrap script runs the same at boot (M10 hook; the package's
 * +POST_INSTALL will call it too); doing it here as well is idempotent
 * and keeps the API usable even if that hook never ran.
 */

namespace OPNsense\Paart\App;

use OPNsense\Paart\Admin\AdminService;
use OPNsense\Paart\Admin\CleanupService;
use OPNsense\Paart\Domain\AuditTrail;
use OPNsense\Paart\Domain\Devices;
use OPNsense\Paart\Domain\Instances;
use OPNsense\Paart\Domain\Subnets;
use OPNsense\Paart\Domain\Ipam;
use OPNsense\Paart\Domain\Users;
use OPNsense\Paart\Enroll\Bundles;
use OPNsense\Paart\Enroll\EnrollmentService;
use OPNsense\Paart\Enroll\EnrollTokens;
use OPNsense\Paart\Enroll\Portal;
use OPNsense\Paart\Exposure\CurlExposureProbe;
use OPNsense\Paart\Exposure\ExposureProbe;
use OPNsense\Paart\Exposure\ExposureService;
use OPNsense\Paart\Exposure\HaproxyGateway;
use OPNsense\Paart\Exposure\HttpHaproxyGateway;
use OPNsense\Paart\Provision\HttpWireguardGateway;
use OPNsense\Paart\Provision\OpnsenseProvisioner;
use OPNsense\Paart\Provision\ProvisionerPeerSource;
use OPNsense\Paart\Provision\WireguardGateway;
use OPNsense\Paart\Rotation\Reconciliation;
use OPNsense\Paart\Rotation\RotationService;
use OPNsense\Paart\Store\Database;
use OPNsense\Paart\Store\Migrator;
use OPNsense\Paart\Store\StoreException;

final class Container
{
    /** Plugin version, sent as X-Paart-Version on every contract response (M01/M10; the native grid routes skip it). */
    public const PLUGIN_VERSION = '0.1.0';
    /** API major version, sent as X-Paart-Api-Version (frozen /api/v1). */
    public const API_VERSION = '1';
    /** Contract EnrollRequest.device_name maxLength (M01), announced by /enroll/policy and enforced by the portal page. */
    public const DEVICE_NAME_MAX_LENGTH = 64;
    /** Store location fixed by M02: /var/db/<plugin>/store.db. */
    public const DEFAULT_DB_PATH = '/var/db/paart/store.db';

    /**
     * The raw gateway, for the display-only reads the M08 screens need —
     * undeclared instances with their peer count (Networks), live tunnel
     * state and peer config lookups (Devices, via Admin\DevicesScreen) —
     * and the server facts bundle assembly reads (Enroll\Bundles, M04).
     * Never a write path: every provisioning write goes through
     * $provisioner, whose guards never touch an undeclared instance (M06).
     */
    public readonly WireguardGateway $gateway;

    // The service graph, in construction order — each layer receives the
    // ones above it, never the reverse. Public and readonly so controllers
    // reach any layer directly (the admin API goes through $admin, the
    // public enrollment API through $enrollment and $bundles) without this
    // class growing a delegating method per operation.

    /** M02 store handle, schema already migrated (see the constructor). */
    public readonly Database $db;
    /** M02 migrator, kept for the schema version the bootstrap script reports (the health payload reads schema_meta itself). */
    public readonly Migrator $migrator;
    /** M07 audit trail — every layer below records through this one. */
    public readonly AuditTrail $audit;
    /** M06 provisioner: the ONLY write path to the firewall. */
    public readonly OpnsenseProvisioner $provisioner;
    /** M03 declared instances (M08 Networks). */
    public readonly Instances $instances;
    /** Labeled subnets of the declared instances (M08 Networks, bundle `subnets[]`). */
    public readonly Subnets $subnets;
    /** M03 address allocation and quarantine. */
    public readonly Ipam $ipam;
    /** M03 device lifecycle. */
    public readonly Devices $devices;
    /** M03 user lifecycle. */
    public readonly Users $users;
    /** M04 enrollment and rekey tokens. */
    public readonly EnrollTokens $enrollTokens;
    /** M04 enrollment sequence (public API). */
    public readonly EnrollmentService $enrollment;
    /** M04 bundle assembly (public API). */
    public readonly Bundles $bundles;
    /** M15 portal page renderer (site label, platforms, limits — nothing per user). */
    public readonly Portal $portal;
    /** M05 rotation and revocation sequences. */
    public readonly RotationService $rotation;
    /** M05 drift reporting — read-only by design, never corrective. */
    public readonly Reconciliation $reconciliation;
    /** M09 public exposure through os-haproxy (Settings > Public exposure). */
    public readonly ExposureService $exposure;
    /** M08 admin API façade. */
    public readonly AdminService $admin;
    /**
     * M10 cleanup — the "purge" half of uninstalling, which the package
     * script cannot run (pkg has no terminal to ask the question).
     * Destroys accesses on purpose, through the same withdrawal path the
     * Networks screen uses; never invents a deletion of its own.
     */
    public readonly CleanupService $cleanup;
    /** M10 periodic maintenance — what the cron job and the configd action run. */
    public readonly Maintenance $maintenance;

    /**
     * The configured enrollment host, '' when unset — the one settings
     * value a screen needs on its own: the M08 Enrollment screen says up
     * front that no link can be built, instead of letting the admin fill a
     * form issueToken() would then refuse. Kept here rather than read from
     * the model a second time, so controllers keep a single settings path.
     */
    public readonly string $enrollHost;

    /**
     * Audit retention horizon in months (M07): consumed by the periodic
     * purge (AuditTrail::purgeExpired, run by Maintenance, M10) and by
     * the Audit screen, which warns below 12 months. 0/absent falls back
     * to AuditTrail::DEFAULT_RETENTION_MONTHS — the model enforces 1..120,
     * so the fallback only covers a store predating the setting.
     */
    public readonly int $auditRetentionMonths;

    /**
     * @param array<string, mixed> $settings scalar settings, keys:
     *        db_path (default DEFAULT_DB_PATH),
     *        rotation_grace_days (0/absent = M05 default 30),
     *        ip_quarantine_days (absent = M03 default 90),
     *        max_devices_per_user (0/absent = unlimited, M03 default),
     *        enroll_host, enroll_pin_sha256 (enroll links, M01: the
     *        PUBLIC endpoint's certificate pin, written as `fp=`),
     *        site_label (bundle site.label, resolved — hostname fallback),
     *        control_port (web GUI port for site.instance_url; ''/443 =
     *        no suffix),
     *        control_plane_pin_sha256 (bundle site.pin_sha256: the web
     *        GUI's own certificate pin, a different certificate from the
     *        enrollment endpoint's — ADR 0003),
     *        audit_retention_months (0/absent = M07 default 24),
     *        exposure_bind (M09 frontend bind, '' = 0.0.0.0:443),
     *        exposure_certificate (M09, System > Trust refid, '' = the
     *        exposure cannot be applied).
     *        Unknown keys are ignored: the wg_api_* credentials belong to
     *        gatewayFromSettings() and haproxyGatewayFromSettings().
     * @param WireguardGateway $gateway usually gatewayFromSettings(); tests
     *        inject their fake here.
     * @param ?HaproxyGateway $haproxy null = haproxyGatewayFromSettings(),
     *        the production path; tests inject their fake.
     * @param ?ExposureProbe $probe null = CurlExposureProbe; tests inject
     *        their scripted one.
     * @throws StoreException when the store cannot be opened or is newer
     *         than the code (SCHEMA_MISMATCH — refuse to operate, M02).
     */
    public function __construct(
        array $settings,
        WireguardGateway $gateway,
        ?HaproxyGateway $haproxy = null,
        ?ExposureProbe $probe = null
    ) {
        $dbPath = (string)($settings['db_path'] ?? self::DEFAULT_DB_PATH);
        $dir = \dirname($dbPath);
        if (!\is_dir($dir) && !@\mkdir($dir, 0700, true)) {
            throw new StoreException("Cannot create the data directory '$dir'. No data has been touched.");
        }

        $this->gateway = $gateway;
        $this->db = new Database($dbPath);
        $this->migrator = new Migrator($this->db, __DIR__ . '/../Store/Migrations');
        $this->migrator->migrate();

        $this->audit = new AuditTrail($this->db);
        $this->provisioner = new OpnsenseProvisioner($this->db, $gateway, $this->audit);
        $peerSource = new ProvisionerPeerSource($this->provisioner, $this->db);

        $quarantineDays = isset($settings['ip_quarantine_days'])
            ? (int)$settings['ip_quarantine_days']
            : Ipam::DEFAULT_QUARANTINE_DAYS;
        $this->ipam = new Ipam($this->db, $peerSource, $quarantineDays);

        $deviceLimit = (int)($settings['max_devices_per_user'] ?? 0);
        $this->devices = new Devices(
            $this->db,
            $this->ipam,
            $peerSource,
            $this->audit,
            $deviceLimit > 0 ? $deviceLimit : null
        );
        $this->users = new Users($this->db, $this->devices, $this->audit);
        $this->instances = new Instances($this->db, $this->audit);
        $this->subnets = new Subnets($this->db, $this->audit);
        $this->enrollTokens = new EnrollTokens($this->db, $this->audit);
        $this->enrollment = new EnrollmentService(
            $this->db,
            $this->enrollTokens,
            $this->devices,
            $this->provisioner,
            $this->audit
        );
        $this->bundles = new Bundles(
            $this->db,
            $gateway,
            (string)($settings['site_label'] ?? ''),
            isset($settings['control_plane_pin_sha256']) ? (string)$settings['control_plane_pin_sha256'] : '',
            (string)($settings['control_port'] ?? ''),
            (string)($settings['site_key'] ?? '')
        );

        $graceDays = (int)($settings['rotation_grace_days'] ?? 0);
        $this->rotation = new RotationService(
            $this->db,
            $this->devices,
            $this->enrollTokens,
            $this->provisioner,
            $this->audit,
            $graceDays > 0 ? $graceDays * 86400 : null
        );
        $this->reconciliation = new Reconciliation($this->db, $this->provisioner, $this->audit);

        $this->enrollHost = isset($settings['enroll_host']) ? (string)$settings['enroll_host'] : '';
        $retention = (int)($settings['audit_retention_months'] ?? 0);
        $this->auditRetentionMonths = $retention > 0 ? $retention : AuditTrail::DEFAULT_RETENTION_MONTHS;
        $this->exposure = new ExposureService(
            $this->db,
            $haproxy ?? self::haproxyGatewayFromSettings($settings),
            $probe ?? new CurlExposureProbe(),
            $this->audit,
            (string)($settings['exposure_bind'] ?? ''),
            (string)($settings['exposure_certificate'] ?? ''),
            (string)($settings['control_port'] ?? ''),
            $this->enrollHost,
            isset($settings['enroll_pin_sha256']) ? (string)$settings['enroll_pin_sha256'] : ''
        );
        $this->admin = new AdminService(
            $this->db,
            $this->users,
            $this->devices,
            $this->instances,
            $this->enrollTokens,
            $this->rotation,
            $this->reconciliation,
            $this->provisioner,
            $this->enrollHost,
            isset($settings['enroll_pin_sha256']) ? (string)$settings['enroll_pin_sha256'] : null,
            $this->exposure
        );
        $this->cleanup = new CleanupService(
            $this->db,
            $this->migrator,
            $this->audit,
            $this->admin,
            $this->exposure,
            $dbPath
        );
        $this->portal = new Portal(
            (string)($settings['site_label'] ?? ''),
            Devices::PLATFORMS,
            self::DEVICE_NAME_MAX_LENGTH
        );
        $this->maintenance = new Maintenance(
            $this->enrollment,
            $this->rotation,
            $this->reconciliation,
            $this->audit,
            $this->auditRetentionMonths
        );
    }

    /**
     * The production gateway: the os-wireguard HTTP API on the firewall
     * itself, exactly the code path the V2/V3 campaign validated (M06).
     *
     * @param array<string, mixed> $settings scalar settings, keys:
     *        wg_api_url (default https://127.0.0.1), wg_api_key,
     *        wg_api_secret, wg_api_verify_tls (default false — the
     *        loopback call presents the firewall's own certificate).
     */
    public static function gatewayFromSettings(array $settings): WireguardGateway
    {
        return new HttpWireguardGateway(
            \rtrim((string)($settings['wg_api_url'] ?? 'https://127.0.0.1'), '/'),
            (string)($settings['wg_api_key'] ?? ''),
            (string)($settings['wg_api_secret'] ?? ''),
            (bool)($settings['wg_api_verify_tls'] ?? false)
        );
    }

    /**
     * The production HAProxy gateway (M09): the os-haproxy API on the
     * firewall itself, reached with the same credentials as the WireGuard
     * one — the API user needs both privileges when the exposure is used.
     *
     * @param array<string, mixed> $settings the wg_api_* keys of gatewayFromSettings().
     */
    public static function haproxyGatewayFromSettings(array $settings): HaproxyGateway
    {
        return new HttpHaproxyGateway(
            \rtrim((string)($settings['wg_api_url'] ?? 'https://127.0.0.1'), '/'),
            (string)($settings['wg_api_key'] ?? ''),
            (string)($settings['wg_api_secret'] ?? ''),
            (bool)($settings['wg_api_verify_tls'] ?? false)
        );
    }
}
