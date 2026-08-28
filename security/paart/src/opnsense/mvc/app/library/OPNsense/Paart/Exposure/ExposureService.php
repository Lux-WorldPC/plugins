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
 * Public exposure of the enrollment endpoint through os-haproxy (M09).
 *
 * The plugin never edits haproxy.conf and never installs HAProxy: it adds
 * its own objects to the HAProxy model — one server (the local web GUI),
 * one backend, four ACLs, five actions, one frontend — every one named
 * with the paart_ prefix, which IS the ownership rule: apply() creates or
 * updates exactly these twelve names, remove() deletes every object carrying
 * the prefix (the twelve, plus anything an admin named paart_* by hand — the
 * prefix is reserved; status() lists such extras among the objects), and
 * nothing else in the HAProxy configuration is ever read for writing.
 * A pre-existing frontend on the same port is a refusal, never a merge.
 *
 * What the generated frontend does, in HAProxy order:
 *   1. http-request deny 429 when the source exceeds RATE_LIMIT_REQUESTS
 *      per RATE_LIMIT_PERIOD (stick table on the frontend, a coarse cap
 *      complementing the per-IP enrollment limit of M04);
 *   2. http-request deny 403 unless the path begins with PUBLIC_PREFIX
 *      or PORTAL_PREFIX (ADR 0008) — so /api/v1/admin/*, /ui/*,
 *      /api/v1/device/* (ADR 0003) and even the plugin's own local paths
 *      are refused (403, never a 401 that would reveal an authentication
 *      surface);
 *   3. http-request set-path rewriting PUBLIC_PREFIX (the frozen contract
 *      path, M01) to LOCAL_PREFIX (where the core's router serves the
 *      plugin's EnrollController), and PORTAL_PREFIX to PORTAL_LOCAL_PREFIX
 *      (the same controller's portal route, M15);
 *   4. use_backend toward 127.0.0.1:<web GUI port> over TLS, with
 *      X-Forwarded-For so the enrollment rate limit sees the client.
 * TLS 1.2 minimum, HSTS, access log on. path_beg on both prefixes:
 * anything under them reaches the plugin's router, which knows just the
 * enrollment routes and answers nothing else.
 *
 * verify() is the "Verify my configuration" button: from the firewall
 * itself, through the frontend's local address with the real host name
 * (SNI/Host), it checks seven paths answer as they must — the policy
 * (200), then admin, UI, device, core API and the local path (403), and
 * the portal page (200, M15) — and
 * inspects the served certificate (validity, names, SPKI pin). Whether
 * the port is reachable from the Internet is something only an outside
 * viewpoint can tell — the result carries the URL for that guided manual
 * test (D2: no editor-side service), and the admin can record having
 * done it. The verification date lives in the store's meta table.
 *
 * Errors: generated objects are never deleted on failure; every message
 * says what stayed in place. The gateway's own messages speak for their
 * call only; when a call fails after earlier writes of the same apply()
 * or remove(), afterWrites() appends what those writes left in place, and
 * every failure is audited with the same lists. Exposure-side refusals
 * are EXPOSURE_* codes, bad inputs VALIDATION_FAILED, unknown effects
 * INTERNAL.
 */

namespace OPNsense\Paart\Exposure;

use OPNsense\Paart\Domain\AuditTrail;
use OPNsense\Paart\Store\Database;

final class ExposureService
{
    /** Name prefix of every HAProxy object the plugin owns. */
    public const PREFIX = 'paart_';
    /** Public enrollment path, frozen by the contract (M01): /api/v1/enroll[/policy]. */
    public const PUBLIC_PREFIX = '/api/v1/enroll';
    /** Where the core router serves the plugin's enrollment controller. */
    public const LOCAL_PREFIX = '/api/paart/enroll';
    /** Canonical public prefix of the portal pages (M15, ADR 0008) — reserved, not generated yet. */
    public const PORTAL_PREFIX = '/enroll/';
    /** Where the plugin serves the portal page (Enroll\Portal::LOCAL_PATH plus the slash the rewrite keeps). */
    public const PORTAL_LOCAL_PREFIX = '/api/paart/enroll/portal/';
    /** Bind used when the setting is empty: every IPv4 address, HTTPS port. */
    public const DEFAULT_BIND = '0.0.0.0:443';
    /** Spec hardening: TLS 1.2 minimum. */
    public const TLS_MIN_VERSION = 'TLSv1.2';
    /** HSTS max-age in seconds: six months (spec 09 hardening) — long enough to stick, short enough to undo. */
    public const HSTS_MAX_AGE_S = 15768000;
    /**
     * Coarse per-source cap at the HAProxy level, RATE_LIMIT_REQUESTS per
     * RATE_LIMIT_PERIOD (an HAProxy duration string) — spec 09 hardening,
     * 20 / 10 s chosen in session 20; M04 keeps the real enrollment limit.
     */
    public const RATE_LIMIT_REQUESTS = 20;
    public const RATE_LIMIT_PERIOD = '10s';
    /** Refusal of anything outside the public prefix; 403, never 401. */
    public const DENY_STATUS = 403;
    /** Answer to a source over the cap — the HTTP "too many requests" status. */
    public const FLOOD_STATUS = 429;

    private const N_SERVER = 'paart_local';
    private const N_BACKEND = 'paart_enroll';
    private const N_ACL_PUBLIC = 'paart_public_path';
    private const N_ACL_LOCAL = 'paart_local_path';
    private const N_ACL_PORTAL = 'paart_portal_path';
    private const N_ACL_FLOOD = 'paart_flood';
    private const N_ACT_FLOOD = 'paart_deny_flood';
    private const N_ACT_DENY = 'paart_deny_other';
    private const N_ACT_REWRITE = 'paart_rewrite_path';
    private const N_ACT_REWRITE_PORTAL = 'paart_rewrite_portal';
    private const N_ACT_ROUTE = 'paart_route_enroll';
    private const N_FRONTEND = 'paart_public';

    /**
     * The generated name per collection — what apply() writes and status()
     * reports as missing. Not the deletion list: remove() and status() go
     * by the prefix, see owned().
     */
    private const OWNED = [
        'servers' => [self::N_SERVER],
        'backends' => [self::N_BACKEND],
        'acls' => [self::N_ACL_PUBLIC, self::N_ACL_PORTAL, self::N_ACL_LOCAL, self::N_ACL_FLOOD],
        'actions' => [
            self::N_ACT_FLOOD, self::N_ACT_DENY, self::N_ACT_REWRITE, self::N_ACT_REWRITE_PORTAL, self::N_ACT_ROUTE,
        ],
        'frontends' => [self::N_FRONTEND],
    ];
    /** Deletion order: dependents first (os-haproxy refuses to delete a referenced object). */
    private const REMOVE_ORDER = ['frontends', 'actions', 'acls', 'backends', 'servers'];

    /** Store meta key: UTC date of the last verify() that passed every check; cleared by remove(). */
    private const META_VERIFIED_AT = 'exposure_last_verified_at';
    /** Store meta key: UTC date the admin confirmed the guided outside test; cleared by remove(). */
    private const META_EXTERNAL_AT = 'exposure_external_confirmed_at';
    /** Description field of every generated object — what the admin reads in Services > HAProxy. */
    private const DESCRIPTION = 'VPN Access enrollment exposure (generated by the plugin, do not edit)';

    private Database $db;
    private HaproxyGateway $haproxy;
    private ExposureProbe $probe;
    private AuditTrail $audit;
    private string $bind;
    private string $certificate;
    private string $controlPort;
    private string $enrollHost;
    private string $enrollPin;

    /**
     * @param Database $db the plugin store (meta: verification dates).
     * @param HaproxyGateway $haproxy the os-haproxy API.
     * @param ExposureProbe $probe HTTPS client for verify().
     * @param AuditTrail $audit receives exposure.apply/remove/verify.
     * @param string $bind frontend bind, `address:port`; '' = DEFAULT_BIND.
     * @param string $certificate refid of the server certificate (System >
     *        Trust) the frontend presents; '' = apply() refuses.
     * @param string $controlPort web GUI port the backend targets; '' = 443.
     * @param string $enrollHost public host[:port] of the enrollment links
     *        (M01 setting); verify() needs it for SNI/Host.
     * @param string $enrollPin optional SPKI pin setting (ADR 0004): when
     *        set, verify() checks the served certificate matches it.
     */
    public function __construct(
        Database $db,
        HaproxyGateway $haproxy,
        ExposureProbe $probe,
        AuditTrail $audit,
        string $bind = '',
        string $certificate = '',
        string $controlPort = '',
        string $enrollHost = '',
        string $enrollPin = ''
    ) {
        $this->db = $db;
        $this->haproxy = $haproxy;
        $this->probe = $probe;
        $this->audit = $audit;
        $this->bind = $bind !== '' ? $bind : self::DEFAULT_BIND;
        $this->certificate = $certificate;
        $this->controlPort = $controlPort;
        $this->enrollHost = $enrollHost;
        $this->enrollPin = $enrollPin;
    }

    // --------------------------------------------------------------- status

    /**
     * The Settings screen's exposure panel in one read. Never throws for
     * an absent or unreachable HAProxy: that IS the status.
     *
     * @return array<string, mixed> haproxy: absent|present|unreachable;
     *         service: core status string or null; service_enabled;
     *         mode: haproxy|internal_only (the frontend exists and is
     *         enabled); objects/missing: owned names found/expected;
     *         the inputs (bind, certificate, backend_port, enroll_host),
     *         the prefixes, the verification dates and the external test
     *         URL; error: the reason when unreachable.
     */
    public function status(): array
    {
        $out = [
            'haproxy' => 'absent',
            'service' => null,
            'service_enabled' => null,
            'mode' => 'internal_only',
            'objects' => [],
            'missing' => self::ownedList(),
            'bind' => $this->bind,
            'certificate' => $this->certificate,
            'backend_port' => $this->backendPort(),
            'enroll_host' => $this->enrollHost,
            'public_prefix' => self::PUBLIC_PREFIX,
            'portal_prefix' => self::PORTAL_PREFIX,
            'last_verified_at' => $this->metaGet(self::META_VERIFIED_AT),
            'external_confirmed_at' => $this->metaGet(self::META_EXTERNAL_AT),
            'external_test_url' => $this->externalTestUrl(),
        ];
        try {
            if (!$this->haproxy->installed()) {
                return $out;
            }
            $out['haproxy'] = 'present';
            $out['service'] = $this->haproxy->serviceStatus();
            $out['service_enabled'] = $this->haproxy->serviceEnabled();
            $owned = $this->owned();
            $found = [];
            foreach ($owned as $collection => $rows) {
                foreach ($rows as $name => $row) {
                    $found[] = "$collection/$name";
                }
            }
            $out['objects'] = $found;
            $out['missing'] = \array_values(\array_diff(self::ownedList(), $found));
            $frontend = $owned['frontends'][self::N_FRONTEND] ?? null;
            if ($frontend !== null && (string)($frontend['enabled'] ?? '0') === '1') {
                $out['mode'] = 'haproxy';
            }
        } catch (ExposureException $e) {
            $out['haproxy'] = 'unreachable';
            $out['error'] = $e->getMessage();
        }
        return $out;
    }

    /**
     * The /admin/health projection (M01 `enrollment_exposure`): mode and
     * last verification, plus the additive `haproxy` presence.
     *
     * @return array{mode: string, last_verified_at: ?string, haproxy: string}
     */
    public function summary(): array
    {
        $status = $this->status();
        return [
            'mode' => $status['mode'],
            'last_verified_at' => $status['last_verified_at'],
            'haproxy' => $status['haproxy'],
        ];
    }

    // ---------------------------------------------------------------- apply

    /**
     * Create or update the owned objects, enable the service if it was
     * off, test the rendered configuration, reload. Idempotent: a second
     * run updates the same objects. Refuses before writing anything when
     * the inputs are incomplete, the plugin is absent, or another
     * frontend (or the web GUI itself) already listens on the bind port.
     *
     * @param string $actorRef admin identity for the audit trail.
     * @return array<string, mixed> result: applied; created/updated:
     *         collection/name lists; service_enabled: whether this call
     *         turned the service on; status: status() afterwards.
     * @throws ExposureException VALIDATION_FAILED (inputs, a refused
     *         object, a failing configtest — objects stay in place),
     *         EXPOSURE_UNAVAILABLE (plugin absent, API unreachable or
     *         refusing the API user), EXPOSURE_CONFLICT (port already
     *         taken — nothing written), INTERNAL (effect unknown: timeout
     *         or non-JSON reply from the API, a refused service enable, or
     *         a failed reload after the configuration was saved). Whatever
     *         the code, a failure after the first write lists the objects
     *         saved so far and, when this call switched the service on,
     *         says it stays on; the failure is audited with the same lists.
     */
    public function apply(string $actorRef): array
    {
        // Every refusal before the first write is an admin act too: audited
        // — the reads of owned() included, so an API lost between the
        // conflict check and the first write leaves a trace.
        try {
            $this->requireInputs();
            if (!$this->haproxy->installed()) {
                throw new ExposureException(
                    'EXPOSURE_UNAVAILABLE',
                    'The os-haproxy plugin is not installed on this firewall, so no exposure can be managed. ' .
                    'Nothing was changed. Install it from System > Firmware > Plugins, or keep enrollment ' .
                    'internal-only: devices then enroll from the office network, which is a legitimate setup.'
                );
            }
            $this->refuseConflicts();
            $owned = $this->owned();
        } catch (ExposureException $e) {
            $this->recordFailure($actorRef, 'exposure.apply', $e->getMessage());
            throw $e;
        }

        $created = [];
        $updated = [];
        $upsert = function (string $collection, string $name, array $fields) use (&$owned, &$created, &$updated): string {
            $existing = $owned[$collection][$name] ?? null;
            $fields += ['name' => $name, 'description' => self::DESCRIPTION];
            try {
                if ($existing !== null) {
                    $uuid = (string)$existing['uuid'];
                    $reply = $this->haproxy->set($collection, $uuid, $fields);
                    $touched = &$updated;
                } else {
                    $reply = $this->haproxy->add($collection, $fields);
                    $uuid = (string)($reply['uuid'] ?? '');
                    $touched = &$created;
                }
            } catch (ExposureException $e) {
                $sofar = \array_merge($created, $updated);
                throw $sofar === [] ? $e : self::afterWrites($e, self::savedClause($sofar, false));
            }
            if (($reply['result'] ?? '') !== 'saved' || $uuid === '') {
                $reasons = [];
                foreach ((array)($reply['validations'] ?? []) as $field => $message) {
                    $reasons[] = "$field: $message";
                }
                $sofar = \array_merge($created, $updated);
                throw new ExposureException(
                    'VALIDATION_FAILED',
                    "HAProxy refused the $collection object '$name'" .
                    ($reasons !== [] ? ' (' . \implode('; ', $reasons) . ')' : '') . '. ' .
                    ($sofar !== []
                        ? self::savedClause($sofar, false)
                        : 'Nothing was saved; the service was not reloaded. Fix the settings and Apply again, or Remove.')
                );
            }
            $touched[] = "$collection/$name";
            return $uuid;
        };

        try {
            $server = $upsert('servers', self::N_SERVER, [
                'enabled' => '1',
                'type' => 'static',
                'address' => '127.0.0.1',
                'port' => $this->backendPort(),
                'mode' => 'active',
                'ssl' => '1',
                // The web GUI usually presents a self-signed certificate; the
                // hop is loopback, so verification would only break setups.
                'sslVerify' => '0',
            ]);
            $backend = $upsert('backends', self::N_BACKEND, [
                'enabled' => '1',
                'mode' => 'http',
                'algorithm' => 'roundrobin',
                'linkedServers' => $server,
                // One local server: a health check would only add log noise.
                'healthCheckEnabled' => '0',
            ]);
            $aclPublic = $upsert('acls', self::N_ACL_PUBLIC, [
                'expression' => 'path_beg',
                'path_beg' => self::PUBLIC_PREFIX,
                'caseSensitive' => '1',
                'negate' => '0',
            ]);
            $aclPortal = $upsert('acls', self::N_ACL_PORTAL, [
                'expression' => 'path_beg',
                'path_beg' => self::PORTAL_PREFIX,
                'caseSensitive' => '1',
                'negate' => '0',
            ]);
            // The rewritten portal path starts with LOCAL_PREFIX too: one
            // routing ACL covers both the API and the portal.
            $aclLocal = $upsert('acls', self::N_ACL_LOCAL, [
                'expression' => 'path_beg',
                'path_beg' => self::LOCAL_PREFIX,
                'caseSensitive' => '1',
                'negate' => '0',
            ]);
            $aclFlood = $upsert('acls', self::N_ACL_FLOOD, [
                'expression' => 'src_http_req_rate',
                'src_http_req_rate_comparison' => 'gt',
                'src_http_req_rate' => (string)self::RATE_LIMIT_REQUESTS,
                'negate' => '0',
            ]);
            $actFlood = $upsert('actions', self::N_ACT_FLOOD, [
                'enabled' => '1',
                'type' => 'http-request',
                'http_request_action' => 'deny',
                'http_request_option' => 'deny_status ' . self::FLOOD_STATUS,
                'testType' => 'if',
                'linkedAcls' => $aclFlood,
                'operator' => 'and',
            ]);
            $actDeny = $upsert('actions', self::N_ACT_DENY, [
                'enabled' => '1',
                'type' => 'http-request',
                'http_request_action' => 'deny',
                'http_request_option' => 'deny_status ' . self::DENY_STATUS,
                'testType' => 'unless',
                // "unless public || portal": the allowed set, exhaustively.
                'linkedAcls' => $aclPublic . ',' . $aclPortal,
                'operator' => 'or',
            ]);
            $actRewrite = $upsert('actions', self::N_ACT_REWRITE, [
                'enabled' => '1',
                'type' => 'http-request',
                'http_request_action' => 'set-path',
                'http_request_option' => self::rewriteExpression(self::PUBLIC_PREFIX, self::LOCAL_PREFIX),
                'testType' => 'if',
                'linkedAcls' => $aclPublic,
                'operator' => 'and',
            ]);
            $actRewritePortal = $upsert('actions', self::N_ACT_REWRITE_PORTAL, [
                'enabled' => '1',
                'type' => 'http-request',
                'http_request_action' => 'set-path',
                'http_request_option' => self::rewriteExpression(self::PORTAL_PREFIX, self::PORTAL_LOCAL_PREFIX),
                'testType' => 'if',
                'linkedAcls' => $aclPortal,
                'operator' => 'and',
            ]);
            $actRoute = $upsert('actions', self::N_ACT_ROUTE, [
                'enabled' => '1',
                'type' => 'use_backend',
                'use_backend' => $backend,
                'testType' => 'if',
                'linkedAcls' => $aclLocal,
                'operator' => 'and',
            ]);
            $upsert('frontends', self::N_FRONTEND, [
                'enabled' => '1',
                'bind' => $this->bind,
                'mode' => 'http',
                'connectionBehaviour' => 'http-keep-alive',
                'ssl_enabled' => '1',
                'ssl_certificates' => $this->certificate,
                'ssl_default_certificate' => $this->certificate,
                // The template only renders ssl_minVersion and HSTS inside the
                // "advanced" block; without this flag both are silently dropped.
                'ssl_advancedEnabled' => '1',
                'ssl_minVersion' => self::TLS_MIN_VERSION,
                'ssl_hstsEnabled' => '1',
                'ssl_hstsMaxAge' => (string)self::HSTS_MAX_AGE_S,
                'forwardFor' => '1',
                'logging_detailedLog' => '1',
                // Slowloris guard: a client must send its request within 10 s.
                'tuning_timeoutHttpReq' => '10s',
                // ipv6 keys hold IPv4 sources too (mapped); a table of 10k
                // entries expiring after 10 idle minutes covers the rate window
                // many times over. Counter on `src` feeds src_http_req_rate.
                'stickiness_pattern' => 'ipv6',
                'stickiness_dataTypes' => 'http_req_rate',
                'stickiness_httpReqRatePeriod' => self::RATE_LIMIT_PERIOD,
                'stickiness_size' => '10k',
                'stickiness_expire' => '10m',
                'stickiness_counter' => '1',
                'stickiness_counter_key' => 'src',
                // HAProxy evaluates http-request rules in this order; the
                // use_backend one is a later stage whatever its position.
                'linkedActions' => \implode(',', [$actFlood, $actDeny, $actRewrite, $actRewritePortal, $actRoute]),
            ]);
        } catch (ExposureException $e) {
            $this->recordFailure($actorRef, 'exposure.apply', $e->getMessage(), [
                'created' => $created,
                'updated' => $updated,
            ]);
            throw $e;
        }

        $serviceEnabled = false;
        $saved = \array_merge($created, $updated);
        try {
            try {
                if (!$this->haproxy->serviceEnabled()) {
                    $this->haproxy->enableService();
                    $serviceEnabled = true;
                }
                $check = $this->haproxy->configtest();
            } catch (ExposureException $e) {
                throw self::afterWrites($e, self::savedClause($saved, $serviceEnabled));
            }
            if (self::configtestFailed($check)) {
                throw new ExposureException(
                    'VALIDATION_FAILED',
                    'HAProxy rejected the generated configuration: ' . self::alertLines($check) . '. ' .
                    self::savedClause($saved, $serviceEnabled)
                );
            }
            try {
                $reload = $this->haproxy->reconfigure();
            } catch (ExposureException $e) {
                throw self::afterWrites($e, self::liveUnknownClause($saved, $serviceEnabled));
            }
            if ($reload !== 'ok') {
                throw new ExposureException(
                    'INTERNAL',
                    'HAProxy did not reload after the configuration was saved. ' .
                    self::liveUnknownClause($saved, $serviceEnabled)
                );
            }
        } catch (ExposureException $e) {
            $this->recordFailure($actorRef, 'exposure.apply', $e->getMessage(), [
                'created' => $created,
                'updated' => $updated,
                'service_enabled' => $serviceEnabled,
            ]);
            throw $e;
        }

        $this->audit->record('admin', $actorRef, 'exposure.apply', 'exposure', 'haproxy', 'success', [
            'bind' => $this->bind,
            'certificate' => $this->certificate,
            'backend_port' => $this->backendPort(),
            'created' => $created,
            'updated' => $updated,
            'service_enabled' => $serviceEnabled,
        ]);
        return [
            'result' => 'applied',
            'created' => $created,
            'updated' => $updated,
            'service_enabled' => $serviceEnabled,
            'status' => $this->status(),
        ];
    }

    // --------------------------------------------------------------- remove

    /**
     * Delete every owned object (nothing else), reload, forget the
     * verification dates. The service's enabled flag is left as it is:
     * the admin's other frontends may depend on it. Harmless when nothing
     * is there.
     *
     * @param string $actorRef admin identity for the audit trail.
     * @return array<string, mixed> result: removed; removed: the
     *         collection/name list; status: status() afterwards.
     * @throws ExposureException EXPOSURE_UNAVAILABLE (API unreachable or
     *         refusing the API user — an absent plugin is NOT an error
     *         here: nothing to remove); INTERNAL when a deletion or the
     *         reload failed, or when the API's effect is unknown (timeout,
     *         non-JSON reply). Whatever the code, a failure after the
     *         first deletion lists what was removed and what stayed; every
     *         failure is audited with the removed list.
     */
    public function remove(string $actorRef): array
    {
        $removed = [];
        try {
            // A failure before the first deletion keeps the gateway's own
            // message: nothing was removed, and it says so.
            if ($this->haproxy->installed()) {
                $owned = $this->owned();
                foreach (self::REMOVE_ORDER as $collection) {
                    foreach ($owned[$collection] as $name => $row) {
                        try {
                            $reply = $this->haproxy->del($collection, (string)$row['uuid']);
                        } catch (ExposureException $e) {
                            throw $removed === [] ? $e : self::afterWrites($e, self::removedClause($removed));
                        }
                        if (($reply['result'] ?? '') !== 'deleted') {
                            throw new ExposureException(
                                'INTERNAL',
                                "HAProxy refused to delete the $collection object '$name' (" .
                                \json_encode($reply) . '). ' . self::removedClause($removed)
                            );
                        }
                        $removed[] = "$collection/$name";
                    }
                }
                if ($removed !== []) {
                    try {
                        $reload = $this->haproxy->reconfigure();
                    } catch (ExposureException $e) {
                        throw self::afterWrites($e, self::removedUnreloadedClause($removed));
                    }
                    if ($reload !== 'ok') {
                        throw new ExposureException(
                            'INTERNAL',
                            'HAProxy did not reload. ' . self::removedUnreloadedClause($removed)
                        );
                    }
                }
            }
        } catch (ExposureException $e) {
            $this->recordFailure($actorRef, 'exposure.remove', $e->getMessage(), ['removed' => $removed]);
            throw $e;
        }
        $this->metaDelete(self::META_VERIFIED_AT);
        $this->metaDelete(self::META_EXTERNAL_AT);
        $this->audit->record('admin', $actorRef, 'exposure.remove', 'exposure', 'haproxy', 'success', [
            'removed' => $removed,
        ]);
        return ['result' => 'removed', 'removed' => $removed, 'status' => $this->status()];
    }

    // --------------------------------------------------------------- verify

    /**
     * "Verify my configuration": probe the frontend from the firewall
     * with the real host name, inspect the certificate, record the date
     * when everything holds. Read-only toward HAProxy.
     *
     * @param string $actorRef admin identity for the audit trail.
     * @param bool $externalConfirmed the admin states the guided outside
     *        test succeeded; recorded with its date when the checks pass.
     * @return array<string, mixed> ok; checks: list of {id, label, path,
     *         expected, actual, ok}; certificate: inspection or null;
     *         external_test: {url, hint}; last_verified_at;
     *         external_confirmed_at.
     * @throws ExposureException EXPOSURE_UNAVAILABLE (plugin absent or
     *         unreachable, nothing listening on the bind), VALIDATION_FAILED
     *         (not applied, or no enrollment host to name); the probe never
     *         writes, so no message has an "in place" clause.
     */
    public function verify(string $actorRef, bool $externalConfirmed = false): array
    {
        $status = $this->status();
        if ($status['haproxy'] !== 'present') {
            throw new ExposureException(
                'EXPOSURE_UNAVAILABLE',
                ($status['haproxy'] === 'absent'
                    ? 'The os-haproxy plugin is not installed: there is no exposure to verify.'
                    : 'The HAProxy API cannot be reached: ' . (string)($status['error'] ?? '')) .
                ' Nothing was changed.'
            );
        }
        if ($status['mode'] !== 'haproxy') {
            throw new ExposureException(
                'VALIDATION_FAILED',
                'The exposure is not applied (internal-only mode): nothing to verify. Nothing was changed. ' .
                'Apply it first.'
            );
        }
        if ($this->enrollHost === '') {
            throw new ExposureException(
                'VALIDATION_FAILED',
                'Set the enrollment host first (Settings > Enrollment links): the verification must use the ' .
                'name devices will use. Nothing was changed.'
            );
        }

        [$address, $port] = self::parseBind($this->bind);
        $ip = self::isWildcard($address) ? '127.0.0.1' : \trim($address, '[]');
        $host = self::hostOf($this->enrollHost);
        $base = 'https://' . $host . ':' . $port;

        $checks = [];
        $pem = null;
        foreach (self::probes() as $probe) {
            $reply = $this->probe->fetch($base . $probe['path'], $host, $ip, $port);
            if ($pem === null && $reply['cert'] !== null) {
                $pem = $reply['cert'];
            }
            $ok = \in_array($reply['status'], $probe['expected'], true);
            if ($ok && $probe['id'] === 'policy') {
                // A 200 must be the plugin's policy, not a page of something else.
                $ok = \is_array(\json_decode($reply['body'], true));
            } elseif ($ok && $probe['id'] === 'portal') {
                // Likewise the portal: the plugin's page carries its config blob.
                $ok = \str_contains($reply['body'], 'paart-config');
            }
            $checks[] = [
                'id' => $probe['id'],
                'label' => $probe['label'],
                'path' => $probe['path'],
                'expected' => \implode(' or ', \array_map('strval', $probe['expected'])),
                'actual' => $reply['status'] === 0 ? 'no HTTP answer' : (string)$reply['status'],
                'ok' => $ok,
            ];
        }

        $certificate = $pem !== null ? self::inspectCertificate($pem, $host, $this->enrollPin) : null;
        $ok = $certificate !== null
            && $certificate['valid_now']
            && $certificate['matches_host']
            && $certificate['matches_pin'] !== false;
        foreach ($checks as $check) {
            $ok = $ok && $check['ok'];
        }

        $detail = [
            'ok' => $ok,
            'checks' => \array_column($checks, 'actual', 'id'),
            'certificate' => $certificate === null ? null : [
                'not_after' => $certificate['not_after'],
                'spki_sha256' => $certificate['spki_sha256'],
                'matches_host' => $certificate['matches_host'],
            ],
            'external_confirmed' => $externalConfirmed,
        ];
        if ($ok) {
            $now = Database::utcNow();
            $this->metaSet(self::META_VERIFIED_AT, $now);
            if ($externalConfirmed) {
                $this->metaSet(self::META_EXTERNAL_AT, $now);
            }
            $this->audit->record('admin', $actorRef, 'exposure.verify', 'exposure', 'haproxy', 'success', $detail);
        } else {
            $this->audit->record('admin', $actorRef, 'exposure.verify', 'exposure', 'haproxy', 'failure', $detail);
        }
        return [
            'ok' => $ok,
            'checks' => $checks,
            'certificate' => $certificate,
            'external_test' => [
                'url' => $this->externalTestUrl(),
                'hint' => 'Open this URL from a device outside your network (a phone on cellular data): a short ' .
                    'JSON policy must come back. Then replace the path with / — the page must be refused (403).',
            ],
            'last_verified_at' => $this->metaGet(self::META_VERIFIED_AT),
            'external_confirmed_at' => $this->metaGet(self::META_EXTERNAL_AT),
        ];
    }

    /**
     * The probes verify() runs, in order. Everything but the public
     * prefix must be refused with DENY_STATUS — including the plugin's
     * own local path, which is only reachable through the rewrite.
     *
     * @return array<int, array{id: string, label: string, path: string, expected: array<int, int>}>
     */
    private static function probes(): array
    {
        return [
            ['id' => 'policy', 'label' => 'Enrollment policy is served',
                'path' => self::PUBLIC_PREFIX . '/policy', 'expected' => [200]],
            ['id' => 'admin', 'label' => 'Admin API is refused',
                'path' => '/api/v1/admin/users', 'expected' => [self::DENY_STATUS]],
            ['id' => 'ui', 'label' => 'Web GUI is refused',
                'path' => '/ui/', 'expected' => [self::DENY_STATUS]],
            ['id' => 'device', 'label' => 'Device API is refused (tunnel only)',
                'path' => '/api/v1/device/bundle', 'expected' => [self::DENY_STATUS]],
            ['id' => 'core', 'label' => 'Core API is refused',
                'path' => '/api/core/firmware/status', 'expected' => [self::DENY_STATUS]],
            ['id' => 'local', 'label' => 'Only the public path is accepted',
                'path' => self::LOCAL_PREFIX . '/policy', 'expected' => [self::DENY_STATUS]],
            ['id' => 'portal', 'label' => 'Enrollment portal page is served',
                'path' => self::PORTAL_PREFIX, 'expected' => [200]],
        ];
    }

    /**
     * What the served certificate says, for the admin and for the pin
     * (ADR 0004). The SPKI SHA-256 is computed the way enrollment-link.md
     * prescribes (DER SubjectPublicKeyInfo, SHA-256, base64).
     *
     * @param string $pem the leaf certificate, PEM.
     * @param string $host the public enrollment host name (no port) the
     *        certificate must name; matched case-insensitively.
     * @param string $pin optional SPKI SHA-256 pin, standard base64 (ADR
     *        0004); '' = no pin configured, matches_pin then reads null.
     * @return ?array{subject: string, sans: array<int, string>, not_before: string,
     *         not_after: string, valid_now: bool, days_left: int, spki_sha256: string,
     *         matches_host: bool, matches_pin: ?bool} null when unparsable.
     */
    public static function inspectCertificate(string $pem, string $host, string $pin = ''): ?array
    {
        $parsed = @\openssl_x509_parse($pem);
        if (!\is_array($parsed)) {
            return null;
        }
        $sans = [];
        foreach (\explode(',', (string)($parsed['extensions']['subjectAltName'] ?? '')) as $entry) {
            $entry = \trim($entry);
            if (\str_starts_with($entry, 'DNS:')) {
                $sans[] = \strtolower(\substr($entry, 4));
            } elseif (\str_starts_with($entry, 'IP Address:')) {
                $sans[] = \substr($entry, 11);
            }
        }
        $cn = \strtolower((string)($parsed['subject']['CN'] ?? ''));
        $now = \time();
        $from = (int)($parsed['validFrom_time_t'] ?? 0);
        $to = (int)($parsed['validTo_time_t'] ?? 0);

        $spki = '';
        $key = @\openssl_pkey_get_public($pem);
        if ($key !== false) {
            $details = \openssl_pkey_get_details($key);
            $der = \base64_decode(\preg_replace('/-----[^-]+-----|\s/', '', (string)($details['key'] ?? '')) ?? '', true);
            if ($der !== false && $der !== '') {
                $spki = \base64_encode(\hash('sha256', $der, true));
            }
        }
        $names = $sans !== [] ? $sans : ($cn !== '' ? [$cn] : []);
        return [
            'subject' => (string)($parsed['name'] ?? ''),
            'sans' => $sans,
            'not_before' => \gmdate('Y-m-d\TH:i:s\Z', $from),
            'not_after' => \gmdate('Y-m-d\TH:i:s\Z', $to),
            'valid_now' => $from <= $now && $now <= $to,
            'days_left' => \intdiv($to - $now, 86400),
            'spki_sha256' => $spki,
            'matches_host' => self::nameMatches(\strtolower($host), $names),
            'matches_pin' => $pin === '' ? null : \hash_equals($pin, $spki),
        ];
    }

    // -------------------------------------------------------------- helpers

    /** @throws ExposureException VALIDATION_FAILED on a malformed bind or a missing certificate. */
    private function requireInputs(): void
    {
        if (
            !\preg_match('/^(\*|[0-9A-Za-z.\-]+|\[[0-9A-Fa-f:.]+\])?:([0-9]{1,5})$/', $this->bind, $m)
            || (int)$m[2] < 1 || (int)$m[2] > 65535
        ) {
            throw new ExposureException(
                'VALIDATION_FAILED',
                "The exposure bind '{$this->bind}' is not address:port (e.g. 0.0.0.0:443). Nothing was changed."
            );
        }
        if ($this->certificate === '') {
            throw new ExposureException(
                'VALIDATION_FAILED',
                'Choose the certificate the public endpoint will present (Settings > Public exposure) and save, ' .
                'then Apply. Nothing was changed.'
            );
        }
    }

    /**
     * Refuse when the bind port is already taken — by the web GUI (it
     * listens on every address) or by another, enabled frontend on an
     * overlapping address. Foreign frontends are read, never written.
     *
     * @throws ExposureException EXPOSURE_CONFLICT; EXPOSURE_UNAVAILABLE /
     *         INTERNAL propagated from the gateway reads (nothing written).
     */
    private function refuseConflicts(): void
    {
        [$address, $port] = self::parseBind($this->bind);
        if ($port === (int)$this->backendPort()) {
            throw new ExposureException(
                'EXPOSURE_CONFLICT',
                "The web GUI itself listens on port $port on every address, so HAProxy cannot bind it. " .
                'Move the GUI port (System > Settings > Administration) or bind the exposure elsewhere. ' .
                'Nothing was changed.'
            );
        }
        foreach ($this->haproxy->search('frontends') as $row) {
            $name = (string)($row['name'] ?? '');
            if (\str_starts_with($name, self::PREFIX) || (string)($row['enabled'] ?? '1') !== '1') {
                continue;
            }
            $node = $this->haproxy->get('frontends', (string)$row['uuid']);
            foreach (self::bindList($node['bind'] ?? '') as $bind) {
                [$otherAddress, $otherPort] = self::parseBind($bind);
                if ($otherPort !== $port) {
                    continue;
                }
                if (self::isWildcard($address) || self::isWildcard($otherAddress) || $otherAddress === $address) {
                    throw new ExposureException(
                        'EXPOSURE_CONFLICT',
                        "The HAProxy frontend '$name' already binds " . \trim($bind) . '. The plugin never ' .
                        'modifies a frontend it did not create: change the exposure bind (Settings > Public ' .
                        'exposure), or move that frontend. Nothing was changed.'
                    );
                }
            }
        }
    }

    /**
     * Objects present on the HAProxy side that carry the prefix — the
     * ownership rule, whatever follows the prefix: a hand-made paart_*
     * object counts as ours (listed by status(), deleted by remove()).
     *
     * @return array<string, array<string, array<string, mixed>>> collection => name => search row.
     */
    private function owned(): array
    {
        $owned = [];
        foreach (self::OWNED as $collection => $names) {
            $owned[$collection] = [];
            foreach ($this->haproxy->search($collection) as $row) {
                $name = (string)($row['name'] ?? '');
                if (\str_starts_with($name, self::PREFIX)) {
                    $owned[$collection][$name] = $row;
                }
            }
        }
        return $owned;
    }

    /** @return array<int, string> every expected collection/name. */
    private static function ownedList(): array
    {
        $list = [];
        foreach (self::OWNED as $collection => $names) {
            foreach ($names as $name) {
                $list[] = "$collection/$name";
            }
        }
        return $list;
    }

    /** The HAProxy set-path expression turning one public prefix into its local one. */
    private static function rewriteExpression(string $publicPrefix, string $localPrefix): string
    {
        return '%[path,regsub(^' . $publicPrefix . ',' . $localPrefix . ')]';
    }

    /** Web GUI port the backend targets; the setting's '' means the default 443. */
    private function backendPort(): string
    {
        return $this->controlPort !== '' ? $this->controlPort : '443';
    }

    /** The policy URL as the Internet sees it — the guided outside test; '' without a host. */
    private function externalTestUrl(): string
    {
        return $this->enrollHost === '' ? '' : 'https://' . $this->enrollHost . self::PUBLIC_PREFIX . '/policy';
    }

    /**
     * `address:port` split; the address keeps its brackets for IPv6.
     * Non-TCP binds (unix@, quic4@) yield port 0 and never conflict.
     *
     * @return array{0: string, 1: int}
     */
    private static function parseBind(string $bind): array
    {
        if (\str_contains($bind, '@')) {
            return [$bind, 0];
        }
        $pos = \strrpos($bind, ':');
        if ($pos === false) {
            return [$bind, 0];
        }
        return [\substr($bind, 0, $pos), (int)\substr($bind, $pos + 1)];
    }

    /**
     * A frontend's bind entries as get() serves them: the core renders a
     * CSVListField as an option map ({entry: {value, selected}}, verified
     * on the 26.1 target — the fake mirrors it); a plain comma-separated
     * string is accepted too, should a core version serve one. Both read
     * the same.
     *
     * @param mixed $bind the node's bind field.
     * @return array<int, string>
     */
    private static function bindList($bind): array
    {
        if (\is_array($bind)) {
            $entries = [];
            foreach ($bind as $entry => $option) {
                if (!\is_array($option) || (int)($option['selected'] ?? 1) === 1) {
                    $entries[] = \trim((string)$entry);
                }
            }
            return $entries;
        }
        return \array_values(\array_filter(\array_map('trim', \explode(',', (string)$bind)), 'strlen'));
    }

    /** Whether a bind address means "every address" — such a bind conflicts with any port-equal one. */
    private static function isWildcard(string $address): bool
    {
        return \in_array($address, ['', '*', '0.0.0.0', '::', '[::]'], true);
    }

    /** host[:port] → host (brackets kept for a literal IPv6). */
    private static function hostOf(string $enrollHost): string
    {
        if (\str_starts_with($enrollHost, '[')) {
            $end = \strpos($enrollHost, ']');
            return $end === false ? $enrollHost : \substr($enrollHost, 0, $end + 1);
        }
        $pos = \strpos($enrollHost, ':');
        return $pos === false ? $enrollHost : \substr($enrollHost, 0, $pos);
    }

    /** @param array<int, string> $names lowercase SAN/CN entries, `*.` wildcards honoured one label deep. */
    private static function nameMatches(string $host, array $names): bool
    {
        foreach ($names as $name) {
            if ($name === $host) {
                return true;
            }
            if (\str_starts_with($name, '*.')) {
                $suffix = \substr($name, 1);
                $dot = \strpos($host, '.');
                if ($dot !== false && \substr($host, $dot) === $suffix) {
                    return true;
                }
            }
        }
        return false;
    }

    /** `haproxy -c` reports problems as [ALERT] lines; warnings are not failures. */
    private static function configtestFailed(string $output): bool
    {
        return \stripos($output, 'ALERT') !== false;
    }

    /** The first three ALERT lines, joined — the rest of the output is noise for the admin. */
    private static function alertLines(string $output): string
    {
        $alerts = [];
        foreach (\preg_split('/\r?\n/', $output) ?: [] as $line) {
            if (\stripos($line, 'ALERT') !== false) {
                $alerts[] = \trim($line);
            }
        }
        return $alerts === [] ? \trim($output) : \implode(' | ', \array_slice($alerts, 0, 3));
    }

    /**
     * Audit a refused or failed admin act with its message as the reason.
     *
     * @param array<string, mixed> $detail what the act had done so far (created/updated/removed lists).
     */
    private function recordFailure(string $actorRef, string $action, string $reason, array $detail = []): void
    {
        $this->audit->record('admin', $actorRef, $action, 'exposure', 'haproxy', 'failure', $detail + [
            'reason' => $reason,
        ]);
    }

    /**
     * The gateway speaks for its own call only ("nothing was changed by
     * this call"); when that call failed after earlier writes of the same
     * apply() or remove(), the admin must also hear what those writes
     * left in place. Same code, the gateway's reason first, then the clause.
     */
    private static function afterWrites(ExposureException $e, string $clause): ExposureException
    {
        return new ExposureException($e->apiCode(), $e->getMessage() . ' ' . $clause);
    }

    /**
     * apply() stopped with objects saved and no reload: what stays, and
     * whether this call switched the service on (never switched back).
     *
     * @param array<int, string> $saved collection/name list.
     */
    private static function savedClause(array $saved, bool $serviceEnabled): string
    {
        return 'The objects saved (' . \implode(', ', $saved) . ') are left in place' .
            ($serviceEnabled ? ', the service was switched on by this call and stays on' : '') .
            '; the service was not reloaded, so the running configuration is unchanged. ' .
            'Fix the cause and Apply again, or Remove.';
    }

    /**
     * apply() saved everything but the reload failed or its outcome is unknown.
     *
     * @param array<int, string> $saved collection/name list.
     */
    private static function liveUnknownClause(array $saved, bool $serviceEnabled): string
    {
        return 'The objects are saved (' . \implode(', ', $saved) . ')' .
            ($serviceEnabled ? ' and the service was switched on by this call (it stays on)' : '') .
            '; whether the exposure is live is unknown — check Services > HAProxy > Log, ' .
            'then Verify or Apply again.';
    }

    /**
     * remove() stopped midway: what went, what stayed.
     *
     * @param array<int, string> $removed collection/name list.
     */
    private static function removedClause(array $removed): string
    {
        return ($removed !== []
                ? 'Already removed: ' . \implode(', ', $removed) . '; '
                : 'Nothing was removed; ') .
            'the remaining paart_ objects are left in place and the service was not reloaded. ' .
            'Delete them from Services > HAProxy if needed, or Remove again.';
    }

    /**
     * remove() deleted its objects but HAProxy did not (verifiably) reload.
     *
     * @param array<int, string> $removed collection/name list.
     */
    private static function removedUnreloadedClause(array $removed): string
    {
        return 'The exposure objects were removed from the configuration (' . \implode(', ', $removed) .
            ') but the running service may still serve the old configuration — check Services > HAProxy.';
    }

    /** Meta table read; null when the key is absent. */
    private function metaGet(string $key): ?string
    {
        $value = $this->db->scalar('SELECT value FROM meta WHERE key = :k', [':k' => $key]);
        return $value === null || $value === false ? null : (string)$value;
    }

    /** Meta table upsert, stamped with the UTC time. */
    private function metaSet(string $key, string $value): void
    {
        $this->db->run(
            'INSERT OR REPLACE INTO meta (key, value, updated_at) VALUES (:k, :v, :now)',
            [':k' => $key, ':v' => $value, ':now' => Database::utcNow()]
        );
    }

    /** Meta table delete; harmless when the key is absent. */
    private function metaDelete(string $key): void
    {
        $this->db->run('DELETE FROM meta WHERE key = :k', [':k' => $key]);
    }
}
