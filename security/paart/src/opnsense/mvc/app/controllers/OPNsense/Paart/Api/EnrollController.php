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
 * Public enrollment API (M04): the plugin's ONLY anonymous controller —
 * forbidden rule #7 caps the public surface at the enrollment routes, and
 * this file is that whole surface, portal page included:
 *
 *   POST /api/paart/enroll                (indexAction)  — enroll, or rekey (ADR 0006);
 *   GET  /api/paart/enroll/policy         (policyAction) — pre-enrollment constraints;
 *   GET  /api/paart/enroll/portal         (portalAction) — the M15 portal page;
 *   POST /api/paart/enroll/portal/submit  (portalAction) — the portal's submission.
 *
 * M09 maps the canonical public paths /api/v1/enroll[/policy] and
 * /enroll/[submit] (ADR 0008) onto these routes at the exposure layer; on
 * the LAN they are reachable as-is (the legitimate no-exposure mode, M09).
 *
 * Auth: beforeExecuteRoute is overridden to skip session/key auth and the
 * CSRF check (the upstream captive-portal pattern) — the enrollment token
 * inside the body IS the credential, validated uniformly by the service
 * (invalid, expired and consumed are indistinguishable, M04). Everything
 * else stays out of anonymous reach by not existing here: these routes
 * read nothing beyond what the submitted token's own bundle needs.
 *
 * Request handling owned here per the service contract: 32 KB body cap
 * (PAYLOAD_TOO_LARGE, M01), contract fields whitelisted
 * (additionalProperties: false — the portal's 'manual' management_level
 * is set by the portal route, never client-supplied), source IP resolved
 * for the audit and rate-limit key, bundle assembly (Enroll\Bundles) with
 * the server facts prefetched so a firewall failure never strands a
 * consumed token. App and portal submissions share enrollAndBundle():
 * the same validation, the same uniform refusals, the same audit.
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Paart\App\Container;
use OPNsense\Paart\Domain\Devices;
use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Enroll\Portal;

class EnrollController extends ApiControllerBase
{
    use ContractTrait;

    /** Contract limit on the /enroll request body (M01/M04). */
    private const MAX_BODY_BYTES = 32768;
    /** EnrollRequest fields (additionalProperties: false in the contract). */
    private const REQUEST_FIELDS = ['token', 'public_key', 'device_name', 'platform', 'attestation'];

    /**
     * Anonymous surface: deliberately empty — the base implementation
     * would 401 a caller without a session or API key, and enrollment
     * happens before either can exist. The body's enrollment token is the
     * credential (M04); skipping the base also skips its CSRF check,
     * which only protects session-authenticated requests.
     */
    public function beforeExecuteRoute($dispatcher)
    {
    }

    /**
     * POST /api/paart/enroll — the public enrollment submission (M01).
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function indexAction()
    {
        return $this->contract(function () {
            if (!$this->request->isPost()) {
                $this->badRoute();
            }
            return $this->enrollAndBundle($this->enrollBody());
        });
    }

    /**
     * The M15 portal: GET /api/paart/enroll/portal serves the page, POST
     * /api/paart/enroll/portal/submit takes its submission (publicly
     * /enroll/ and /enroll/submit, rewritten by M09). The page is the
     * same bytes for everyone (Enroll\Portal); the submission is the app's
     * enrollment with management_level forced to 'manual' — a downloaded
     * .conf cannot self-rotate (M05) — and the device token withheld
     * (Portal::response()). Any other path element is a 404 and any other
     * method on the page a 405, both with an empty body: the anonymous
     * surface answers nothing it does not own (the submission's own
     * method check goes through the contract envelope, like the app's).
     *
     * @param string|null $step path element after /portal ('submit' or none).
     * @return string|null the HTML page (or an empty body on a refused
     *         route); null once contract() has written the submission JSON.
     */
    public function portalAction($step = null)
    {
        if ($step === Portal::SUBMIT_STEP) {
            return $this->contract(function () {
                if (!$this->request->isPost()) {
                    $this->badRoute();
                }
                $req = $this->enrollBody();
                $req['management_level'] = 'manual';
                return Portal::response($this->enrollAndBundle($req));
            });
        }
        if ($step !== null && $step !== '') {
            $this->response->setStatusCode(404);
            return '';
        }
        if (!$this->request->isGet()) {
            $this->response->setStatusCode(405);
            return '';
        }
        // Headers the page relies on: no caching of a page whose fragment
        // carries a token, no framing, no referrer leaking the URL, and a
        // CSP that admits nothing but the inlined scripts and same-origin
        // fetches (the page carries the same policy as a meta tag).
        $this->response->setContentType('text/html', 'UTF-8');
        $this->response->setHeader('Cache-Control', 'no-store');
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');
        $this->response->setHeader('X-Frame-Options', 'DENY');
        $this->response->setHeader('Referrer-Policy', 'no-referrer');
        $this->response->setHeader(
            'Content-Security-Policy',
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " .
            "img-src data: blob:; connect-src 'self'; form-action 'none'; base-uri 'none'"
        );
        try {
            return $this->paart()->portal->render();
        } catch (\Throwable $e) {
            // A missing asset is a packaging defect: say so in the log, not
            // to the visitor, who gets a page-less 500.
            \openlog('paart', LOG_PID, LOG_USER);
            \syslog(LOG_ERR, 'portal page could not be rendered: ' . $e->getMessage());
            $this->response->setStatusCode(500);
            return '';
        }
    }

    /**
     * GET /api/paart/enroll/policy — public pre-enrollment constraints (M01).
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function policyAction()
    {
        return $this->contract(fn() => [
            'api_version' => (int)Container::API_VERSION,
            // Mirrors the contract's EnrollRequest.device_name maxLength.
            'device_name' => ['max_length' => Container::DEVICE_NAME_MAX_LENGTH],
            'platforms' => Devices::PLATFORMS,
            // v1 never verifies attestations (App Attest verification is
            // backlogged); announced honestly rather than promised.
            'attestation' => 'ignore',
        ]);
    }

    // -------------------------------------------------------------- helpers

    /**
     * One enrollment, app or portal: prefetch, enroll, assemble.
     *
     * The server facts the bundle needs are fetched FIRST: if the firewall
     * API is not reachable now, the refusal is retryable and nothing is
     * consumed — a failure after enroll() would strand a completed
     * enrollment without its config. An invalid token falls through:
     * enroll() re-validates and produces the audited uniform rejection
     * that feeds the rate limiter.
     *
     * @param array<string, mixed> $req whitelisted EnrollRequest body,
     *        plus management_level when the portal route sets it.
     * @return array<string, mixed> Bundles::response() payload.
     * @throws DomainException as EnrollmentService::enroll() and
     *         Bundles::serverForToken() do.
     */
    private function enrollAndBundle(array $req): array
    {
        $c = $this->paart();
        $server = null;
        try {
            $server = $c->bundles->serverForToken(
                $c->enrollTokens->validate((string)($req['token'] ?? ''))
            );
        } catch (DomainException $e) {
            if ($e->apiCode() !== 'ENROLLMENT_REJECTED') {
                throw $e; // PROVISIONING_UNAVAILABLE / NOT_FOUND — nothing consumed
            }
        }
        $out = $c->enrollment->enroll($req, $this->sourceIp());
        // enroll() accepting the token implies the prefetch validated it
        // too; the null branch is defensive only.
        $server ??= $c->bundles->serverForInstance((string)$out['device']['instance_id']);
        return $c->bundles->response($out, $server);
    }

    /**
     * The whitelisted EnrollRequest body. 'attestation' is accepted and
     * dropped (policy 'ignore'); field-level validation stays in the
     * service layer so app and portal submissions are refused identically.
     *
     * @return array<string, mixed>
     * @throws DomainException PAYLOAD_TOO_LARGE | VALIDATION_FAILED.
     */
    private function enrollBody(): array
    {
        $raw = (string)$this->request->getRawBody();
        if (\strlen($raw) > self::MAX_BODY_BYTES) {
            throw new DomainException('PAYLOAD_TOO_LARGE', 'Request body too large. Nothing was changed.');
        }
        $body = $this->jsonBody();
        // additionalProperties: false — names are not echoed back: the
        // response never reflects attacker-controlled content.
        if (\array_diff(\array_keys($body), self::REQUEST_FIELDS) !== []) {
            throw new DomainException(
                'VALIDATION_FAILED',
                'The request body carries an unexpected field. Nothing was changed.'
            );
        }
        unset($body['attestation']);
        return $body;
    }

    /**
     * Audit and rate-limit key (M04/M07). Behind the M09 frontal every
     * request reaches this server from loopback, so the forwarded address
     * is honored ONLY then — a direct (LAN) caller must never spoof its
     * way around the per-IP limit with a forged X-Forwarded-For.
     */
    private function sourceIp(): string
    {
        $address = (string)$this->request->getClientAddress();
        if (\in_array($address, ['127.0.0.1', '::1'], true)) {
            $forwarded = \trim(\explode(',', (string)$this->request->getHeader('X-Forwarded-For'))[0]);
            if ($forwarded !== '') {
                return $forwarded;
            }
        }
        return $address !== '' ? $address : 'unknown';
    }
}
