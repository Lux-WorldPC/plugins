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
 * Shared plumbing for the plugin's API controllers (M08): one composition
 * root per request (App\Container built from the config.xml model), and
 * the contract() wrapper that turns library exceptions into the uniform
 * M01 error envelope with the registry's HTTP status — controllers never
 * leak a raw exception or invent a code. Every response served through
 * contract(), success or error, carries the X-Paart-Api-Version /
 * X-Paart-Version headers; the native grid routes (searchNetwork,
 * getNetwork) are framework UI plumbing outside the contract and skip
 * both the headers and the envelope.
 *
 * contract() also writes the JSON itself, marked SAFE. The core's
 * ApiControllerBase::afterExecuteRoute() otherwise runs every array it
 * serialises through htmlspecialchars() unless the request carries an
 * Authorization header (API key): a defence for core pages that inject
 * API data as HTML. Our consumers never do — the app and the portal page
 * parse JSON, the volts render through .text() — and that escaping
 * turned "&" into "&amp;" inside links (enroll_link, portal_link) and
 * labels for every browser session and for the anonymous enrollment
 * surface. The exception is the grid feeds (searchDevice, searchUser,
 * searchEntry — and searchNetwork, which never goes through contract()):
 * the core's default cell formatter injects values as HTML with "no
 * sanitization" (opnsense_bootgrid.js), so those three pass safe=false
 * and stay escaped by the core, exactly as the core's own grids are. The
 * volts decode those rows before reusing them in dialogs (htmlDecode)
 * and escape explicitly where a dialog title is HTML. Unexpected
 * throwables are logged to syslog (class, route without query string,
 * message, file:line) before the INTERNAL envelope goes out. Also hosts
 * the request-reading helpers shared by the hand-written grid feeds of
 * the SQLite-backed screens (jsonBody, queryParam, gridParam, gridSort).
 */

namespace OPNsense\Paart\Api;

use OPNsense\Paart\Admin\HttpError;
use OPNsense\Paart\App\Container;
use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Store\StoreException;
use OPNsense\Paart\Paart;

trait ContractTrait
{
    private ?Container $paartContainer = null;

    /** The production service graph, wired once per request. */
    protected function paart(): Container
    {
        if ($this->paartContainer === null) {
            $settings = (new Paart())->libSettings();
            $this->paartContainer = new Container(
                $settings,
                Container::gatewayFromSettings($settings)
            );
        }
        return $this->paartContainer;
    }

    /**
     * Run one contract operation: version headers always, library
     * exceptions mapped onto the M01 envelope and status. DomainException
     * covers ProvisionException (it extends it). Anything else becomes the
     * INTERNAL envelope after being written to the system log.
     *
     * @param callable(): array<string, mixed> $op
     * @param bool $safe true (default): the payload is written here as
     *        safe, unescaped JSON and null is returned so the base class
     *        leaves the response alone. false: the payload is returned
     *        for the base class to serialise — HTML-escaped for a browser
     *        session — which is what a bootgrid feed needs (see header).
     * @return array<string, mixed>|null null when $safe, else the payload.
     */
    protected function contract(callable $op, bool $safe = true)
    {
        $payload = $this->contractPayload($op);
        if (!$safe) {
            return $payload;
        }
        $this->response->setContentType('application/json', 'UTF-8');
        $this->response->setContent($payload, true);
        return null;
    }

    /**
     * The contract payload: the operation's result, or the M01 envelope
     * for a mapped exception (status set on the way).
     *
     * @param callable(): array<string, mixed> $op
     * @return array<string, mixed>
     */
    private function contractPayload(callable $op): array
    {
        $this->response->setHeader('X-Paart-Api-Version', Container::API_VERSION);
        $this->response->setHeader('X-Paart-Version', Container::PLUGIN_VERSION);
        try {
            return $op();
        } catch (DomainException $e) {
            $this->response->setStatusCode(HttpError::status($e->apiCode()));
            return HttpError::envelope($e->apiCode(), $e->getMessage());
        } catch (StoreException $e) {
            $this->response->setStatusCode(HttpError::status($e->apiCode()));
            return HttpError::envelope($e->apiCode(), $e->getMessage());
        } catch (\Throwable $e) {
            // M08 rule: every error states whether a change was applied. An
            // unexpected failure is the one case where we cannot know. The
            // envelope hides the exception from the caller, so log it here —
            // otherwise "Check the system log" points at an empty log. The
            // query string is stripped: URLs may carry secrets, logs must not.
            // The paart program name routes the line to /var/log/paart/ (M10).
            \openlog('paart', LOG_PID, LOG_USER);
            \syslog(LOG_ERR, \sprintf(
                'unexpected %s on %s: %s (%s:%d)',
                \get_class($e),
                \strtok((string)$this->request->getURI(), '?'),
                $e->getMessage(),
                $e->getFile(),
                $e->getLine()
            ));
            $this->response->setStatusCode(500);
            return HttpError::envelope(
                'INTERNAL',
                'Unexpected failure; whether a change was applied is unknown. Check the system log.'
            );
        }
    }

    /** Authenticated admin identity for the audit trail (session or API key). */
    protected function contractActor(): string
    {
        $name = \method_exists($this, 'getUserName') ? (string)$this->getUserName() : '';
        return $name !== '' ? $name : 'admin';
    }

    /**
     * Contract operations take JSON bodies; form-encoded POST is accepted
     * as a fallback for the UI's convenience. The fallback reads the parsed
     * $_POST, so it also catches a body the client sent with the wrong
     * content type — and an empty JSON object ({}) falls through to it,
     * which is harmless: an empty $_POST yields the same empty array.
     *
     * @return array<string, mixed>
     */
    protected function jsonBody(): array
    {
        $body = $this->request->getJsonRawBody(true);
        if (\is_array($body) && $body !== []) {
            return $body;
        }
        $post = $this->request->getPost();
        return \is_array($post) ? $post : [];
    }

    /** One query-string parameter; null when absent or empty. */
    protected function queryParam(string $name): ?string
    {
        $value = $this->request->getQuery($name, null, null);
        return \is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * One bootgrid request parameter (POST body, query-string fallback) —
     * shared by the hand-written grid feeds of the SQLite-backed screens
     * (Users, Devices, Audit — Enrollment serves a single overview, no grid).
     *
     * The 26.1 grid (Tabulator behind UIBootgrid) posts its request as a
     * JSON document in which `current` and `rowCount` are NUMBERS, while
     * the filters stay strings. A string-only read silently dropped both
     * to their defaults — every page rendered page one, and "50 per page"
     * served 25, under a footer that claimed otherwise (found on the
     * Audit screen, the first grid to exceed one page). So
     * numbers are stringified here; anything else non-string (array,
     * bool, null) reads as absent.
     *
     * @param string $name bootgrid parameter name.
     * @param string $default returned when the parameter is absent or
     *                        empty — callers pass the grid's own default
     *                        ('1' for current, '25' for rowCount).
     * @return string the parameter value, never trimmed.
     */
    protected function gridParam(string $name, string $default = ''): string
    {
        $value = self::scalarString($this->request->getPost($name, null, null));
        if ($value === '') {
            $value = self::scalarString($this->request->getQuery($name, null, null));
        }
        return $value !== '' ? $value : $default;
    }

    /** A string or number as string; every other type reads as absent. */
    private static function scalarString($value): string
    {
        if (\is_int($value) || \is_float($value)) {
            return (string)$value;
        }
        return \is_string($value) ? $value : '';
    }

    /**
     * The bootgrid sort request as one column/direction pair.
     *
     * Bootgrid sends its order as `sort[<column>]=asc|desc` — a map, even
     * though the grids are single-sort; only the first entry is read, and
     * a second one is dropped rather than silently half-applied. Nothing
     * here is trusted: both halves go to GridSort, which refuses any
     * column outside the feed's whitelist.
     *
     * @return array{0: string, 1: string} column and direction, both ''
     *         when no usable sort was asked for.
     */
    protected function gridSort(): array
    {
        $sort = $this->request->getPost('sort', null, null);
        if (!\is_array($sort)) {
            $sort = $this->request->getQuery('sort', null, null);
        }
        if (!\is_array($sort) || $sort === []) {
            return ['', ''];
        }
        $column = (string)\array_key_first($sort);
        $direction = $sort[$column];
        return [$column, \is_string($direction) ? $direction : ''];
    }

    /** @throws DomainException always — unmatched route inside an action. */
    protected function badRoute(): void
    {
        throw new DomainException(
            'VALIDATION_FAILED',
            'Unsupported method or path for this endpoint. Nothing was changed.'
        );
    }
}
