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
 * Transport toward the os-haproxy plugin's own API (M09). The plugin
 * never writes haproxy.conf: every object it needs (server, backend,
 * ACLs, actions, frontend) goes through the HAProxy model, exactly as
 * the admin's own objects do, so the two coexist in config.xml and the
 * template renders them together. Collections are the model's ArrayField
 * names: frontends, backends, servers, acls, actions.
 *
 * Implementations are transport only — no naming rule, no ownership
 * check: ExposureService decides what to touch (the paart_ prefix) and
 * this layer only carries the calls. Every method throws
 * ExposureException EXPOSURE_UNAVAILABLE when the API cannot be reached
 * or refuses the caller (absent plugin, privileges), INTERNAL when the
 * effect of a call is unknown (timeout, non-JSON reply) — and, for
 * enableService() alone, when the API refuses a change that carries no
 * input to fix. installed() is the exception: a refusal still proves
 * the plugin is there, so it answers true and only throws when the API
 * is unreachable (or INTERNAL on a timeout). Messages speak for the
 * failing call only ("nothing was changed by this call");
 * ExposureService adds what earlier calls of the same operation left in
 * place.
 */

namespace OPNsense\Paart\Exposure;

interface HaproxyGateway
{
    /**
     * Whether os-haproxy is installed on this firewall — the plugin never
     * installs it (M09). An installed plugin may still be disabled or
     * stopped; see serviceStatus() and serviceEnabled().
     */
    public function installed(): bool;

    /**
     * Rows of one collection, as the plugin's own grids see them: at least
     * uuid and name (frontends/backends/actions/servers also carry
     * enabled). Never the full node — use get() for that.
     *
     * @return array<int, array<string, mixed>>
     */
    public function search(string $collection): array;

    /**
     * One node in full, form-shaped: scalar fields as strings, list
     * fields as option maps. The caller only reads the fields it needs.
     *
     * @return array<string, mixed>
     */
    public function get(string $collection, string $uuid): array;

    /**
     * Create one node. Returns the API payload verbatim: {result: saved,
     * uuid} or {result: failed, validations: {field: message}} — the
     * caller decides how a refusal is reported.
     *
     * @param array<string, string> $fields
     * @return array<string, mixed>
     */
    public function add(string $collection, array $fields): array;

    /**
     * Update the given fields of one node (others keep their value).
     *
     * @param array<string, string> $fields
     * @return array<string, mixed> {result: saved} or the validation shape.
     */
    public function set(string $collection, string $uuid, array $fields): array;

    /** @return array<string, mixed> {result: deleted} or {result: not found}. */
    public function del(string $collection, string $uuid): array;

    /** Whether the HAProxy service is enabled in its general settings. */
    public function serviceEnabled(): bool;

    /** Turn the service on in its general settings (does not start it). */
    public function enableService(): void;

    /** 'running' | 'stopped' | 'disabled' | other core status strings. */
    public function serviceStatus(): string;

    /**
     * Render the staged configuration and run `haproxy -c` on it. Returns
     * the raw check output; the caller looks for HAProxy's ALERT lines.
     */
    public function configtest(): string;

    /**
     * Render and (re)load the live configuration. Returns the core status
     * string ('ok' on success, 'failed' otherwise).
     */
    public function reconfigure(): string;
}
