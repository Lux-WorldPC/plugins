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
 * Read-only projection for the M08 Enrollment screen — OFF-contract screen
 * plumbing, like the Users, Devices and Dashboard feeds. One call carries
 * the whole screen: the two pickers the issue form needs (active users,
 * declared networks), the active tokens with the names behind their ULIDs,
 * and the server clock the countdown is anchored to.
 *
 * Never touches the firewall. Issuing a token provisions nothing and both
 * pickers read the store, so — unlike the Users screen, whose issue dialog
 * fills its network list from AdminService::health() — this screen costs
 * neither a reachability probe nor a reconciliation pass, and stays usable
 * while the firewall is down. Completing an enrollment still needs it;
 * handing someone a QR code ahead of time does not.
 *
 * The countdown is anchored on the server clock: the payload carries 'now'
 * next to every 'expires_at', so a browser whose clock drifts still shows
 * the time the firewall will actually honour.
 *
 * No token secret is ever listed here: only the issuance response carries
 * the plaintext, once (M04 — the store keeps hashes only).
 *
 * This class NEVER writes — the screen's writes (issue, revoke) call the
 * recetted /api/paart/admin/tokens contract routes.
 */

namespace OPNsense\Paart\Admin;

use OPNsense\Paart\Store\Database;

final class EnrollmentScreen
{
    private AdminService $admin;
    private Database $db;
    private string $enrollHost;

    /**
     * @param AdminService $admin contract façade — the token list comes
     *        from its recetted payloads, not from a second query.
     * @param Database $db store handle, for the names the payloads carry
     *        only as ULIDs and for the two pickers.
     * @param string $enrollHost the configured enrollment host, '' when
     *        unset — issuance refuses without it (see overview()).
     */
    public function __construct(AdminService $admin, Database $db, string $enrollHost)
    {
        $this->admin = $admin;
        $this->db = $db;
        $this->enrollHost = $enrollHost;
    }

    /**
     * The whole screen in one read.
     *
     * enroll_host_configured is false when no enrollment host is set: the
     * view says so up front instead of letting the admin fill a form that
     * AdminService::issueToken() would refuse — the refusal is actionable,
     * but only after the work is done.
     *
     * @return array{
     *   tokens: array<int, array<string, mixed>>,
     *   users: array<int, array{id: string, slug: string, display_name: string}>,
     *   instances: array<int, array{id: string, label: string}>,
     *   now: string,
     *   enroll_host_configured: bool
     * }
     */
    public function overview(): array
    {
        return [
            'tokens' => $this->tokens(),
            'users' => $this->users(),
            'instances' => $this->instances(),
            // Server clock, read once with the rest: the view derives every
            // countdown from it rather than from the browser's own clock.
            'now' => Database::utcNow(),
            'enroll_host_configured' => $this->enrollHost !== '',
        ];
    }

    // -------------------------------------------------------------- helpers

    /**
     * Active enrollment tokens (AdminService::listTokens() decides what
     * "active" means), each carrying the user and network names behind its
     * ULIDs plus uses_left, so the table needs no second lookup. Rekey
     * tokens are rotation plumbing and never appear (ADR 0006).
     *
     * @return array<int, array<string, mixed>>
     */
    private function tokens(): array
    {
        $tokens = $this->admin->listTokens()['tokens'];
        if ($tokens === []) {
            return [];
        }

        $users = [];
        foreach ($this->db->query('SELECT id, slug, display_name FROM users') as $row) {
            $users[(string)$row['id']] = $row;
        }
        $instances = [];
        foreach ($this->db->query('SELECT id, label FROM instances') as $row) {
            $instances[(string)$row['id']] = $row;
        }

        foreach ($tokens as $i => $token) {
            $user = $users[(string)$token['user_id']] ?? null;
            $instance = $instances[(string)$token['instance_id']] ?? null;
            $token['user_slug'] = $user !== null ? (string)$user['slug'] : '';
            $token['user_display_name'] = $user !== null ? (string)$user['display_name'] : '';
            $token['instance_label'] = $instance !== null ? (string)$instance['label'] : '';
            $token['uses_left'] = \max(0, (int)$token['max_uses'] - (int)$token['used_count']);
            $tokens[$i] = $token;
        }
        return $tokens;
    }

    /**
     * Active users for the issue form. Disabled users are omitted: issuing
     * for one is refused downstream (USER_DISABLED), so the picker never
     * offers the choice.
     *
     * @return array<int, array{id: string, slug: string, display_name: string}>
     */
    private function users(): array
    {
        $out = [];
        $rows = $this->db->query(
            "SELECT id, slug, display_name FROM users WHERE status = 'active' ORDER BY display_name, slug"
        );
        foreach ($rows as $row) {
            $out[] = [
                'id' => (string)$row['id'],
                'slug' => (string)$row['slug'],
                'display_name' => (string)$row['display_name'],
            ];
        }
        return $out;
    }

    /**
     * Declared networks for the issue form — the admin fixes the target
     * instance, never the enrolling user (M08). Same lightest-possible read
     * as the Devices filter: the store only, no reachability probe.
     *
     * @return array<int, array{id: string, label: string}>
     */
    private function instances(): array
    {
        $out = [];
        foreach ($this->db->query('SELECT id, label FROM instances ORDER BY label') as $row) {
            $out[] = ['id' => (string)$row['id'], 'label' => (string)$row['label']];
        }
        return $out;
    }
}
