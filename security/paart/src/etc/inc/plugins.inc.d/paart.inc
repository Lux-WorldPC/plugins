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
 * VPN Access plugin hooks (M10) — what the OPNsense core asks of a plugin
 * through plugins.inc: the cron job, the syslog target and the boot hook.
 * The plugin runs no daemon (D3), so there is no *_services() entry:
 * everything happens in the web GUI's PHP and in the configd actions of
 * actions_paart.conf, which the scripts under scripts/OPNsense/Paart back.
 */

/**
 * Maintenance every 15 minutes (App\Maintenance: abandoned enrollments
 * after one hour, rotation graces, reconciliation report, audit purge).
 * flock -n skips a run that overlaps a slow one instead of stacking them,
 * and -E 0 makes that skip a silent exit 0 rather than a cron failure;
 * the lock file lives in /tmp (cleared at boot, no stale lock to unstick);
 * the job is not detached (-d) so the lock covers the whole run. Always
 * scheduled: with nothing declared the run is a handful of empty queries.
 */
function paart_cron()
{
    return [[
        'autocron' => [
            '/usr/local/bin/flock -n -E 0 -o /tmp/paart-maintenance.lock /usr/local/sbin/configctl paart maintenance',
            '*/15',
        ],
    ]];
}

/** Everything logged under the paart program name lands in /var/log/paart/. */
function paart_syslog()
{
    return [
        'paart' => ['facility' => ['paart']],
    ];
}

/** Boot: bring the store schema up to date before the first API call (M02). */
function paart_configure()
{
    return [
        'bootup' => ['paart_bootstrap'],
    ];
}

/** The 'bootup' hook body: runs the bootstrap configd action (store backup + migrations). */
function paart_bootstrap($verbose = false)
{
    service_log('Bootstrapping VPN Access store...', $verbose);

    configd_run('paart bootstrap');

    service_log("done.\n", $verbose);
}
