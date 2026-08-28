#!/usr/local/bin/php
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
 * VPN Access periodic maintenance (M10) — the command behind the plugin's
 * cron job (paart_cron() in plugins.inc.d/paart.inc, every 15 minutes) and
 * the "VPN Access maintenance" configd action an admin can schedule from
 * System > Settings > Cron. Wires the production graph exactly as the API
 * controllers do (settings from the config.xml model, WireGuard API on
 * the loopback) and runs App\Maintenance: abandoned enrollments (M04),
 * overdue rotation graces (M05), reconciliation report (M05), audit
 * retention purge (M07). Each task audits itself and is isolated from the
 * others; this script only prints the JSON summary on stdout (configd
 * hands it back) and writes failures to syslog under the paart program
 * name. Exit status: 0 when every selected task ran, 1 when a task failed,
 * a task name was unknown (nothing runs) or the store could not be opened.
 *
 * Usage: maintenance.php [task ...]   tasks: abandoned graces reconcile purge
 *        (none = all, always in that order).
 */

require_once 'script/load_phalcon.php';
require_once 'config.inc';

use OPNsense\Paart\App\Container;
use OPNsense\Paart\Paart;

\openlog('paart', LOG_PID, LOG_USER);
$tasks = \array_slice($argv, 1);
try {
    $settings = (new Paart())->libSettings();
    $container = new Container($settings, Container::gatewayFromSettings($settings));
    $result = $container->maintenance->run($tasks);
} catch (\Throwable $e) {
    \syslog(LOG_ERR, 'maintenance did not run: ' . \get_class($e) . ': ' . $e->getMessage());
    echo \json_encode(['ok' => false, 'error' => $e->getMessage()]), "\n";
    exit(1);
}
foreach ($result['errors'] as $task => $message) {
    \syslog(LOG_ERR, "maintenance task '$task' failed: $message");
}
echo \json_encode($result), "\n";
exit($result['ok'] ? 0 : 1);
