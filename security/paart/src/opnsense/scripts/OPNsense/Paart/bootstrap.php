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
 * VPN Access store bootstrap (M02/M10): open the store, back it up and
 * bring its schema up to date, refuse a store newer than the code. Run
 * at boot by the 'bootup' hook of plugins.inc.d/paart.inc — and, once the
 * package exists (M10 packaging, to come), by its +POST_INSTALL; idempotent, so
 * running it by hand ("configctl paart bootstrap") is always safe. The
 * API controllers migrate on first request too — this script exists so
 * the schema is ready, and any refusal visible, before anyone calls.
 *
 * Prints {ok, db_path, schema_version} on stdout. On failure prints the
 * reason on stderr — SQLite3 extension missing, SCHEMA_MISMATCH (store
 * newer than the code, a downgraded package), unwritable directory — and
 * exits 1; the same line goes to syslog under the paart program name.
 * Touches no WireGuard state: the gateway is wired, never called.
 */

require_once 'script/load_phalcon.php';
require_once 'config.inc';

use OPNsense\Paart\App\Container;
use OPNsense\Paart\Paart;

\openlog('paart', LOG_PID, LOG_USER);
try {
    $settings = (new Paart())->libSettings();
    $container = new Container($settings, Container::gatewayFromSettings($settings));
} catch (\Throwable $e) {
    \syslog(LOG_ERR, 'store bootstrap refused: ' . $e->getMessage());
    \fwrite(STDERR, 'VPN Access store bootstrap refused: ' . $e->getMessage() . "\n");
    exit(1);
}
echo \json_encode([
    'ok' => true,
    'db_path' => $container->db->path(),
    'schema_version' => $container->migrator->currentVersion(),
]), "\n";
