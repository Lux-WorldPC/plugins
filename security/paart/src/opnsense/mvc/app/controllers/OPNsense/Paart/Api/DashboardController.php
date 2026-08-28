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
 * Dashboard API (M08 Dashboard screen): one read-only route serving the
 * whole screen in a single call — counters, health, alerts and the recent
 * journal entries.
 *
 *   GET /api/paart/dashboard/overview
 *
 * Off-contract screen plumbing, like the Users and Devices feeds: the
 * shape is the screen's, not the M01 contract's (whose /admin/health and
 * /admin/audit stay the API surface for consumers). One call rather than
 * three keeps the reconciliation pass single — health() probes the
 * firewall — and the page consistent with itself.
 *
 * Served through contract(): version headers, and the M01 envelope on the
 * refusals DashboardScreen does not swallow (an unreachable firewall is
 * degraded there, not refused).
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Paart\Admin\DashboardScreen;

class DashboardController extends ApiControllerBase
{
    use ContractTrait;

    /**
     * GET /api/paart/dashboard/overview — the whole screen in one read.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function overviewAction()
    {
        return $this->contract(function () {
            if (!$this->request->isGet()) {
                $this->badRoute();
            }
            $c = $this->paart();
            return (new DashboardScreen($c->admin, $c->db))->overview();
        });
    }
}
