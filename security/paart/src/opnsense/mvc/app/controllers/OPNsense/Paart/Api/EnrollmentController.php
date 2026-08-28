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
 * Enrollment screen API (M08 Enrollment): one read-only route serving the
 * whole screen in a single call — the issue form's pickers, the active
 * tokens with their names and countdown anchor, and whether an enrollment
 * host is configured at all.
 *
 *   GET /api/paart/enrollment/overview
 *
 * Off-contract screen plumbing, like the Dashboard, Users and Devices
 * feeds: the shape is the screen's, not the M01 contract's (whose
 * /admin/tokens stays the API surface for consumers). The screen's two
 * writes — issue and revoke — go straight to those recetted contract
 * routes, so this controller adds no write surface at all.
 *
 * Served through contract(): version headers, and the M01 envelope on
 * refusal.
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Paart\Admin\EnrollmentScreen;

class EnrollmentController extends ApiControllerBase
{
    use ContractTrait;

    /**
     * GET /api/paart/enrollment/overview — the whole screen in one read.
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
            return (new EnrollmentScreen($c->admin, $c->db, $c->enrollHost))->overview();
        });
    }
}
