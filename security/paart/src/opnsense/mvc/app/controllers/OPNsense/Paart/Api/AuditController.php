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
 * Audit screen API (M07 consultation): bootgrid-protocol plumbing over
 * the read-only Admin\AuditScreen projection. OFF-contract, like the
 * other screen feeds — the contract's own audit surface is
 * GET /api/paart/admin/audit (AdminController::auditAction).
 *
 * Routes, both READ-ONLY — this controller exposes no write at all, and
 * no route anywhere modifies or deletes an audit entry (M07 integrity
 * criterion; the retention purge is AuditTrail::purgeExpired, which is
 * not a route either — App\Maintenance runs it every 15 minutes from
 * the plugin's cron job, M10):
 *
 *   searchEntry -> bootgrid page (POST current/rowCount/searchPhrase plus
 *                  the filter bar: from/to dates, user_id, device_id,
 *                  action_id, outcome), newest first always — the spec
 *                  fixes the order, so no column sorts;
 *   overview    -> filter pickers, retention setting + warning flag.
 *
 * Everything is served through contract() (M01 envelope on refusal,
 * version headers).
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Paart\Admin\AuditScreen;

class AuditController extends ApiControllerBase
{
    use ContractTrait;

    /**
     * POST/GET /api/paart/audit/searchEntry — bootgrid feed. Serialised by the core
     * (contract(..., false)): the grid renders cells as HTML.
     *
     * @return array<string, mixed> grid page, for the base class to send.
     */
    public function searchEntryAction()
    {
        return $this->contract(function () {
            $filters = [
                'from' => $this->gridParam('from'),
                'to' => $this->gridParam('to'),
                'user_id' => $this->gridParam('user_id'),
                'device_id' => $this->gridParam('device_id'),
                // 'action_id' on the wire — audit.volt's requestHandler sends
                // the action filter under that name; keep the two in step.
                'action' => $this->gridParam('action_id'),
                'outcome' => $this->gridParam('outcome'),
                'q' => $this->gridParam('searchPhrase'),
            ];
            $current = \max(1, (int)$this->gridParam('current', '1'));
            // '25' mirrors the grid's default page size; -1 means "all",
            // which AuditScreen caps at 1000 rows.
            $size = (int)$this->gridParam('rowCount', '25');
            return $this->screen()->search($filters, $current, $size);
        }, false);
    }

    /**
     * GET /api/paart/audit/overview — filter pickers + retention banner.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function overviewAction()
    {
        return $this->contract(function () {
            if (!$this->request->isGet()) {
                $this->badRoute();
            }
            return $this->screen()->overview();
        });
    }

    // -------------------------------------------------------------- helpers

    /** The screen's projection service over the production graph. */
    private function screen(): AuditScreen
    {
        $c = $this->paart();
        return new AuditScreen($c->db, $c->auditRetentionMonths);
    }
}
