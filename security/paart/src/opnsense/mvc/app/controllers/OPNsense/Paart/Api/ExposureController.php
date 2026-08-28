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
 * Exposure API (M09, Settings screen panel): the os-haproxy side of the
 * public enrollment endpoint, driven by Exposure\ExposureService.
 *
 *   GET  /api/paart/exposure/status   the panel in one read (never fails
 *                                    for an absent or unreachable HAProxy)
 *   POST /api/paart/exposure/apply    generate/update the paart_ objects, reload
 *   POST /api/paart/exposure/remove   delete the paart_ objects, reload
 *   POST /api/paart/exposure/verify   probe the frontend; body
 *                                    {external_confirmed: bool} records the
 *                                    guided outside test
 *
 * Off-contract screen plumbing (x-exposure: admin, same-origin): the
 * shapes are the panel's. The inputs (bind, certificate) are settings —
 * the page saves the form before calling apply, so the graph composed
 * here reads the values the admin sees. Served through contract():
 * version headers and the M01 envelope on refusals, which always state
 * what stayed in place.
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiControllerBase;

class ExposureController extends ApiControllerBase
{
    use ContractTrait;

    /**
     * GET /api/paart/exposure/status — presence, mode, objects, dates.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function statusAction()
    {
        return $this->contract(function () {
            if (!$this->request->isGet()) {
                $this->badRoute();
            }
            return $this->paart()->exposure->status();
        });
    }

    /**
     * POST /api/paart/exposure/apply — create or update the owned objects, reload.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function applyAction()
    {
        return $this->contract(function () {
            if (!$this->request->isPost()) {
                $this->badRoute();
            }
            return $this->paart()->exposure->apply($this->contractActor());
        });
    }

    /**
     * POST /api/paart/exposure/remove — delete the owned objects, reload.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function removeAction()
    {
        return $this->contract(function () {
            if (!$this->request->isPost()) {
                $this->badRoute();
            }
            return $this->paart()->exposure->remove($this->contractActor());
        });
    }

    /**
     * POST /api/paart/exposure/verify — the seven probes (API, refusals,
     * portal page) and the certificate.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function verifyAction()
    {
        return $this->contract(function () {
            if (!$this->request->isPost()) {
                $this->badRoute();
            }
            $body = $this->jsonBody();
            $external = \filter_var($body['external_confirmed'] ?? false, FILTER_VALIDATE_BOOLEAN);
            return $this->paart()->exposure->verify($this->contractActor(), $external);
        });
    }
}
