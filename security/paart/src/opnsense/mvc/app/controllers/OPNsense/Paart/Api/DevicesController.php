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
 * Devices grid API (M08 Devices screen): bootgrid-protocol plumbing over
 * the read-only DevicesScreen projections. Devices live in the SQLite
 * store, so the grid shapes are produced by hand, like the Users screen.
 * Routes (all read-only — the screen's writes call the recetted
 * /api/paart/admin/* contract routes directly):
 *
 *   searchDevice  -> bootgrid page (POST current/rowCount/searchPhrase/sort,
 *                    plus the screen's instance_id network filter),
 *                    ordered server-side over the whole result set before
 *                    the page is cut, as in the Users feed. The store's
 *                    order (id, i.e. creation) stands when no sort is
 *                    asked for, and survives ties. The runtime columns are
 *                    sortable like any other, but only carry values while
 *                    the firewall answers — when it does not they are
 *                    absent everywhere, and absent sorts last;
 *                    the response-level 'live' flag says whether
 *                    the runtime columns (handshake, peer status) are
 *                    populated — the UI reads the per-row copy, so the
 *                    response-level one only informs API consumers and
 *                    the zero-row case;
 *   getDetail     -> the folded "Technical details" of one device;
 *   listInstances -> declared instances for the network filter dropdown.
 *
 * Everything is served through contract() (M01 envelope on refusal,
 * version headers).
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Paart\Admin\DevicesScreen;
use OPNsense\Paart\Support\GridSort;

class DevicesController extends ApiControllerBase
{
    use ContractTrait;

    /**
     * Columns the grid may order by, and how each compares. Any other
     * column name in the request is refused by GridSort. 'handshake_age'
     * is seconds since the last handshake, so ascending means most
     * recently seen first; a device the firewall has no peer for has no
     * age at all and sorts last either way.
     */
    private const SORTABLE = [
        'user_display_name' => GridSort::TEXT,
        'label' => GridSort::TEXT,
        'platform' => GridSort::TEXT,
        'instance_label' => GridSort::TEXT,
        'ip_address' => GridSort::TEXT,
        'handshake_age' => GridSort::NUMBER,
        'key_created_at' => GridSort::TIMESTAMP,
        'status' => GridSort::TEXT,
    ];

    /**
     * POST/GET /api/paart/devices/searchDevice — bootgrid feed. Serialised by the core
     * (contract(..., false)): the grid renders cells as HTML.
     *
     * @return array<string, mixed> grid page, for the base class to send.
     */
    public function searchDeviceAction()
    {
        return $this->contract(function () {
            $instance = $this->gridParam('instance_id');
            $q = $this->gridParam('searchPhrase');
            $out = $this->screen()->rows(
                $instance === '' ? null : $instance,
                $q === '' ? null : $q
            );
            $devices = $out['devices'];
            [$column, $direction] = $this->gridSort();
            $devices = GridSort::apply($devices, self::SORTABLE, $column, $direction);
            $current = \max(1, (int)$this->gridParam('current', '1'));
            // '25' mirrors the grid's default page size; -1 means "all".
            $size = (int)$this->gridParam('rowCount', '25');
            return [
                'rows' => $size > 0 ? \array_slice($devices, ($current - 1) * $size, $size) : $devices,
                'rowCount' => $size,
                'total' => \count($devices),
                'current' => $current,
                'live' => $out['live'],
            ];
        }, false);
    }

    /**
     * GET /api/paart/devices/getDetail/{id} — folded technical details.
     *
     * @param string $id device ULID; '' is a bad route, an unknown id a NOT_FOUND envelope.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function getDetailAction($id = '')
    {
        return $this->contract(function () use ($id) {
            if ($id === '') {
                $this->badRoute();
            }
            return $this->screen()->detail($id); // NOT_FOUND -> M01 envelope
        });
    }

    /**
     * GET /api/paart/devices/listInstances — network filter dropdown.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function listInstancesAction()
    {
        return $this->contract(fn() => $this->screen()->instances());
    }

    // -------------------------------------------------------------- helpers

    /** The screen's projection service over the production graph. */
    private function screen(): DevicesScreen
    {
        $c = $this->paart();
        return new DevicesScreen($c->admin, $c->db, $c->gateway);
    }
}
