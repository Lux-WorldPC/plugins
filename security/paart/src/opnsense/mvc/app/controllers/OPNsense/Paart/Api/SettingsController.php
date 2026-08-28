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
 * Settings API (M08 Settings screen): get/set of the settings subtree
 * ONLY. Deliberately not the stock full-model set: the networks subtree
 * must never change without its domain validation and SQLite mirror sync
 * (Q13), which NetworksController owns — a full-model set would be a
 * side door around both. Settings changes need no service restart: every
 * request composes its graph from the current values.
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

class SettingsController extends ApiMutableModelControllerBase
{
    use ContractTrait;

    protected static $internalModelName = 'paart';
    protected static $internalModelClass = '\OPNsense\Paart\Paart';

    /**
     * GET /api/paart/settings/get — the settings subtree, form-shaped.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function getAction()
    {
        return $this->contract(function () {
            return ['paart' => ['settings' => $this->getModel()->settings->getNodes()]];
        });
    }

    /**
     * POST /api/paart/settings/set — validate, then persist to config.xml.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function setAction()
    {
        return $this->contract(function () {
            if (!$this->request->isPost()) {
                $this->badRoute();
            }
            $post = $this->request->getPost('paart');
            if (!\is_array($post) || !isset($post['settings']) || !\is_array($post['settings'])) {
                $this->badRoute();
            }
            $mdl = $this->getModel();
            $mdl->settings->setNodes($post['settings']);

            $validations = [];
            foreach ($mdl->performValidation() as $message) {
                $validations['paart.' . $message->getField()] = $message->getMessage();
            }
            if ($validations !== []) {
                return ['result' => 'failed', 'validations' => $validations];
            }
            $mdl->serializeToConfig();
            Config::getInstance()->save();
            return ['result' => 'saved'];
        });
    }
}
