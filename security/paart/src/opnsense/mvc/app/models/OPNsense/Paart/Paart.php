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
 * Config.xml model class (M08). Field definitions live in Paart.xml; this
 * class only bridges the model to the framework-free library: libSettings()
 * flattens the settings node into the scalar array App\Container consumes,
 * so the mapping between model fields and library keys exists in exactly
 * one place.
 */

namespace OPNsense\Paart;

use OPNsense\Base\BaseModel;
use OPNsense\Core\Config;

class Paart extends BaseModel
{
    /**
     * Settings in the shape App\Container expects.
     *
     * @return array<string, mixed>
     */
    public function libSettings(): array
    {
        return [
            'rotation_grace_days' => (int)(string)$this->settings->rotationGraceDays,
            'audit_retention_months' => (int)(string)$this->settings->auditRetentionMonths,
            'ip_quarantine_days' => (int)(string)$this->settings->ipQuarantineDays,
            'max_devices_per_user' => (int)(string)$this->settings->maxDevicesPerUser,
            'site_label' => $this->siteLabel(),
            'control_port' => $this->webguiPort(),
            'control_plane_pin_sha256' => (string)$this->settings->controlPlanePinSha256,
            'site_key' => (string)$this->settings->siteKey,
            'enroll_host' => (string)$this->settings->enrollHost,
            'enroll_pin_sha256' => (string)$this->settings->enrollPinSha256,
            'exposure_bind' => (string)$this->settings->exposureBind,
            'exposure_certificate' => (string)$this->settings->exposureCertificate,
            'wg_api_url' => (string)$this->settings->wgApiUrl,
            'wg_api_key' => (string)$this->settings->wgApiKey,
            'wg_api_secret' => (string)$this->settings->wgApiSecret,
            'wg_api_verify_tls' => (string)$this->settings->wgApiVerifyTls === '1',
        ];
    }

    /**
     * The bundle's site.label (M04): the siteLabel setting, or the
     * firewall's host.domain name when unset — the library side never
     * sees an empty label.
     */
    private function siteLabel(): string
    {
        $label = (string)$this->settings->siteLabel;
        if ($label !== '') {
            return $label;
        }
        $system = Config::getInstance()->object()->system;
        return \trim((string)$system->hostname . '.' . (string)$system->domain, '.');
    }

    /**
     * Web GUI listen port, for the in-tunnel control-plane URL of the
     * bundle (site.instance_url, ADR 0003); '' means the default 443.
     */
    private function webguiPort(): string
    {
        $webgui = Config::getInstance()->object()->system->webgui ?? null;
        return $webgui !== null ? (string)$webgui->port : '';
    }
}
