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
 * Enrollment portal (M15): the browser counterpart of the Apple app, for
 * devices that run a classic WireGuard client (Windows, Linux, Android,
 * routers). One self-contained HTML page, served anonymously by the
 * plugin's public controller (Api\EnrollController — forbidden rule #7:
 * nothing but the enrollment routes is anonymous) at LOCAL_PATH, and
 * publicly under ExposureService::PORTAL_PREFIX through the M09 rewrite
 * (ADR 0008).
 *
 * What the page does, and what it never does: the key pair is generated
 * IN the browser (WebCrypto X25519, else the inlined pure-JS fallback,
 * else the user pastes a public key they generated themselves); only the
 * public key is submitted, to the same enrollment service the app uses
 * (EnrollmentService — "no duplicated enrollment code", M04/M15); the
 * .conf is assembled client-side from the returned bundle, with the
 * private key inserted locally. The server never sees a private key (D4)
 * and this class never renders one: it injects a JSON configuration blob
 * (site label, platforms, limits) and the two scripts into the template,
 * nothing per-user.
 *
 * Why everything is inline: the page must work on an isolated firewall
 * (no CDN, spec 15) and through the exposure ACL, which refuses every
 * path but the enrollment ones — a <script src="/ui/js/..."> would 403.
 * The QR library is the core's own (MIT, /usr/local/opnsense/www/js/
 * qrcode.js), read at render time rather than copied into the plugin.
 *
 * The enrollment token travels in the URL FRAGMENT (#token=...): it never
 * reaches the server, HAProxy's access log, or a proxy on the way. The
 * page reads it and posts it in the JSON body, like the app does.
 *
 * A rekey link (ADR 0006: same page, token bound to an existing device)
 * adds a second fragment field, &name=<device label>, set by the admin
 * side when the link is built. It is a display hint for the page — the
 * name is shown, not editable — and nothing more: the token stays opaque
 * (the page never asks the server what a token is for, which would be a
 * validity oracle), and the server ignores the submitted name on a rekey
 * anyway (EnrollmentService keeps the device's own label). A forged hint
 * changes what the page shows, never what the store holds.
 */

namespace OPNsense\Paart\Enroll;

use OPNsense\Paart\Exposure\ExposureService;

final class Portal
{
    /** Where the core's router serves the page: Api\EnrollController::portalAction(). */
    public const LOCAL_PATH = '/api/paart/enroll/portal';
    /** Path element the page posts to (LOCAL_PATH/submit, or /enroll/submit publicly). */
    public const SUBMIT_STEP = 'submit';
    /** The core's QR generator, inlined into the page (Kazuhiko Arase, MIT). */
    public const CORE_QRCODE_JS = '/usr/local/opnsense/www/js/qrcode.js';
    /** The page template and the X25519 fallback, next to the plugin's views. */
    public const TEMPLATE_DIR = __DIR__ . '/../../../../views/OPNsense/Paart/portal';
    /** Placeholders the template carries: the site label wherever it is shown, the others exactly once. */
    private const PLACEHOLDER_SITE = '{{PAART_SITE}}';
    private const PLACEHOLDER_CONFIG = '{{PAART_CONFIG}}';
    private const PLACEHOLDER_X25519 = '{{PAART_X25519_JS}}';
    private const PLACEHOLDER_QRCODE = '{{PAART_QRCODE_JS}}';

    private string $siteLabel;
    /** @var array<int, string> */
    private array $platforms;
    private int $deviceNameMaxLength;
    private string $coreQrcodeJs;
    private string $templateDir;

    /**
     * @param string $siteLabel resolved site.label (Paart::libSettings()).
     * @param array<int, string> $platforms contract platform values the
     *        page offers (Domain\Devices::PLATFORMS).
     * @param int $deviceNameMaxLength contract EnrollRequest.device_name
     *        maxLength, enforced by the page before it posts.
     * @param string|null $coreQrcodeJs path of the QR library to inline
     *        (tests point it at a stub); null = CORE_QRCODE_JS.
     * @param string|null $templateDir directory holding enroll.html and
     *        x25519.js; null = TEMPLATE_DIR.
     */
    public function __construct(
        string $siteLabel,
        array $platforms,
        int $deviceNameMaxLength,
        ?string $coreQrcodeJs = null,
        ?string $templateDir = null
    ) {
        $this->siteLabel = $siteLabel;
        $this->platforms = \array_values($platforms);
        $this->deviceNameMaxLength = $deviceNameMaxLength;
        $this->coreQrcodeJs = $coreQrcodeJs ?? self::CORE_QRCODE_JS;
        $this->templateDir = $templateDir ?? self::TEMPLATE_DIR;
    }

    /**
     * The complete page, ready to send as text/html. Nothing in it is
     * per-request: the same bytes serve every visitor, and nothing an
     * enrolling user types is ever rendered server-side (the page builds
     * its own DOM from the JSON reply). The one admin-entered value, the
     * site label, is HTML-escaped where it lands in markup and
     * JSON-encoded (HEX flags: no "</script>" break-out) where it lands
     * in the configuration blob.
     *
     * @return string the HTML document.
     * @throws \RuntimeException when the template or a script is missing
     *         or unreadable — a packaging defect, not a runtime condition.
     */
    public function render(): string
    {
        $html = self::readFile($this->templateDir . '/enroll.html');
        $config = [
            'site_label' => $this->siteLabel,
            'platforms' => $this->platforms,
            'device_name_max_length' => $this->deviceNameMaxLength,
            'submit_step' => self::SUBMIT_STEP,
        ];
        $json = \json_encode(
            $config,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );
        $scripts = [
            self::PLACEHOLDER_X25519 => self::readFile($this->templateDir . '/x25519.js'),
            self::PLACEHOLDER_QRCODE => self::readFile($this->coreQrcodeJs),
        ];
        foreach ($scripts as $placeholder => $script) {
            // A "</script>" inside an inlined script would end the block early.
            if (\stripos($script, '</script') !== false) {
                throw new \RuntimeException("Refusing to inline a script containing '</script' ($placeholder).");
            }
        }
        $replacements = [
            self::PLACEHOLDER_SITE => \htmlspecialchars($this->siteLabel, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            self::PLACEHOLDER_CONFIG => $json,
        ] + $scripts;
        foreach ($replacements as $placeholder => $value) {
            $count = \substr_count($html, $placeholder);
            if ($count === 0 || ($count > 1 && $placeholder !== self::PLACEHOLDER_SITE)) {
                throw new \RuntimeException("Portal template must carry $placeholder exactly once.");
            }
            $html = \str_replace($placeholder, $value, $html);
        }
        return $html;
    }

    /**
     * The link an admin hands out for the portal flow (M08 Enrollment and
     * Rotate screens). Public form when the M09 exposure is applied —
     * https://<host>/enroll/#token=... — else the plugin's own path on the
     * web GUI port, which is what a LAN browser reaches in the legitimate
     * internal-only mode (M09 criterion 6). The token sits in the
     * fragment on both forms, followed by the device-name hint for a
     * rekey link (see file header).
     *
     * @param string $enrollHost host[:port] from the settings (the public
     *        name; its port is the exposure's, dropped for the local form).
     * @param string $token plaintext enrollment or rekey token.
     * @param bool $exposed ExposureService::status()['mode'] === 'haproxy'.
     * @param string $webguiPort the web GUI port for the local form;
     *        '' or '443' add no suffix.
     * @param string|null $deviceName label of the device a REKEY token is
     *        bound to, shown non-editable by the page; null for an
     *        enrollment token (the user names the device). Any non-null
     *        value — '' included — emits the hint field, and its presence
     *        alone is what tells the page it serves a rekey.
     * @return string absolute https:// URL, token (and hint) in the fragment.
     */
    public static function link(
        string $enrollHost,
        string $token,
        bool $exposed,
        string $webguiPort,
        ?string $deviceName = null
    ): string {
        $fragment = '#token=' . \rawurlencode($token);
        if ($deviceName !== null) {
            $fragment .= '&name=' . \rawurlencode($deviceName);
        }
        if ($exposed) {
            return 'https://' . $enrollHost . ExposureService::PORTAL_PREFIX . $fragment;
        }
        $host = self::hostWithoutPort($enrollHost);
        $port = ($webguiPort === '' || $webguiPort === '443') ? '' : ':' . $webguiPort;
        return 'https://' . $host . $port . self::LOCAL_PATH . $fragment;
    }

    /**
     * The portal's reply to a submission: the EnrollResponse without its
     * device token. A portal device is 'manual' — it never calls the
     * in-tunnel device API, so its token would only be a secret left in a
     * browser. The device keeps a hashed token in the store like any
     * other (schema rule), simply one that nothing ever presents.
     *
     * @param array<string, mixed> $enrollResponse Bundles::response().
     * @return array{device_id: string, bundle: array<string, mixed>}
     */
    public static function response(array $enrollResponse): array
    {
        return [
            'device_id' => (string)$enrollResponse['device_id'],
            'bundle' => $enrollResponse['bundle'],
        ];
    }

    /** host[:port] → host; a bracketed IPv6 literal keeps its brackets. */
    private static function hostWithoutPort(string $enrollHost): string
    {
        if (\str_starts_with($enrollHost, '[')) {
            $end = \strpos($enrollHost, ']');
            return $end === false ? $enrollHost : \substr($enrollHost, 0, $end + 1);
        }
        $colon = \strrpos($enrollHost, ':');
        return $colon === false ? $enrollHost : \substr($enrollHost, 0, $colon);
    }

    /** @throws \RuntimeException when the file cannot be read. */
    private static function readFile(string $path): string
    {
        $content = \is_readable($path) ? \file_get_contents($path) : false;
        if ($content === false) {
            throw new \RuntimeException("Portal asset unreadable: $path");
        }
        return $content;
    }
}
