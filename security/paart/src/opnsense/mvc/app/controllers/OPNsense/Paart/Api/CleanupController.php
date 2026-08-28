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
 * Cleanup API (M10 — the "purge" half of uninstalling):
 *
 *   GET  /api/paart/cleanup/impact
 *   POST /api/paart/cleanup/purge   {"export": "export|skip", "confirm": "<site label>"}
 *
 * Uninstalling must never cut a company's VPNs, so +PRE_DEINSTALL removes
 * nothing and points here instead: purging is a deliberate act of the
 * administrator, taken while the plugin is still installed and can still
 * reach the firewall. Everything destructive lives in Admin\CleanupService;
 * this controller owns the two things a service must not do — asking the
 * question, and writing config.xml.
 *
 * The confirmation is the site's own label, typed by hand. A purge is the
 * one action here that no later screen can undo, and a dialog answered by
 * reflex is exactly forbidden rule #4's failure mode. It is checked before
 * anything runs, so a mistyped confirmation costs nothing.
 *
 * The order of the purge is the reverse of the damage, and the two steps
 * this controller inserts are what make the order safe:
 *
 *   1. CleanupService::purge() — export, exposure, then the peers of each
 *      instance, batched per instance through the Networks screen's own
 *      withdrawal path.
 *   2. Config::forceReload() when a peer batch actually went through. The
 *      batch rewrote config.xml from ANOTHER process (the local WireGuard
 *      API): saving this request's older DOM would resurrect the deleted
 *      peers while the runtime no longer has them (seen live, session 16;
 *      documented on NetworksController::delNetworkAction).
 *   3. The plugin's whole node is removed from config.xml and saved. Not
 *      just the declarations: the node also holds the WireGuard API key
 *      and secret and the TLS pins, and a cleanup that leaves credentials
 *      behind is not a cleanup.
 *   4. CleanupService::dropStore() LAST, and only if step 3 succeeded — a
 *      failed save with the store already gone would leave declarations
 *      pointing at nothing, and no row left to say what happened.
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Paart\Admin\CleanupService;
use OPNsense\Paart\Domain\DomainException;

class CleanupController extends ApiMutableModelControllerBase
{
    use ContractTrait;

    protected static $internalModelName = 'paart';
    protected static $internalModelClass = '\OPNsense\Paart\Paart';

    /**
     * GET /api/paart/cleanup/impact — what a purge would destroy, plus the
     * phrase the admin has to type to authorise it.
     *
     * Read-only, and the screen's only source: no figure shown here is
     * computed a second time on the way to the purge.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function impactAction()
    {
        return $this->contract(function () {
            if (!$this->request->isGet()) {
                $this->badRoute();
            }
            return $this->paart()->cleanup->impact() + [
                'confirm_phrase' => $this->confirmPhrase(),
            ];
        });
    }

    /**
     * POST /api/paart/cleanup/purge — destroy this plugin's data, its
     * generated HAProxy objects and the peers of the devices it manages.
     *
     * Peers this plugin never created are never named and never touched
     * (D8, forbidden rule #3): the deletions go by public key, through the
     * same withdrawal call the Networks screen uses.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function purgeAction()
    {
        return $this->contract(function () {
            if (!$this->request->isPost()) {
                $this->badRoute();
            }
            $body = $this->jsonBody();
            $disposition = (string)($body['export'] ?? '');
            $this->assertConfirmed((string)($body['confirm'] ?? ''));
            if (!\in_array($disposition, CleanupService::EXPORT_DISPOSITIONS, true)) {
                // Same refusal the service raises, but before it is called:
                // an unnamed choice must never reach a destructive path.
                throw new DomainException(
                    'VALIDATION_FAILED',
                    "Purging needs an explicit choice for the store's contents: 'export' " .
                    "(a snapshot is written beside the store first) or 'skip'. Nothing was changed."
                );
            }

            $cleanup = $this->paart()->cleanup;
            $result = $cleanup->purge($disposition, $this->contractActor());

            if ((int)$result['peers_deleted'] > 0) {
                // A reconfigure ran, so config.xml on disk is newer than the
                // DOM this request holds. Reload before removing our node,
                // or the save below writes the deleted peers back.
                Config::getInstance()->forceReload();
            }

            $this->removeOwnNode($result);
            $result['store'] = $cleanup->dropStore();
            $result['result'] = 'purged';
            return $result;
        });
    }

    // -------------------------------------------------------------- internals

    /**
     * The phrase that authorises a purge: this site's label, as the
     * Settings screen shows it (its hostname fallback included). A site
     * with no label at all falls back to a fixed word rather than to the
     * empty string, which anything would match.
     */
    private function confirmPhrase(): string
    {
        // Read through the model this controller already holds, and read it
        // BEFORE anything is destroyed: after the purge its subtree is gone
        // from the DOM.
        $label = \trim((string)($this->getModel()->libSettings()['site_label'] ?? ''));
        return $label !== '' ? $label : 'PURGE';
    }

    /**
     * Refuse anything but an exact match, before a single byte is
     * destroyed. Surrounding whitespace is forgiven (it survives a
     * copy-paste); nothing else is.
     *
     * @throws DomainException VALIDATION_FAILED — nothing was changed.
     */
    private function assertConfirmed(string $typed): void
    {
        if (\trim($typed) !== $this->confirmPhrase()) {
            throw new DomainException(
                'VALIDATION_FAILED',
                'Cleaning up destroys this plugin\'s data and the peers of the devices it ' .
                'manages. Type this site\'s name exactly to confirm. Nothing was changed.'
            );
        }
    }

    /**
     * Remove //OPNsense/paart from config.xml and save.
     *
     * The model is deliberately not used: serializeToConfig() would write
     * the subtree back. The node is detached from the DOM instead, which
     * takes settings, credentials, pins and every declaration with it in
     * one write.
     *
     * @param array<string, mixed> $done what the purge already destroyed —
     *        named in the failure, because none of it can be undone.
     * @throws DomainException INTERNAL when the save fails. The store is
     *         then left ALONE (the caller stops), so the declarations and
     *         the rows still describe each other.
     */
    private function removeOwnNode(array $done): void
    {
        try {
            $config = Config::getInstance();
            $root = $config->object();
            if (isset($root->OPNsense->paart)) {
                $node = \dom_import_simplexml($root->OPNsense->paart);
                $node->parentNode->removeChild($node);
            }
            $config->save();
        } catch (\Throwable $e) {
            throw new DomainException(
                'INTERNAL',
                'Saving config.xml failed: ' . $e->getMessage() . ' The peers and the ' .
                'generated objects are already gone and are NOT restored (' .
                (int)($done['peers_deleted'] ?? 0) . ' peer(s), ' .
                (int)($done['exposure_removed'] ?? 0) . ' object(s)). The store was kept, ' .
                'so the declarations still match its rows: retry the cleanup.' .
                (($done['export_path'] ?? null) !== null
                    ? ' The export is at ' . $done['export_path'] . '.'
                    : '')
            );
        }
    }
}
