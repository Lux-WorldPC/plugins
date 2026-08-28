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
 * Networks API (M08 Networks screen): CRUD over the declared-instance
 * rows of config.xml — the authoritative declaration — with the SQLite
 * mirror synchronized at declaration time (Q13) through Domain\Instances,
 * which owns the deep rules (single /24, pool bounds, range overlap,
 * removal refused while devices remain unless the admin's peer choice
 * accompanies it). Order of operations per write:
 *
 *   1. model field validation (masks) — reject malformed input, no side
 *      effect;
 *   2. domain declare/update/undeclare — writes the mirror and audits, or
 *      throws the actionable message the UI shows; config.xml untouched;
 *   3. config.xml save — the withdrawal's 'delete' branch first reloads
 *      the DOM from disk (see delNetworkAction); on the (exceptional)
 *      save failure the mirror step is compensated, so the two stores
 *      never drift apart silently.
 *
 * subnetsAction is the one write outside that order: the subnets are a
 * store-only detail of the mirror row (ADR 0012), so it stops at step 2
 * — no config.xml save, nothing to compensate.
 *
 * availableAction is the ONE display-only read of undeclared instances
 * the spec sanctions (M08: visible, never modifiable, with their peer
 * count); it uses the raw gateway on purpose — the provisioner's guards
 * never read undeclared instances (M06) and stay that way. impactAction
 * is the other read-only route, and reads the store alone: it answers
 * what a withdrawal would cost, before the admin decides.
 *
 * Not every route here belongs to the M01 contract: searchNetwork and
 * getNetwork are the framework's own grid/dialog plumbing, served by the
 * base class outside contract() — no error envelope, no version headers.
 * The declaration writes (add/set/del/toggleNetwork), availableAction,
 * impactAction and subnetsAction do go through contract(); the contract itself publishes no /networks
 * operation, this whole surface being same-origin UI plumbing (x-exposure:
 * admin) rather than a documented API.
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Paart\Domain\DomainException;

class NetworksController extends ApiMutableModelControllerBase
{
    use ContractTrait;

    protected static $internalModelName = 'network';
    protected static $internalModelClass = '\OPNsense\Paart\Paart';

    private const NODE_PATH = 'networks.network';

    /**
     * GET/POST /api/paart/networks/searchNetwork — bootgrid feed. Served by
     * the framework base outside contract(): native UI plumbing, no M01
     * envelope, no version headers (assumed — see the ContractTrait header).
     * Note: wgInstanceRef being a ModelRelationField, each row carries the
     * raw uuid under `wgInstanceRef` and the instance's display name under
     * `%wgInstanceRef` — read the raw key, never parse the %-decorated one.
     *
     * @return array the grid page, serialised by the core.
     */
    public function searchNetworkAction()
    {
        return $this->searchBase(
            self::NODE_PATH,
            ['enabled', 'label', 'wgInstanceRef', 'endpoint', 'ipRangeCidr', 'poolStartOctet', 'poolEndOctet'],
            'label'
        );
    }

    /**
     * GET /api/paart/networks/getNetwork[/{uuid}] — dialog feed. Framework
     * base outside contract(), like searchNetworkAction above.
     *
     * @param string|null $uuid declaration to edit; null serves the empty form.
     * @return array the node's form values, serialised by the core.
     */
    public function getNetworkAction($uuid = null)
    {
        return $this->getBase('network', self::NODE_PATH, $uuid);
    }

    /**
     * POST /api/paart/networks/addNetwork — declare a new instance.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function addNetworkAction()
    {
        return $this->contract(function () {
            if (!$this->request->isPost() || !\is_array($this->request->getPost('network'))) {
                $this->badRoute();
            }
            $mdl = $this->getModel();
            $node = $mdl->networks->network->Add();
            $node->setNodes($this->request->getPost('network'));

            $validations = $this->nodeValidation($node);
            if ($validations !== []) {
                return ['result' => 'failed', 'validations' => $validations];
            }
            $decl = self::declFromNode($node);
            $row = $this->paart()->instances->declare($decl, $this->contractActor());
            $this->saveConfig(function () use ($row): void {
                $this->paart()->instances->undeclare((string)$row['id'], $this->contractActor());
            });
            return ['result' => 'saved'];
        });
    }

    /**
     * POST /api/paart/networks/setNetwork/{uuid} — re-validate and sync.
     *
     * @param string $uuid config.xml uuid of the declaration; unknown → NOT_FOUND envelope.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function setNetworkAction($uuid = '')
    {
        return $this->contract(function () use ($uuid) {
            if (!$this->request->isPost() || !\is_array($this->request->getPost('network'))) {
                $this->badRoute();
            }
            $mdl = $this->getModel();
            $node = $mdl->getNodeByReference(self::NODE_PATH . '.' . $uuid);
            if ($node === null) {
                $this->notFound($uuid);
            }
            $oldDecl = self::declFromNode($node);
            $node->setNodes($this->request->getPost('network'));

            $validations = $this->nodeValidation($node);
            if ($validations !== []) {
                return ['result' => 'failed', 'validations' => $validations];
            }
            $decl = self::declFromNode($node);
            $instances = $this->paart()->instances;
            $mirrorId = $this->mirrorIdForRef($oldDecl['wg_instance_ref']);
            if ($mirrorId === null) {
                // Mirror row missing (manual config edit): declaration time
                // is exactly when Q13 says to resynchronize.
                $row = $instances->declare($decl, $this->contractActor());
                $undo = fn() => $instances->undeclare((string)$row['id'], $this->contractActor());
            } else {
                $instances->updateDeclaration($mirrorId, $decl, $this->contractActor());
                $undo = fn() => $instances->updateDeclaration($mirrorId, $oldDecl, $this->contractActor());
            }
            $this->saveConfig($undo);
            return ['result' => 'saved'];
        });
    }

    /**
     * GET /api/paart/networks/impact/{uuid} — what withdrawing this
     * declaration would cost, for the warning the screen shows BEFORE the
     * admin chooses (M08 Confirmations). Read-only; an unreachable
     * firewall does not stop it, the answer being about what the plugin
     * knows. A uuid with no mirror row answers with an empty impact rather
     * than 404: the declaration exists in config.xml, it simply has
     * nothing operational attached.
     *
     * @param string $uuid config.xml uuid of the declaration; unknown → NOT_FOUND envelope.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function impactAction($uuid = '')
    {
        return $this->contract(function () use ($uuid) {
            if (!$this->request->isGet()) {
                $this->badRoute();
            }
            $mdl = $this->getModel();
            $node = $mdl->getNodeByReference(self::NODE_PATH . '.' . $uuid);
            if ($node === null) {
                $this->notFound($uuid);
            }
            $decl = self::declFromNode($node);
            $mirrorId = $this->mirrorIdForRef($decl['wg_instance_ref']);
            if ($mirrorId === null) {
                // Same shape as AdminService::instanceWithdrawalImpact —
                // keep the two in step if that form ever changes.
                return [
                    'instance' => [
                        'id' => '',
                        'label' => $decl['label'],
                        'wg_instance_ref' => $decl['wg_instance_ref'],
                    ],
                    'devices' => [],
                    'live_count' => 0,
                    'revoked_count' => 0,
                    'active_tokens' => 0,
                ];
            }
            return $this->paart()->admin->instanceWithdrawalImpact($mirrorId);
        });
    }

    /**
     * POST /api/paart/networks/delNetwork/{uuid} — remove from management.
     *
     * The `peers` parameter carries the admin's choice for the devices
     * still in service — 'keep' (their peers stay up, unmanaged) or
     * 'delete' (their peers go, in one batch, before the withdrawal).
     * Absent, the strict path applies: Domain\Instances::undeclare refuses
     * while any non-revoked device remains. That default is deliberate —
     * a caller that forgets the parameter can never destroy an access
     * (forbidden rule #4).
     *
     * With no mirror row at all (manual config edit — the declaration
     * never went through this screen), `peers` is silently ignored and
     * only the config.xml node goes: the store holds no devices for the
     * instance, so there is no access the choice could destroy and no
     * peer this plugin may touch (D8 scope). Unlike set/toggle,
     * nothing resynchronizes first (Q13) — declaring a mirror row just to
     * purge it in the same request would be audit churn over nothing.
     *
     * Order matters and is not reversible in full: peers are deleted while
     * the instance is still declared (M06 refuses to write to an undeclared
     * one), then the mirror is purged, then config.xml is saved — from a
     * DOM reloaded after the peer batch on the delete branch, since that
     * batch rewrote config.xml from another process. On the
     * exceptional save failure the compensation re-declares the instance —
     * creating the mirror row when none existed before the call (Q13:
     * declaration time is the resynchronization point) — and restores the
     * declaration only, never the operational rows, which are gone by
     * then. The audit entry is what remains of them.
     *
     * @param string $uuid config.xml uuid of the declaration; unknown → NOT_FOUND envelope.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function delNetworkAction($uuid = '')
    {
        return $this->contract(function () use ($uuid) {
            if (!$this->request->isPost()) {
                $this->badRoute();
            }
            $mdl = $this->getModel();
            $node = $mdl->getNodeByReference(self::NODE_PATH . '.' . $uuid);
            if ($node === null) {
                $this->notFound($uuid);
            }
            $decl = self::declFromNode($node);
            $instances = $this->paart()->instances;
            $mirrorId = $this->mirrorIdForRef($decl['wg_instance_ref']);
            $peers = (string)$this->request->getPost('peers', null, '');
            // Count of peers actually deleted from the firewall — under
            // 'delete', devices whose peer was already gone do not count
            // (withdrawInstance counts what the firewall lost). Zero here
            // therefore means no reconfigure ran, so everything below that
            // talks about a batch must stay silent.
            $peersDeleted = 0;
            if ($mirrorId !== null) {
                if ($peers === '') {
                    $instances->undeclare($mirrorId, $this->contractActor());
                } else {
                    $withdrawal = $this->paart()->admin
                        ->withdrawInstance($mirrorId, $peers, $this->contractActor());
                    $peersDeleted = (int)$withdrawal['peers_deleted'];
                    if ($peersDeleted > 0) {
                        // The peer batch went through the local WireGuard API,
                        // which rewrote config.xml from ANOTHER process. This
                        // request's Config DOM predates those deletions, and
                        // Config::save() writes the whole DOM — saving now
                        // would resurrect the deleted peers in config.xml
                        // while the runtime no longer has them (seen live,
                        // session 16). Reload from disk first; our own model
                        // subtree is re-serialized over it below, so nothing
                        // of this plugin's data is lost.
                        Config::getInstance()->forceReload();
                    }
                }
            }
            $mdl->networks->network->del($uuid);
            $this->saveConfig(
                function () use ($instances, $decl): void {
                    $instances->declare($decl, $this->contractActor());
                },
                $peersDeleted > 0
                    // Only what holds on BOTH saveConfig failure branches:
                    // the declaration's fate differs between them and each
                    // branch's own message already states it.
                    ? 'Note: the peer deletions had already gone through and are not ' .
                      'undone — the peers of its former devices are gone from the ' .
                      'firewall and the store.'
                    : ''
            );
            return ['result' => 'deleted'];
        });
    }

    /**
     * POST /api/paart/networks/toggleNetwork/{uuid}[/{enabled}] — flip or
     * set the enabled flag. Like setNetwork, a missing mirror row (manual
     * config edit) is resynchronized here by a fresh declare (Q13).
     *
     * @param string $uuid config.xml uuid of the declaration; unknown → NOT_FOUND envelope.
     * @param string|int|null $enabled '1'/'0' sets that state (bootgrid sends
     *        strings, tests ints); null flips the current one.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function toggleNetworkAction($uuid = '', $enabled = null)
    {
        return $this->contract(function () use ($uuid, $enabled) {
            if (!$this->request->isPost()) {
                $this->badRoute();
            }
            $mdl = $this->getModel();
            $node = $mdl->getNodeByReference(self::NODE_PATH . '.' . $uuid);
            if ($node === null) {
                $this->notFound($uuid);
            }
            $oldDecl = self::declFromNode($node);
            // Bootgrid toggle semantics: an explicit value sets that state;
            // no value flips the current one.
            $node->enabled = $enabled !== null
                ? ($enabled === '1' || $enabled === 1 ? '1' : '0')
                : ((string)$node->enabled === '1' ? '0' : '1');

            $decl = self::declFromNode($node);
            $instances = $this->paart()->instances;
            $mirrorId = $this->mirrorIdForRef($decl['wg_instance_ref']);
            if ($mirrorId === null) {
                $row = $instances->declare($decl, $this->contractActor());
                $undo = fn() => $instances->undeclare((string)$row['id'], $this->contractActor());
            } else {
                $instances->updateDeclaration($mirrorId, $decl, $this->contractActor());
                $undo = fn() => $instances->updateDeclaration($mirrorId, $oldDecl, $this->contractActor());
            }
            $this->saveConfig($undo);
            return ['result' => (string)$node->enabled === '1' ? 'Enabled' : 'Disabled'];
        });
    }

    /**
     * GET /api/paart/networks/available — every WireGuard instance on this
     * firewall, flagged declared/undeclared, with its peer count (M08:
     * undeclared instances are visible, never modifiable).
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function availableAction()
    {
        return $this->contract(function () {
            if (!$this->request->isGet()) {
                $this->badRoute();
            }
            $container = $this->paart();
            $declared = [];
            foreach ($container->db->query('SELECT wg_instance_ref, label FROM instances') as $row) {
                $declared[(string)$row['wg_instance_ref']] = (string)$row['label'];
            }
            $instances = [];
            foreach ($container->gateway->listServers() as $server) {
                $uuid = (string)$server['uuid'];
                $instances[] = [
                    'uuid' => $uuid,
                    'name' => (string)$server['name'],
                    'declared' => isset($declared[$uuid]),
                    'label' => $declared[$uuid] ?? null,
                    'peer_count' => \count($container->gateway->searchClients($uuid)),
                ];
            }
            return ['instances' => $instances];
        });
    }

    /**
     * GET/POST /api/paart/networks/subnets/{uuid} — the labeled subnets of
     * one declared network (spec 01 bundle `subnets[]`), read or replaced
     * as a whole list (Domain\Subnets keeps the ULID of every row it
     * recognises, so device switch states survive an edit).
     *
     * The rows live in the store alone, keyed by the mirror ULID: no
     * config.xml write here, hence no saveConfig() and no compensation.
     * A declaration with no mirror row (manual config edit) is
     * resynchronized first on POST (Q13, like setNetwork); on GET it
     * simply has no subnets yet.
     *
     * Both verbs answer `instance {id, label}` (the mirror ULID, '' while
     * no mirror row exists) and `allow_subnet_toggle` (the dialog says
     * whether devices will get switches at all). GET adds `subnets[]` as
     * stored; POST adds `result: "saved"` and Domain\Subnets' counters
     * `added` / `updated` / `removed`. Refusals: a verb other than
     * GET/POST, or a POST body without a `subnets` array, are bad routes
     * (BAD_REQUEST envelope); a row the domain rejects (label, CIDR,
     * duplicate, cap) is the actionable message it throws, nothing saved.
     *
     * @param string $uuid config.xml uuid of the declaration; unknown → NOT_FOUND envelope.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function subnetsAction($uuid = '')
    {
        return $this->contract(function () use ($uuid) {
            $mdl = $this->getModel();
            $node = $mdl->getNodeByReference(self::NODE_PATH . '.' . $uuid);
            if ($node === null) {
                $this->notFound($uuid);
            }
            $decl = self::declFromNode($node);
            $mirrorId = $this->mirrorIdForRef($decl['wg_instance_ref']);
            $head = [
                'instance' => ['id' => $mirrorId ?? '', 'label' => $decl['label']],
                'allow_subnet_toggle' => $decl['allow_subnet_toggle'],
            ];
            if ($this->request->isGet()) {
                return $head + [
                    'subnets' => $mirrorId === null ? [] : $this->paart()->subnets->list($mirrorId),
                ];
            }
            if (!$this->request->isPost()) {
                $this->badRoute();
            }
            $body = $this->jsonBody();
            if (!isset($body['subnets']) || !\is_array($body['subnets'])) {
                $this->badRoute();
            }
            if ($mirrorId === null) {
                $mirrorId = (string)$this->paart()->instances->declare($decl, $this->contractActor())['id'];
                $head['instance']['id'] = $mirrorId;
            }
            $out = $this->paart()->subnets->replace($mirrorId, $body['subnets'], $this->contractActor());
            return $head + ['result' => 'saved'] + $out;
        });
    }

    // -------------------------------------------------------------- helpers

    /**
     * Persist the in-memory model to config.xml; when the save itself
     * fails, roll the mirror back through $undoMirror so config.xml and
     * the mirror never drift apart silently — and say so. Rethrowing raw
     * would land in the generic INTERNAL envelope ("whether a change was
     * applied is unknown") when the outcome here is known (M08: every
     * error states the resulting state). $irreversible lets a caller
     * append what the failure does NOT undo (the withdrawal's peer
     * batch); empty for callers whose writes are fully reversed.
     */
    private function saveConfig(callable $undoMirror, string $irreversible = ''): void
    {
        try {
            $this->getModel()->serializeToConfig();
            Config::getInstance()->save();
        } catch (\Throwable $e) {
            try {
                $undoMirror();
            } catch (\Throwable $undoFailure) {
                throw new DomainException(
                    'INTERNAL',
                    'Saving config.xml failed (' . $e->getMessage() . ') and rolling the ' .
                    'mirror back also failed (' . $undoFailure->getMessage() . '): the ' .
                    'mirror now disagrees with config.xml until this operation is ' .
                    'retried successfully.' . ($irreversible === '' ? '' : ' ' . $irreversible)
                );
            }
            throw new DomainException(
                'INTERNAL',
                'Saving config.xml failed: ' . $e->getMessage() . ' The mirror change ' .
                'was rolled back; the declarations on disk are unchanged.' .
                ($irreversible === '' ? '' : ' ' . $irreversible)
            );
        }
    }

    /**
     * Field-level model validation, keyed for the dialog ("network.<field>").
     *
     * @param \OPNsense\Base\FieldTypes\BaseField $node the model node just
     *        filled from the request — its absolute path is stripped from
     *        every message so the keys match the dialog's field ids.
     * @return array<string, string> field id => message; empty when valid.
     */
    private function nodeValidation($node): array
    {
        $validations = [];
        // __reference is BaseField's magic absolute-path property — the only
        // public way to read a node's model path on OPNsense 26.1.
        $reference = $node->__reference . '.';
        foreach ($this->getModel()->performValidation() as $message) {
            $validations['network.' . \str_replace($reference, '', $message->getField())] =
                $message->getMessage();
        }
        return $validations;
    }

    /** Mirror ULID for a wg instance reference, null when not mirrored. */
    private function mirrorIdForRef(string $wgInstanceRef): ?string
    {
        $id = $this->paart()->db->scalar(
            'SELECT id FROM instances WHERE wg_instance_ref = :ref',
            [':ref' => $wgInstanceRef]
        );
        return $id !== null ? (string)$id : null;
    }

    /** @throws \OPNsense\Paart\Domain\DomainException NOT_FOUND always. */
    private function notFound(string $uuid): void
    {
        throw new \OPNsense\Paart\Domain\DomainException(
            'NOT_FOUND',
            "No declared network with uuid '$uuid'. Nothing was changed."
        );
    }

    /**
     * The Domain\Instances declaration shape for one model row.
     *
     * @param \OPNsense\Base\FieldTypes\BaseField $node one networks.network
     *        model node.
     * @return array<string, mixed> declaration accepted by Instances.
     */
    private static function declFromNode($node): array
    {
        return [
            'wg_instance_ref' => (string)$node->wgInstanceRef,
            'label' => (string)$node->label,
            'endpoint' => (string)$node->endpoint,
            'ip_range_cidr' => (string)$node->ipRangeCidr,
            'pool_start_octet' => (int)(string)$node->poolStartOctet,
            'pool_end_octet' => (int)(string)$node->poolEndOctet,
            'dns_servers' => self::csv((string)$node->dnsServers),
            'match_domains' => self::csv((string)$node->matchDomains),
            'allow_full_tunnel' => (string)$node->allowFullTunnel === '1',
            'allow_subnet_toggle' => (string)$node->allowSubnetToggle === '1',
            'enabled' => (string)$node->enabled === '1',
        ];
    }

    /** @return array<int, string> trimmed, empties dropped. */
    private static function csv(string $value): array
    {
        return \array_values(\array_filter(\array_map('\trim', \explode(',', $value))));
    }
}
