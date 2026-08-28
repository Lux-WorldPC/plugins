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
 * Admin surface of the M01 contract over OPNsense routing (M08).
 *
 * The contract publishes /admin/users, /admin/devices, /admin/tokens,
 * /admin/audit, /admin/health; OPNsense's API router serves them here as
 * /api/paart/admin/<resource>[/<id>[/<command>]] — same operations, same
 * bodies, same errors, platform prefix aside (the admin surface is
 * consumed same-origin by the plugin UI, x-exposure: admin, never
 * public). Authentication and the dedicated privilege come from the web
 * GUI (ACL.xml); all logic lives in the framework-free AdminService.
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiControllerBase;

class AdminController extends ApiControllerBase
{
    use ContractTrait;

    /**
     * /api/paart/admin/users[/{id}[/rotate]] — list, create, update, disable,
     * rotate every device of one user.
     *
     * @param string $id user ULID, '' on the collection routes.
     * @param string $command sub-resource ('rotate'), '' when none.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function usersAction($id = '', $command = '')
    {
        return $this->contract(function () use ($id, $command) {
            $admin = $this->paart()->admin;
            if ($id === '' && $command === '') {
                if ($this->request->isGet()) {
                    return $admin->listUsers($this->queryParam('status'), $this->queryParam('q'));
                }
                if ($this->request->isPost()) {
                    return $admin->createUser($this->jsonBody(), $this->contractActor());
                }
            } elseif ($id !== '' && $command === '' && $this->request->isDelete()) {
                return $admin->disableUser($id, $this->contractActor());
            } elseif ($id !== '' && $command === '' && $this->request->isPatch()) {
                return $admin->updateUser($id, $this->jsonBody(), $this->contractActor());
            } elseif ($id !== '' && $command === 'rotate' && $this->request->isPost()) {
                return $admin->rotateUserDevices($id, $this->contractActor());
            }
            $this->badRoute();
        });
    }

    /**
     * /api/paart/admin/devices[/{id}[/rotate|revoke|reissue|manage]] — list,
     * rename, rotate, re-issue, revoke, and move between 'full' and 'manual'.
     *
     * @param string $id device ULID, '' on the collection route.
     * @param string $command sub-resource ('rotate'|'revoke'|'reissue'|'manage'), '' when none.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function devicesAction($id = '', $command = '')
    {
        return $this->contract(function () use ($id, $command) {
            $admin = $this->paart()->admin;
            if ($id === '' && $command === '' && $this->request->isGet()) {
                return $admin->listDevices(
                    $this->queryParam('user_id'),
                    $this->queryParam('instance_id'),
                    $this->queryParam('status')
                );
            }
            if ($id !== '' && $command === '') {
                if ($this->request->isDelete()) {
                    // Contract: deleting a device IS revoking it (M03).
                    return $admin->revokeDevice($id, $this->contractActor());
                }
                if ($this->request->isPatch()) {
                    $body = $this->jsonBody();
                    return $admin->renameDevice($id, (string)($body['label'] ?? ''), $this->contractActor());
                }
            }
            if ($id !== '' && $this->request->isPost()) {
                switch ($command) {
                    case 'rotate':
                        return $admin->rotateDevice($id, $this->contractActor());
                    case 'revoke':
                        return $admin->revokeDevice($id, $this->contractActor());
                    case 'reissue':
                        return $admin->reissueDevice($id, $this->contractActor());
                    case 'manage':
                        $body = $this->jsonBody();
                        return $admin->manageDevice(
                            $id,
                            (string)($body['management_level'] ?? ''),
                            $this->contractActor()
                        );
                }
            }
            $this->badRoute();
        });
    }

    /**
     * /api/paart/admin/tokens[/{id}] — list active enrollment tokens, issue
     * one (plaintext returned once), revoke one.
     *
     * @param string $id enrollment token ULID, '' on the collection route.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function tokensAction($id = '')
    {
        return $this->contract(function () use ($id) {
            $admin = $this->paart()->admin;
            if ($id === '') {
                if ($this->request->isGet()) {
                    return $admin->listTokens();
                }
                if ($this->request->isPost()) {
                    return $admin->issueToken($this->jsonBody(), $this->contractActor());
                }
            } elseif ($this->request->isDelete()) {
                return $admin->revokeToken($id, $this->contractActor());
            }
            $this->badRoute();
        });
    }

    /**
     * /api/paart/admin/audit — read-only (M07: no route modifies entries).
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function auditAction()
    {
        return $this->contract(function () {
            if (!$this->request->isGet()) {
                $this->badRoute();
            }
            // queryAudit() reads only the contract's filter keys; router
            // noise in the query string is ignored by design.
            return $this->paart()->admin->queryAudit((array)$this->request->getQuery());
        });
    }

    /**
     * /api/paart/admin/health — dashboard feed.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function healthAction()
    {
        return $this->contract(function () {
            if (!$this->request->isGet()) {
                $this->badRoute();
            }
            return $this->paart()->admin->health();
        });
    }
}
