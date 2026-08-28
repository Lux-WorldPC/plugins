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
 * Users grid API (M08 Users screen): bootgrid-protocol plumbing over the
 * admin façade. Users live in the SQLite store, not in a config.xml
 * model, so the framework's model-bound base does not apply and the grid
 * shapes are produced by hand — but every read and write still goes
 * through AdminService (validation, audit, contract semantics). Routes:
 *
 *   searchUser -> bootgrid page (POST current/rowCount/searchPhrase/sort),
 *                 ordered server-side over the whole result set before the
 *                 page is cut — sorting the page in the browser would only
 *                 order the twenty-five rows it already holds. The store's
 *                 order (slug) stands when no sort is asked for, and
 *                 survives ties;
 *   getUser    -> dialog payload ({user: {...}}, blank defaults when no id);
 *   addUser    -> createUser, dialog validation shape on refusal;
 *   setUser    -> updateUser, a slug change is refused (immutable, M03).
 *
 * Destructive operations (disable, rotate, tokens) are NOT served here:
 * the screen calls the recetted contract routes under /api/paart/admin/*.
 * Like every route in this file's sibling controllers, responses go
 * through contract() — validation refusals inside add/set are the one
 * exception, converted to the framework's {result: failed, validations}
 * shape so the dialog can show them on the offending field.
 */

namespace OPNsense\Paart\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Paart\Domain\DomainException;
use OPNsense\Paart\Support\GridSort;

class UsersController extends ApiControllerBase
{
    use ContractTrait;

    /**
     * Columns the grid may order by, and how each compares. Any other
     * column name in the request is refused by GridSort — 'email' and
     * 'id' are deliberately absent, being unshown or meaningless to sort.
     */
    private const SORTABLE = [
        'display_name' => GridSort::TEXT,
        'slug' => GridSort::TEXT,
        'device_count' => GridSort::NUMBER,
        'last_seen_at' => GridSort::TIMESTAMP,
        'status' => GridSort::TEXT,
    ];

    /**
     * POST/GET /api/paart/users/searchUser — bootgrid feed. Serialised by the core
     * (contract(..., false)): the grid renders cells as HTML.
     *
     * @return array<string, mixed> grid page, for the base class to send.
     */
    public function searchUserAction()
    {
        return $this->contract(function () {
            $q = $this->gridParam('searchPhrase');
            $users = $this->paart()->admin->listUsers(null, $q === '' ? null : $q)['users'];
            [$column, $direction] = $this->gridSort();
            $users = GridSort::apply($users, self::SORTABLE, $column, $direction);
            $current = \max(1, (int)$this->gridParam('current', '1'));
            // '25' mirrors the grid's default page size; -1 means "all".
            $size = (int)$this->gridParam('rowCount', '25');
            return [
                'rows' => $size > 0 ? \array_slice($users, ($current - 1) * $size, $size) : $users,
                'rowCount' => $size,
                'total' => \count($users),
                'current' => $current,
            ];
        }, false);
    }

    /**
     * GET /api/paart/users/getUser[/{id}] — dialog feed.
     *
     * @param string $id user ULID; '' serves the empty form of the create dialog,
     * @param        an unknown id a NOT_FOUND envelope.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function getUserAction($id = '')
    {
        return $this->contract(function () use ($id) {
            if ($id === '') {
                return ['user' => ['slug' => '', 'display_name' => '', 'email' => '']];
            }
            $row = $this->paart()->users->get($id); // NOT_FOUND -> M01 envelope
            return ['user' => [
                'slug' => (string)$row['slug'],
                'display_name' => (string)$row['display_name'],
                'email' => $row['email'] !== null ? (string)$row['email'] : '',
            ]];
        });
    }

    /**
     * POST /api/paart/users/addUser — create through the contract façade.
     *
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function addUserAction()
    {
        return $this->contract(function () {
            if (!$this->request->isPost()) {
                $this->badRoute();
            }
            $form = (array)($this->jsonBody()['user'] ?? []);
            $body = [
                'slug' => (string)($form['slug'] ?? ''),
                'display_name' => (string)($form['display_name'] ?? ''),
            ];
            if (($form['email'] ?? '') !== '') {
                $body['email'] = (string)$form['email'];
            }
            return $this->dialogSave(fn() => $this->paart()->admin->createUser($body, $this->contractActor()));
        });
    }

    /**
     * POST /api/paart/users/setUser/{id} — profile update, slug immutable.
     *
     * @param string $id user ULID; '' is a bad route, an unknown id a NOT_FOUND envelope.
     * @return null — the payload (or error envelope) is written by contract().
     */
    public function setUserAction($id = '')
    {
        return $this->contract(function () use ($id) {
            if (!$this->request->isPost() || $id === '') {
                $this->badRoute();
            }
            $form = (array)($this->jsonBody()['user'] ?? []);
            $current = $this->paart()->users->get($id); // NOT_FOUND -> M01 envelope
            if ((string)($form['slug'] ?? $current['slug']) !== (string)$current['slug']) {
                return ['result' => 'failed', 'validations' => [
                    'user.slug' => 'The slug cannot be changed once created.',
                ]];
            }
            return $this->dialogSave(fn() => $this->paart()->admin->updateUser($id, [
                'display_name' => (string)($form['display_name'] ?? ''),
                'email' => (string)($form['email'] ?? ''),
            ], $this->contractActor()));
        });
    }

    // -------------------------------------------------------------- helpers

    /**
     * Run one dialog-backed write: success becomes {result: saved}, a
     * domain validation refusal becomes the framework's dialog shape,
     * attributed to the field the message names. Anything else stays a
     * contract() concern (M01 envelope, page-level alert).
     *
     * @param callable(): array<string, mixed> $write
     * @return array<string, mixed>
     */
    private function dialogSave(callable $write): array
    {
        try {
            $write();
        } catch (DomainException $e) {
            if ($e->apiCode() !== 'VALIDATION_FAILED') {
                throw $e;
            }
            $message = $e->getMessage();
            $field = 'user.display_name';
            if (\stripos($message, 'slug') !== false) {
                $field = 'user.slug';
            } elseif (\stripos($message, 'email') !== false) {
                $field = 'user.email';
            }
            return ['result' => 'failed', 'validations' => [$field => $message]];
        }
        return ['result' => 'saved'];
    }
}
