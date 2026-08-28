{#
 # Copyright (C) 2026 Lux-World PC SARL
 #
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

{#
 # Devices screen (M08): every enrolled device — grid (user, device,
 # platform, network, IP, last handshake, key age, state) with a network
 # filter, and the per-device actions: rename, move between `full` and
 # `manual` management, rotate (active devices), re-issue rekey link
 # (devices already rotating — a fresh token, the previous one retired),
 # revoke behind a TYPED confirmation (the device name must be retyped —
 # irreversible, M08 Confirmations). Public keys
 # never appear in the grid (M08 guiding principle); they live in the
 # folded "Technical details" of the detail dialog, fetched on demand.
 # Reads go through the bootgrid plumbing (/api/paart/devices/*); every
 # write calls the recetted /api/paart/admin/* contract routes, whose
 # refusals arrive as the M01 envelope and are surfaced in the alert box.
 # Rekey secrets (manual devices) are shown ONCE, in the rotate/re-issue
 # result dialog — the browser portal link (portal_link, M15) first, then
 # the app link or the bare token — never stored, never logged.
 #
 # Columns sort server-side: the header sends bootgrid's sort parameters
 # and the feed orders the whole result set before cutting the page.
 # Creation order stands when nothing is asked, and behind equal values.
 # "Last handshake" is sortable like the rest, but it only holds values
 # while the firewall answers; when it does not, every device is equally
 # unknown and the order simply does not move. Commands is not sortable.
 #
 # 26.1 bootgrid pitfalls apply: no column named "commands", datakey
 # pinned to the real row key.
 #}

<div class="alert alert-danger hidden" role="alert" id="errorAlert">
    <span id="errorMessage"></span>
</div>
<div class="alert alert-info hidden" role="alert" id="liveAlert">
    {{ lang._('The WireGuard service is unreachable — live tunnel state is not shown. Nothing was changed.') }}
</div>

<div class="content-box">
    <div class="content-box-main">
        <div style="display:flex;justify-content:flex-end;align-items:center;padding:8px 8px 0 8px;">
            <label for="filter-instance" style="margin:0 6px 0 0;">{{ lang._('Network') }}</label>
            {# width:auto shrinks a select to its text; the theme paints its
             # caret inside the padding, so leave that room or the two overlap. #}
            <select id="filter-instance" class="form-control" style="width:auto;padding-right:28px;">
                <option value="">{{ lang._('All networks') }}</option>
            </select>
        </div>
        <table id="grid-devices" class="table table-condensed table-hover table-striped">
            <thead>
                <tr>
                    <th data-sortable="false" data-column-id="id" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="user_display_name" data-type="string">{{ lang._('User') }}</th>
                    <th data-column-id="label" data-type="string">{{ lang._('Device') }}</th>
                    <th data-column-id="platform" data-formatter="platform" data-width="6em">{{ lang._('Platform') }}</th>
                    <th data-column-id="instance_label" data-type="string" data-width="8em">{{ lang._('Network') }}</th>
                    <th data-column-id="ip_address" data-formatter="ipAddress" data-width="8em">{{ lang._('IP address') }}</th>
                    <th data-column-id="handshake_age" data-formatter="lastHandshake" data-width="9em">{{ lang._('Last handshake') }}</th>
                    <th data-column-id="key_created_at" data-formatter="keyAge" data-width="6em">{{ lang._('Key age') }}</th>
                    <th data-column-id="status" data-formatter="deviceState" data-width="7em">{{ lang._('State') }}</th>
                    {# NOT data-column-id="commands" — the 26.1 bootgrid compat
                       layer reserves that name for its own formatter. #}
                    <th data-column-id="actions" data-formatter="deviceCommands" data-sortable="false" data-width="11em">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
</div>

<script>
    $(document).ready(function() {
        var currentRows = {};

        // Grid rows arrive HTML-escaped: searchDevice hands its page to
        // the core (contract(..., false)), which escapes what it serialises
        // for a browser session — required, since the grid renders cells
        // as HTML. Keep a decoded COPY for the dialogs, which compare, edit
        // and show these strings through .text(); the grid keeps its own
        // escaped rows. Where a dialog title is HTML (BootstrapDialog),
        // escape again with esc(). Every other route answers raw JSON.
        function decodeRow(row) {
            var copy = $.extend({}, row);
            Object.keys(copy).forEach(function (k) {
                if (typeof copy[k] === 'string') { copy[k] = htmlDecode(copy[k]); }
            });
            return copy;
        }
        function esc(text) { return $('<div>').text(text).html(); }

        // ISO-8601 UTC (Database::utcNow) -> the browser's local format.
        // Operational times are shown in the reader's own time; only the audit
        // trail stays UTC, and says so in its column header.
        function localTime(iso) {
            var t = Date.parse(iso);
            return isNaN(t) ? iso : new Date(t).toLocaleString();
        }

        var PLATFORMS = {
            ios: 'iOS', ipados: 'iPadOS', macos: 'macOS',
            windows: 'Windows', linux: 'Linux', android: 'Android', other: "{{ lang._('Other') }}"
        };

        // Seconds -> short human age ("35 s", "4 min", "3 h", "12 d").
        function humanAge(seconds) {
            if (seconds < 60) { return seconds + " {{ lang._('s') }}"; }
            if (seconds < 3600) { return Math.floor(seconds / 60) + " {{ lang._('min') }}"; }
            if (seconds < 86400) { return Math.floor(seconds / 3600) + " {{ lang._('h') }}"; }
            return Math.floor(seconds / 86400) + " {{ lang._('d') }}";
        }

        $("#grid-devices").UIBootgrid({
            search: '/api/paart/devices/searchDevice',
            datakey: 'id',
            options: {
                // The network filter travels with every grid request; the
                // plumbing reads it as a plain bootgrid parameter.
                requestHandler: function (request) {
                    request['instance_id'] = $("#filter-instance").val();
                    return request;
                },
                formatters: {
                    platform: function (column, row) {
                        return PLATFORMS[row.platform] || row.platform;
                    },
                    ipAddress: function (column, row) {
                        return row.ip_address === null ? '—' : row.ip_address;
                    },
                    lastHandshake: function (column, row) {
                        if (row.status === 'revoked' || row.status === 'pending' || !row.live) {
                            return '—';
                        }
                        return row.handshake_age === null
                            ? "{{ lang._('Never') }}"
                            : humanAge(row.handshake_age) + " {{ lang._('ago') }}";
                    },
                    keyAge: function (column, row) {
                        // key_created_at is Database::utcNow() ISO ("...T...Z"),
                        // directly parseable.
                        var t = Date.parse(row.key_created_at);
                        if (isNaN(t)) { return '—'; }
                        return humanAge(Math.max(0, Math.floor((Date.now() - t) / 1000)));
                    },
                    deviceState: function (column, row) {
                        // Spec indicator: connected recently / inactive /
                        // rotating / revoked — derived from the store status
                        // and, for active devices, the live peer status.
                        if (row.status === 'revoked') {
                            return '<span class="label label-default">' + "{{ lang._('Revoked') }}" + '</span>';
                        }
                        if (row.status === 'rotating') {
                            return '<span class="label label-warning">' + "{{ lang._('Rotating') }}" + '</span>';
                        }
                        if (row.status === 'pending') {
                            return '<span class="label label-info">' + "{{ lang._('Pending') }}" + '</span>';
                        }
                        if (!row.live) {
                            return '<span class="label label-primary" title="' +
                                "{{ lang._('The WireGuard service is unreachable — live state unknown.') }}" + '">' +
                                "{{ lang._('Active') }}" + '</span>';
                        }
                        return row.peer_status === 'online'
                            ? '<span class="label label-success">' + "{{ lang._('Connected') }}" + '</span>'
                            : '<span class="label label-default">' + "{{ lang._('Inactive') }}" + '</span>';
                    },
                    deviceCommands: function (column, row) {
                        var btn = function (cls, icon, title) {
                            return '<button type="button" class="btn btn-xs btn-default ' + cls +
                                '" data-row-id="' + row.id + '" title="' + title + '">' +
                                '<span class="fa fa-fw ' + icon + '"></span></button> ';
                        };
                        var html = btn('command-device-detail', 'fa-info-circle', "{{ lang._('Details') }}");
                        if (row.status !== 'revoked') {
                            html += btn('command-device-rename', 'fa-pencil', "{{ lang._('Rename') }}");
                            html += btn('command-device-manage', 'fa-exchange',
                                row.management_level === 'full'
                                    ? "{{ lang._('Set to manual management') }}"
                                    : "{{ lang._('Set to full management') }}");
                            if (row.status === 'active') {
                                html += btn('command-device-rotate', 'fa-refresh', "{{ lang._('Rotate key') }}");
                            }
                            if (row.status === 'rotating') {
                                html += btn('command-device-reissue', 'fa-repeat', "{{ lang._('Re-issue rekey link') }}");
                            }
                            html += btn('command-device-revoke', 'fa-ban', "{{ lang._('Revoke') }}");
                        }
                        return html;
                    }
                }
            }
        });

        $("#grid-devices").on("loaded.rs.jquery.bootgrid", function () {
            currentRows = {};
            var anyRow = null;
            $("#grid-devices").bootgrid("getCurrentRows").forEach(function (row) {
                currentRows[row.id] = decodeRow(row);
                anyRow = row;
            });
            {# The banner reads a row's 'live' copy — the response-level
               flag never reaches this handler. An empty grid hides the
               banner, which is vacuous then: rows come from the store,
               so zero rows means zero devices, not an unreachable
               firewall. #}
            $("#liveAlert").toggleClass('hidden', anyRow === null || anyRow.live);
            var bind = function (cls, handler) {
                $("#grid-devices").find(cls).off('click.paart').on('click.paart', function () {
                    var row = currentRows[$(this).data('row-id')];
                    if (row !== undefined) {
                        handler(row);
                    }
                });
            };
            bind('.command-device-detail', showDetail);
            bind('.command-device-rename', renameDevice);
            bind('.command-device-manage', manageDevice);
            bind('.command-device-rotate', rotateDevice);
            bind('.command-device-reissue', reissueDevice);
            bind('.command-device-revoke', revokeDevice);
        });

        // Populate the network filter once; changing it reloads the grid.
        ajaxGet('/api/paart/devices/listInstances', {}, function (data, status) {
            if (status === 'success' && data.instances !== undefined) {
                data.instances.forEach(function (inst) {
                    $("#filter-instance").append($('<option>').val(inst.id).text(inst.label));
                });
            }
        });
        $("#filter-instance").on('change', reload);

        function reload() {
            $("#grid-devices").bootgrid("reload");
        }

        // One read-only input + copy button; secrets pass through the DOM
        // value only (shown once by contract, never logged).
        function secretField(label, value) {
            var $input = $('<input type="text" readonly class="form-control input-sm" style="margin-bottom:4px;">').val(value);
            var $copy = $('<button type="button" class="btn btn-xs btn-default" style="margin-left:4px;">')
                .append($('<span class="fa fa-clipboard fa-fw">'))
                .on('click', function () { $input.trigger('select'); document.execCommand('copy'); });
            return $('<div>')
                .append($('<strong>').text(label))
                .append($('<div style="display:flex;align-items:center;">').append($input).append($copy));
        }

        // Show the rekey secret ONCE when a rotate/re-issue response
        // carries one (manual device), then refresh the grid.
        function rotationResult(title, data) {
            var $result = $('<div>').append($('<p>').text(
                "{{ lang._('The device keeps working during the grace period.') }}"));
            if (data.rekey_token !== null && data.rekey_token !== undefined) {
                // A manual device re-downloads through the browser portal
                // (M15); the app link is offered too, the token as a last
                // resort when no enrollment host is configured.
                if (data.portal_link !== null && data.portal_link !== undefined) {
                    $result.append(secretField(
                        "{{ lang._('Portal link (manual device, shown once)') }}", data.portal_link));
                }
                $result.append(secretField(
                    data.enroll_link !== null ? "{{ lang._('App link (shown once)') }}" : "{{ lang._('Rekey token (shown once)') }}",
                    data.enroll_link !== null ? data.enroll_link : data.rekey_token));
            }
            BootstrapDialog.show({
                title: title,
                type: BootstrapDialog.TYPE_SUCCESS,
                message: $result,
                buttons: [{label: "{{ lang._('Close') }}", action: function (d) { d.close(); }}]
            });
            reload();
        }

        // ------------------------------------------------ detail + technical
        function showDetail(row) {
            ajaxGet('/api/paart/devices/getDetail/' + row.id, {}, function (data, status) {
                if (status !== 'success' || data.technical === undefined) {
                    return; // envelope shown by the page alert
                }
                var kv = function ($tbody, label, value) {
                    $tbody.append($('<tr>')
                        .append($('<th style="white-space:nowrap;padding-right:12px;">').text(label))
                        .append($('<td style="word-break:break-all;">').text(value)));
                };
                var $summary = $('<tbody>');
                var $table = $('<table class="table table-condensed">').append($summary);
                kv($summary, "{{ lang._('User') }}", row.user_display_name + ' (' + row.user_slug + ')');
                kv($summary, "{{ lang._('Network') }}", row.instance_label);
                kv($summary, "{{ lang._('Platform') }}", PLATFORMS[row.platform] || row.platform);
                kv($summary, "{{ lang._('IP address') }}", row.ip_address === null ? '—' : row.ip_address);
                kv($summary, "{{ lang._('Enrolled') }}", localTime(row.enrolled_at));
                kv($summary, "{{ lang._('Status') }}", row.status);
                kv($summary, "{{ lang._('Management') }}", managementLabel(row.management_level));

                var $tech = $('<tbody>');
                var $techTable = $('<table class="table table-condensed" style="font-family:monospace;">')
                    .append($tech).hide();
                kv($tech, "{{ lang._('Public key') }}", data.technical.public_key);
                kv($tech, "{{ lang._('Peer name') }}",
                    data.technical.peer_name === null ? '—' : data.technical.peer_name);
                kv($tech, "{{ lang._('Last endpoint') }}",
                    data.technical.last_endpoint === null ? '—' : data.technical.last_endpoint);
                var $toggle = $('<a href="#">').text("{{ lang._('Technical details') }} ▸")
                    .on('click', function (e) {
                        e.preventDefault();
                        $techTable.toggle();
                        $(this).text("{{ lang._('Technical details') }} " +
                            ($techTable.is(':visible') ? '▾' : '▸'));
                    });
                var $message = $('<div>').append($table).append($toggle).append($techTable);
                if (!data.live) {
                    $message.append($('<p class="text-muted">').text(
                        "{{ lang._('The WireGuard service is unreachable — peer name and endpoint are not shown.') }}"));
                }
                BootstrapDialog.show({
                    title: esc(row.label),
                    message: $message,
                    buttons: [{label: "{{ lang._('Close') }}", action: function (d) { d.close(); }}]
                });
            });
        }

        // ------------------------------------------------ rename
        function renameDevice(row) {
            {# maxlength mirrors the contract's device label maxLength
               (protocol/openapi.yaml). #}
            var $input = $('<input type="text" class="form-control" maxlength="64">').val(row.label);
            BootstrapDialog.show({
                title: "{{ lang._('Rename device') }}",
                message: $('<div>')
                    .append($('<p>').text("{{ lang._('The name only labels the device for people; keys and tunnels are untouched.') }}"))
                    .append($input),
                buttons: [
                    {label: "{{ lang._('Cancel') }}", action: function (dialog) { dialog.close(); }},
                    {label: "{{ lang._('Rename') }}", cssClass: 'btn-primary', action: function (dialog) {
                        $.ajax({
                            url: '/api/paart/admin/devices/' + row.id,
                            type: 'PATCH',
                            contentType: 'application/json',
                            data: JSON.stringify({label: $input.val()}),
                            dataType: 'json'
                        }).done(function () {
                            dialog.close();
                            reload();
                        }); // a refusal keeps the dialog open, envelope in the page alert
                    }}
                ]
            });
        }

        // ------------------------------------------------ management level
        function managementLabel(level) {
            return level === 'manual'
                ? "{{ lang._('Manual (downloaded configuration)') }}"
                : "{{ lang._('Full (managed by the app)') }}";
        }

        {# What the number under "Managed devices" on the dashboard counts,
           and the only way to lower it other than revoking somebody's
           access. The plugin reads no licence and refuses nothing (ADR
           0018, D16) — it publishes the count, a client binary compares it
           to its own site key. #}
        function manageDevice(row) {
            var toManual = row.management_level === 'full';
            BootstrapDialog.confirm({
                title: toManual
                    ? "{{ lang._('Set to manual management') }}"
                    : "{{ lang._('Set to full management') }}",
                type: BootstrapDialog.TYPE_PRIMARY,
                message: $('<div>').text(
                    toManual
                        ? "{{ lang._('Mark') }} \"" + row.label + "\" " +
                          "{{ lang._('as a device that uses a downloaded configuration. Its access is untouched: the peer stays, the key stays, a running tunnel keeps running. It leaves the managed-devices count, and a future key rotation will hand you a rekey link instead of being applied by the app.') }}"
                        : "{{ lang._('Mark') }} \"" + row.label + "\" " +
                          "{{ lang._('as a device managed by the app. Its access is untouched. It joins the managed-devices count, and future key rotations are applied by the app instead of handing you a rekey link.') }}"),
                btnOKLabel: toManual ? "{{ lang._('Set to manual') }}" : "{{ lang._('Set to full') }}",
                btnCancelLabel: "{{ lang._('Cancel') }}",
                callback: function (confirmed) {
                    if (!confirmed) {
                        return;
                    }
                    ajaxCall(
                        '/api/paart/admin/devices/' + row.id + '/manage',
                        {management_level: toManual ? 'manual' : 'full'},
                        function (data, status) {
                            if (status !== 'success' || data.id === undefined) {
                                return; // envelope shown by the page alert
                            }
                            reload();
                        }
                    );
                }
            });
        }

        // ------------------------------------------------ rotate / re-issue
        function rotateDevice(row) {
            BootstrapDialog.confirm({
                title: "{{ lang._('Rotate key') }}",
                type: BootstrapDialog.TYPE_WARNING,
                message: $('<div>').text(
                    "{{ lang._('Start a key rotation for') }} \"" + row.label + "\"? " +
                    "{{ lang._('The device keeps working during the grace period.') }}"),
                btnOKLabel: "{{ lang._('Rotate') }}",
                btnCancelLabel: "{{ lang._('Cancel') }}",
                callback: function (confirmed) {
                    if (!confirmed) {
                        return;
                    }
                    ajaxCall('/api/paart/admin/devices/' + row.id + '/rotate', {}, function (data, status) {
                        if (status !== 'success' || data.id === undefined) {
                            return; // envelope shown by the page alert
                        }
                        rotationResult("{{ lang._('Rotation started') }}", data);
                    });
                }
            });
        }

        function reissueDevice(row) {
            BootstrapDialog.confirm({
                title: "{{ lang._('Re-issue rekey link') }}",
                type: BootstrapDialog.TYPE_WARNING,
                message: $('<div>').text(
                    "{{ lang._('Re-arm the pending rotation of') }} \"" + row.label + "\"? " +
                    "{{ lang._('The previous rekey link stops working; a new one is issued.') }}"),
                btnOKLabel: "{{ lang._('Re-issue') }}",
                btnCancelLabel: "{{ lang._('Cancel') }}",
                callback: function (confirmed) {
                    if (!confirmed) {
                        return;
                    }
                    ajaxCall('/api/paart/admin/devices/' + row.id + '/reissue', {}, function (data, status) {
                        if (status !== 'success' || data.id === undefined) {
                            return; // envelope shown by the page alert
                        }
                        rotationResult("{{ lang._('Rekey link re-issued') }}", data);
                    });
                }
            });
        }

        // ------------------------------------------------ revoke (typed)
        function revokeDevice(row) {
            var $input = $('<input type="text" class="form-control" autocomplete="off">');
            BootstrapDialog.show({
                title: "{{ lang._('Revoke device') }}",
                type: BootstrapDialog.TYPE_DANGER,
                message: $('<div>')
                    .append($('<p>').text(
                        "{{ lang._('Permanently revoke') }} \"" + row.label + "\" (" + row.user_display_name + ")? " +
                        "{{ lang._('Its tunnel stops working immediately. This cannot be undone.') }}"))
                    .append($('<p>').text("{{ lang._('Type the device name to confirm:') }}"))
                    .append($input),
                buttons: [
                    {label: "{{ lang._('Cancel') }}", action: function (dialog) { dialog.close(); }},
                    {id: 'btn-device-revoke-ok', label: "{{ lang._('Revoke') }}", cssClass: 'btn-danger',
                     action: function (dialog) {
                        ajaxCall('/api/paart/admin/devices/' + row.id + '/revoke', {}, function (data, status) {
                            if (status !== 'success' || data.id === undefined) {
                                return; // envelope shown by the page alert
                            }
                            dialog.close();
                            reload();
                        });
                    }}
                ],
                // M08 Confirmations: the button only arms once the exact
                // device name has been retyped.
                onshown: function (dialog) {
                    var $ok = dialog.getButton('btn-device-revoke-ok');
                    $ok.disable();
                    $input.off('input.paart').on('input.paart', function () {
                        if ($input.val() === row.label) {
                            $ok.enable();
                        } else {
                            $ok.disable();
                        }
                    }).trigger('focus');
                }
            });
        }

        // Contract refusals (M01 envelope) always state whether anything
        // changed; surface the actionable message at the top of the page.
        $(document).ajaxError(function (event, jqxhr) {
            var message = "{{ lang._('The request failed. Nothing is known to have changed.') }}";
            try {
                var body = JSON.parse(jqxhr.responseText);
                if (body.error && body.error.message) {
                    message = body.error.message;
                }
            } catch (e) {
            }
            $("#errorMessage").text(message);
            $("#errorAlert").removeClass('hidden');
            window.scrollTo(0, 0);
        });
        $(document).ajaxSuccess(function () {
            $("#errorAlert").addClass('hidden');
        });
    });
</script>

{{ partial("OPNsense/Paart/footer") }}
