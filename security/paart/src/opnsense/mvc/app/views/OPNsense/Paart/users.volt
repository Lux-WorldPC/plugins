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
 # Users screen (M08): named identities — grid (name, device count, last
 # seen, status), create/edit dialog, and per-user actions: devices
 # detail, issue enrollment token, rotate all devices, disable. No screen
 # element ever shows a public key (M08 guiding principle). Grid CRUD goes
 # through the bootgrid plumbing (/api/paart/users/*); every other action
 # calls the recetted /api/paart/admin/* contract routes, whose refusals
 # arrive as the M01 envelope and are surfaced in the alert box. Token and
 # rekey secrets are shown ONCE, in the result dialog — never stored,
 # never logged.
 #
 # Columns sort server-side: the header sends bootgrid's sort parameters
 # and the feed orders the whole result set before cutting the page, so
 # clicking "Name" reorders every user, not the twenty-five on screen.
 # Slug order stands when nothing is asked, and behind equal values.
 # Commands is not sortable — there is nothing to order it by.
 #}

<div class="alert alert-danger hidden" role="alert" id="errorAlert">
    <span id="errorMessage"></span>
</div>

<div class="content-box">
    <div class="content-box-main">
        <table id="grid-users" class="table table-condensed table-hover table-striped"
               data-editDialog="DialogUser" data-editAlert="userChangeMessage">
            <thead>
                <tr>
                    <th data-sortable="false" data-column-id="id" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="display_name" data-type="string">{{ lang._('Name') }}</th>
                    <th data-column-id="slug" data-type="string" data-width="10em">{{ lang._('Slug') }}</th>
                    <th data-column-id="device_count" data-type="numeric" data-width="7em">{{ lang._('Devices') }}</th>
                    <th data-column-id="last_seen_at" data-formatter="lastSeen" data-width="12em">{{ lang._('Last seen') }}</th>
                    <th data-column-id="status" data-formatter="userStatus" data-width="7em">{{ lang._('Status') }}</th>
                    {# NOT data-column-id="commands": the 26.1 bootgrid compat
                       layer force-binds a column named "commands" to its own
                       built-in formatter (which reads row[datakey]) and would
                       ignore userCommands entirely. #}
                    <th data-column-id="actions" data-formatter="userCommands" data-sortable="false" data-width="12em">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td>
                        <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-plus fa-fw"></span></button>
                    </td>
                </tr>
            </tfoot>
        </table>
        <div id="userChangeMessage" class="alert alert-info" style="display: none" role="alert">
            {{ lang._('Disabling a user permanently revokes all their devices. Enrollment tokens and rekey links are shown once, at issuance.') }}
        </div>
    </div>
</div>

<script>
    $(document).ready(function() {
        var currentRows = {};

        // Grid rows arrive HTML-escaped: searchUser hands its page to the
        // core (contract(..., false)), which escapes what it serialises
        // for a browser session — required, since the grid renders cells
        // as HTML. Keep a decoded COPY for the dialogs, which show these
        // strings through .text(); the grid keeps its own escaped rows.
        // Where a dialog title is HTML (BootstrapDialog), escape again
        // with esc(). Every other route answers raw JSON.
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

        $("#grid-users").UIBootgrid({
            search: '/api/paart/users/searchUser',
            get: '/api/paart/users/getUser/',
            set: '/api/paart/users/setUser/',
            add: '/api/paart/users/addUser/',
            datakey: 'id',
            options: {
                formatters: {
                    userStatus: function (column, row) {
                        return row.status === 'active'
                            ? '<span class="label label-success">' + "{{ lang._('Active') }}" + '</span>'
                            : '<span class="label label-default">' + "{{ lang._('Disabled') }}" + '</span>';
                    },
                    lastSeen: function (column, row) {
                        return row.last_seen_at === null
                            ? "{{ lang._('Never') }}"
                            : esc(localTime(row.last_seen_at));
                    },
                    userCommands: function (column, row) {
                        var btn = function (cls, icon, title) {
                            return '<button type="button" class="btn btn-xs btn-default ' + cls +
                                '" data-row-id="' + row.id + '" title="' + title + '">' +
                                '<span class="fa fa-fw ' + icon + '"></span></button> ';
                        };
                        var html = btn('command-edit', 'fa-pencil', "{{ lang._('Edit') }}");
                        html += btn('command-user-devices', 'fa-list', "{{ lang._('Devices') }}");
                        if (row.status === 'active') {
                            html += btn('command-user-token', 'fa-qrcode', "{{ lang._('Issue enrollment token') }}");
                            html += btn('command-user-rotate', 'fa-refresh', "{{ lang._('Rotate all devices') }}");
                            html += btn('command-user-disable', 'fa-ban', "{{ lang._('Disable') }}");
                        }
                        return html;
                    }
                }
            }
        });

        $("#grid-users").on("loaded.rs.jquery.bootgrid", function () {
            currentRows = {};
            $("#grid-users").bootgrid("getCurrentRows").forEach(function (row) {
                currentRows[row.id] = decodeRow(row);
            });
            var bind = function (cls, handler) {
                $("#grid-users").find(cls).off('click.paart').on('click.paart', function () {
                    var row = currentRows[$(this).data('row-id')];
                    if (row !== undefined) {
                        handler(row);
                    }
                });
            };
            bind('.command-user-devices', showDevices);
            bind('.command-user-token', issueToken);
            bind('.command-user-rotate', rotateAll);
            bind('.command-user-disable', disableUser);
        });

        function reload() {
            $("#grid-users").bootgrid("reload");
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

        // ------------------------------------------------ devices detail
        function showDevices(row) {
            ajaxGet('/api/paart/admin/devices', {user_id: row.id}, function (data, status) {
                if (status !== 'success' || data.devices === undefined) {
                    return;
                }
                var $table = $('<table class="table table-condensed table-striped">');
                $table.append($('<thead>').append($('<tr>')
                    .append($('<th>').text("{{ lang._('Device') }}"))
                    .append($('<th>').text("{{ lang._('Platform') }}"))
                    .append($('<th>').text("{{ lang._('IP address') }}"))
                    .append($('<th>').text("{{ lang._('Status') }}"))
                    .append($('<th>').text("{{ lang._('Last handshake') }}"))));
                var $tbody = $('<tbody>').appendTo($table);
                data.devices.forEach(function (device) {
                    $tbody.append($('<tr>')
                        .append($('<td>').text(device.label))
                        .append($('<td>').text(device.platform))
                        .append($('<td>').text(device.ip_address === null ? '—' : device.ip_address))
                        .append($('<td>').text(device.status))
                        .append($('<td>').text(device.last_handshake_at === null ? "{{ lang._('Never') }}" : device.last_handshake_at)));
                });
                BootstrapDialog.show({
                    title: "{{ lang._('Devices of') }} " + esc(row.display_name),
                    message: data.devices.length === 0
                        ? $('<div>').text("{{ lang._('No devices. Issue an enrollment token to add one.') }}")
                        : $('<div class="table-responsive">').append($table),
                    buttons: [{label: "{{ lang._('Close') }}", action: function (dialog) { dialog.close(); }}]
                });
            });
        }

        // ------------------------------------------------ issue token
        function issueToken(row) {
            ajaxGet('/api/paart/admin/health', {}, function (data, status) {
                if (status !== 'success' || data.instances === undefined) {
                    return;
                }
                if (data.instances.length === 0) {
                    BootstrapDialog.alert("{{ lang._('No network is declared yet (Networks screen). No token can be issued.') }}");
                    return;
                }
                {# no input-sm on selects: the theme clips the option text #}
                var $instance = $('<select class="form-control">');
                data.instances.forEach(function (inst) {
                    $instance.append($('<option>').val(inst.id).text(inst.label));
                });
                {# maxlength mirrors the contract's token label maxLength
                   (protocol/openapi.yaml). #}
                var $label = $('<input type="text" class="form-control input-sm" maxlength="64">');
                var $uses = $('<input type="number" class="form-control input-sm" min="1" value="1">');
                var $ttl = $('<select class="form-control">')
                    .append($('<option value="3600">').text("{{ lang._('1 hour') }}"))
                    .append($('<option value="28800">').text("{{ lang._('8 hours') }}"))
                    .append($('<option value="86400" selected>').text("{{ lang._('24 hours') }}"))
                    .append($('<option value="259200">').text("{{ lang._('3 days') }}"))
                    .append($('<option value="604800">').text("{{ lang._('7 days') }}"));
                var field = function (label, $control) {
                    return $('<div style="margin-bottom:6px;">')
                        .append($('<label style="display:block;margin-bottom:2px;">').text(label))
                        .append($control);
                };
                var $form = $('<div>')
                    .append(field("{{ lang._('Network') }}", $instance))
                    .append(field("{{ lang._('Label (optional, e.g. new phone)') }}", $label))
                    .append(field("{{ lang._('Maximum uses') }}", $uses))
                    .append(field("{{ lang._('Valid for') }}", $ttl));
                BootstrapDialog.show({
                    title: "{{ lang._('Issue enrollment token for') }} " + esc(row.display_name),
                    message: $form,
                    buttons: [
                        {label: "{{ lang._('Cancel') }}", action: function (dialog) { dialog.close(); }},
                        {label: "{{ lang._('Issue') }}", cssClass: 'btn-primary', action: function (dialog) {
                            var body = {
                                user_id: row.id,
                                instance_id: $instance.val(),
                                max_uses: $uses.val(),
                                ttl_seconds: $ttl.val()
                            };
                            if ($label.val() !== '') {
                                body.label = $label.val();
                            }
                            ajaxCall('/api/paart/admin/tokens', body, function (data, status) {
                                if (status !== 'success' || data.token === undefined) {
                                    return; // envelope shown by the page alert
                                }
                                dialog.close();
                                var $result = $('<div>')
                                    .append($('<p>').text("{{ lang._('Shown once — copy it now. Expires:') }} " + data.expires_at))
                                    .append(secretField("{{ lang._('Token') }}", data.token));
                                if (data.enroll_link !== null) {
                                    $result.append(secretField("{{ lang._('Enrollment link') }}", data.enroll_link));
                                }
                                BootstrapDialog.show({
                                    title: "{{ lang._('Enrollment token issued') }}",
                                    type: BootstrapDialog.TYPE_SUCCESS,
                                    message: $result,
                                    buttons: [{label: "{{ lang._('Close') }}", action: function (d) { d.close(); }}]
                                });
                            });
                        }}
                    ]
                });
            });
        }

        // ------------------------------------------------ rotate all
        function rotateAll(row) {
            BootstrapDialog.confirm({
                title: "{{ lang._('Rotate all devices') }}",
                type: BootstrapDialog.TYPE_WARNING,
                message: $('<div>').text(
                    "{{ lang._('Start a key rotation on every active device of') }} \"" + row.display_name + "\"? " +
                    "{{ lang._('Devices keep working during the grace period.') }}"),
                btnOKLabel: "{{ lang._('Rotate') }}",
                btnCancelLabel: "{{ lang._('Cancel') }}",
                callback: function (confirmed) {
                    if (!confirmed) {
                        return;
                    }
                    ajaxCall('/api/paart/admin/users/' + row.id + '/rotate', {}, function (data, status) {
                        if (status !== 'success' || data.rotating_device_ids === undefined) {
                            return; // envelope shown by the page alert
                        }
                        var $result = $('<div>').append($('<p>').text(
                            data.rotating_device_ids.length + " {{ lang._('device(s) now rotating.') }}"));
                        (data.rekey_tokens || []).forEach(function (entry) {
                            $result.append(secretField(
                                "{{ lang._('Rekey link (manual device, shown once)') }}",
                                entry.enroll_link !== null ? entry.enroll_link : entry.rekey_token));
                        });
                        BootstrapDialog.show({
                            title: "{{ lang._('Rotation started') }}",
                            type: BootstrapDialog.TYPE_SUCCESS,
                            message: $result,
                            buttons: [{label: "{{ lang._('Close') }}", action: function (d) { d.close(); }}]
                        });
                        reload();
                    });
                }
            });
        }

        // ------------------------------------------------ disable
        function disableUser(row) {
            BootstrapDialog.confirm({
                title: "{{ lang._('Disable user') }}",
                type: BootstrapDialog.TYPE_DANGER,
                message: $('<div>').text(
                    "{{ lang._('Disable') }} \"" + row.display_name + "\" {{ lang._('and permanently revoke') }} " +
                    row.device_count + " {{ lang._('device(s)? Their tunnels stop working immediately. This cannot be undone.') }}"),
                btnOKLabel: "{{ lang._('Disable') }}",
                btnCancelLabel: "{{ lang._('Cancel') }}",
                callback: function (confirmed) {
                    if (!confirmed) {
                        return;
                    }
                    $.ajax({
                        url: '/api/paart/admin/users/' + row.id,
                        type: 'DELETE',
                        dataType: 'json'
                    }).done(function () {
                        reload();
                    });
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

{{ partial("layout_partials/base_dialog",['fields':formDialogUser,'id':'DialogUser','label':lang._('Edit user')]) }}

{{ partial("OPNsense/Paart/footer") }}
