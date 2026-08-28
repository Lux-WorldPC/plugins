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
 # Networks screen (M08): grid of declared instances (config.xml is
 # authoritative; the store mirrors it at declaration time, Q13) and the
 # read-only list of every WireGuard instance on this firewall — the
 # admin sees what the plugin does NOT manage (undeclared: visible,
 # never modifiable). Deep declaration errors (overlap, /24 rule, pool
 # bounds, removal refused while devices remain) come back as the M01
 # error envelope and are surfaced in the alert box.
 #
 # Withdrawal is not the framework's delete: it opens the M08 warning
 # dialog (impact list + the explicit choice about the peers) and posts
 # that choice. The built-in row command is overridden rather than
 # replaced by a button of our own, so the grid keeps rendering it in its
 # usual place; the multi-select variant is filtered out, a withdrawal
 # being one instance at a time by construction.
 #
 # Subnets (spec 01 bundle `subnets[]`) are not a field of the core form
 # dialog — that vocabulary has no list type — but a row command of their
 # own: a dialog listing label / CIDR / on-by-default in the admin's
 # order, saved as a whole to /api/paart/networks/subnets/{uuid}. Every
 # value it renders goes through .text() (contract JSON is unescaped).
 #}

<div class="alert alert-danger hidden" role="alert" id="errorAlert">
    <span id="errorMessage"></span>
</div>

<div class="content-box">
    <div class="content-box-main">
        <table id="grid-networks" class="table table-condensed table-hover table-striped"
               data-editDialog="DialogNetwork" data-editAlert="networkChangeMessage">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="enabled" data-formatter="rowtoggle" data-sortable="false" data-width="6em">{{ lang._('Enabled') }}</th>
                    <th data-column-id="label" data-type="string">{{ lang._('Label') }}</th>
                    <th data-column-id="ipRangeCidr" data-type="string">{{ lang._('Managed range') }}</th>
                    <th data-column-id="endpoint" data-type="string">{{ lang._('Public endpoint') }}</th>
                    <th data-column-id="commands" data-width="9em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
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
        <div id="networkChangeMessage" class="alert alert-info" style="display: none" role="alert">
            {{ lang._('Declarations apply immediately. Removing a network from management never touches the WireGuard instance itself; what happens to the peers of its devices is asked for, and chosen, at that moment.') }}
        </div>
    </div>
</div>

<section class="content-box" style="margin-top: 10px;">
    <div class="content-box-main">
        <div class="table-responsive">
            <table id="available-instances" class="table table-condensed table-hover table-striped">
                <caption>{{ lang._('WireGuard instances on this firewall') }}</caption>
                <thead>
                    <tr>
                        <th>{{ lang._('Instance') }}</th>
                        <th>{{ lang._('Status') }}</th>
                        <th>{{ lang._('Peers') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
        <div class="alert alert-info" role="alert">
            {{ lang._('Instances not declared above are listed for awareness only: the plugin reads their name, status and peer count for this display and never writes to them.') }}
        </div>
    </div>
</section>

<script>
    $(document).ready(function() {
        $("#grid-networks").UIBootgrid({
            search: '/api/paart/networks/searchNetwork',
            get: '/api/paart/networks/getNetwork/',
            set: '/api/paart/networks/setNetwork/',
            add: '/api/paart/networks/addNetwork/',
            del: '/api/paart/networks/delNetwork/',
            toggle: '/api/paart/networks/toggleNetwork/',
            commands: {
                // Custom row command (core UIBootgrid): the subnets dialog.
                // `sequence` orders the row buttons; the core's built-ins
                // sit at 100 (edit) and 500 (delete), so 5 puts this one first.
                'subnets': {
                    method: function (event, cell) {
                        openSubnets(cell.getData());
                    },
                    classname: 'fa fa-fw fa-sitemap',
                    title: "{{ lang._('Subnets') }}",
                    sequence: 5
                },
                // The row trash button keeps its place and its icon; only what
                // it does changes. `del` must stay declared above: the built-in
                // command requires it to render at all.
                'delete': {
                    method: function (event, cell) {
                        withdrawNetwork(cell.getData());
                    },
                    title: "{{ lang._('Remove from management') }}"
                },
                // No bulk withdrawal: the warning names the devices of ONE
                // instance, and a choice made over a selection would not be
                // the explicit one M08 asks for.
                'delete-selected': {
                    filter: function () { return false; }
                }
            }
        });

        // ------------------------------------------- withdrawal (M08)

        // Reads the impact first, so the warning states what is actually at
        // stake instead of a generic "are you sure". The store answers alone:
        // an unreachable firewall must not stop an admin from seeing it.
        function withdrawNetwork(row) {
            ajaxGet('/api/paart/networks/impact/' + row.uuid, {}, function (data, status) {
                if (status !== 'success' || data.devices === undefined) {
                    return; // envelope shown by the page alert
                }
                withdrawDialog(row, data);
            });
        }

        function withdrawDialog(row, impact) {
            // impact comes raw from a contract route; the grid row comes
            // from searchBase, outside contract(), so the core has
            // HTML-escaped it — decode it.
            var label = impact.instance.label || htmlDecode(row.label);
            var $body = $('<div>');
            $body.append($('<p>').append($('<strong>').text(
                "{{ lang._('Remove') }} \"" + label + "\" {{ lang._('from management?') }}")));
            $body.append($('<p>').text(
                "{{ lang._('The WireGuard instance itself is never touched: it keeps running, with its own peers, exactly as it is. What goes away is everything this plugin knows about it — device records, address allocations, enrollment tokens — and that cannot be undone.') }}"));

            var extra = [];
            if (impact.revoked_count > 0) {
                extra.push(impact.revoked_count + " {{ lang._('revoked device record(s)') }}");
            }
            if (impact.active_tokens > 0) {
                extra.push(impact.active_tokens + " {{ lang._('enrollment token(s) still valid') }}");
            }
            if (extra.length > 0) {
                $body.append($('<p>').text(
                    "{{ lang._('Also removed:') }} " + extra.join(', ') + '.'));
            }

            var $keep = $('<input type="radio" name="paart-peers" value="keep" checked>');
            var $del = $('<input type="radio" name="paart-peers" value="delete">');
            var $confirm = $('<input type="text" class="form-control" autocomplete="off">');
            var $confirmBlock = $('<div>')
                .append($('<p>').text("{{ lang._('Type the network label to confirm:') }}"))
                .append($confirm)
                .hide();

            if (impact.live_count > 0) {
                var $list = $('<ul>');
                impact.devices.forEach(function (d) {
                    $list.append($('<li>').text(
                        d.user_display_name + ' — ' + d.label +
                        (d.ip_address === null ? '' : ' (' + d.ip_address + ')')));
                });
                $body.append($('<p>').append($('<strong>').text(
                    impact.live_count + " {{ lang._('device(s) are still in service on this network:') }}")));
                $body.append($list);
                $body.append($('<p>').text("{{ lang._('Choose what happens to their WireGuard peers:') }}"));
                $body.append($('<div class="radio">').append($('<label>')
                    .append($keep)
                    .append(document.createTextNode(
                        " {{ lang._('Keep the peers. Their tunnels keep working, on an instance this plugin no longer manages.') }}"))));
                $body.append($('<div class="radio">').append($('<label>')
                    .append($del)
                    .append(document.createTextNode(
                        " {{ lang._('Delete the peers. Their tunnels stop immediately.') }}"))));
                $body.append($confirmBlock);
            }

            BootstrapDialog.show({
                title: "{{ lang._('Remove network from management') }}",
                type: BootstrapDialog.TYPE_DANGER,
                message: $body,
                buttons: [
                    {label: "{{ lang._('Cancel') }}", action: function (dialog) { dialog.close(); }},
                    {id: 'btn-network-withdraw-ok', label: "{{ lang._('Remove') }}", cssClass: 'btn-danger',
                     action: function (dialog) {
                        var params = {};
                        // Nothing in service: no choice to make, and the API's
                        // strict path (no 'peers') is the one that refuses if
                        // that stopped being true since the impact was read.
                        if (impact.live_count > 0) {
                            params.peers = $del.is(':checked') ? 'delete' : 'keep';
                        }
                        ajaxCall('/api/paart/networks/delNetwork/' + row.uuid, params,
                            function (data, status) {
                                if (status !== 'success' || data.result !== 'deleted') {
                                    return; // envelope shown by the page alert
                                }
                                dialog.close();
                                $("#grid-networks").bootgrid('reload');
                            });
                    }}
                ],
                // M08 Confirmations: deleting live peers is irreversible, so
                // that branch alone asks for the label to be retyped; keeping
                // them needs no such barrier.
                onshown: function (dialog) {
                    var $ok = dialog.getButton('btn-network-withdraw-ok');
                    var arm = function () {
                        if (impact.live_count === 0 || !$del.is(':checked')) {
                            $confirmBlock.hide();
                            $ok.enable();
                            return;
                        }
                        $confirmBlock.show();
                        if ($confirm.val() === label) {
                            $ok.enable();
                        } else {
                            $ok.disable();
                        }
                    };
                    $keep.add($del).off('change.paart').on('change.paart', arm);
                    $confirm.off('input.paart').on('input.paart', arm);
                    arm();
                }
            });
        }

        // ------------------------------------------- subnets (M08)

        // One editable row of the subnets table. `id` is the stored ULID
        // (empty for a new row) — posted back so the server keeps it and
        // the devices keep their switch state for that subnet. The label
        // maxlength mirrors Domain\Subnets::MAX_LABEL_LENGTH (64); the
        // per-network cap (32) is not enforced here — the server refuses
        // the 33rd row with an actionable message, like any other rule.
        function subnetRow(subnet) {
            var $tr = $('<tr>').data('id', subnet.id || '');
            $tr.append($('<td>').append(
                $('<input type="text" class="form-control input-sm paart-subnet-label" maxlength="64">')
                    .val(subnet.label || '')));
            $tr.append($('<td>').append(
                $('<input type="text" class="form-control input-sm paart-subnet-cidr" placeholder="10.7.1.0/24">')
                    .val(subnet.cidr || '')));
            $tr.append($('<td class="text-center">').append(
                $('<input type="checkbox" class="paart-subnet-default">').prop('checked', !!subnet.default_on)));
            var $up = $('<button type="button" class="btn btn-default btn-xs" title="{{ lang._('Move up') }}"><span class="fa fa-arrow-up fa-fw"></span></button>')
                .on('click', function () { var $p = $tr.prev(); if ($p.length) { $tr.insertBefore($p); } });
            var $down = $('<button type="button" class="btn btn-default btn-xs" title="{{ lang._('Move down') }}"><span class="fa fa-arrow-down fa-fw"></span></button>')
                .on('click', function () { var $n = $tr.next(); if ($n.length) { $tr.insertAfter($n); } });
            var $remove = $('<button type="button" class="btn btn-default btn-xs" title="{{ lang._('Remove') }}"><span class="fa fa-trash-o fa-fw"></span></button>')
                .on('click', function () { $tr.remove(); });
            $tr.append($('<td class="text-nowrap">').append($up).append(' ').append($down).append(' ').append($remove));
            return $tr;
        }

        function openSubnets(row) {
            ajaxGet('/api/paart/networks/subnets/' + row.uuid, {}, function (data, status) {
                if (status !== 'success' || data.subnets === undefined) {
                    return; // envelope shown by the page alert
                }
                subnetsDialog(row, data);
            });
        }

        function subnetsDialog(row, data) {
            var label = data.instance.label || htmlDecode(row.label);
            var $body = $('<div>');
            $body.append($('<p>').text(
                "{{ lang._('Managed devices receive this list in their bundle and show one switch per subnet. The subnets switched on by default are what a device routes through the tunnel; with none switched on, every subnet is; with no subnet declared at all, everything goes through the tunnel.') }}"));
            if (!data.allow_subnet_toggle) {
                $body.append($('<p class="text-muted">').text(
                    "{{ lang._('Subnet toggling is off for this network (Edit network, advanced): devices route the defaults and cannot change them.') }}"));
            }
            var $tbody = $('<tbody>');
            data.subnets.forEach(function (s) { $tbody.append(subnetRow(s)); });
            var $table = $('<table class="table table-condensed">')
                .append($('<thead>').append($('<tr>')
                    .append($('<th>').text("{{ lang._('Label') }}"))
                    .append($('<th>').text("{{ lang._('CIDR') }}"))
                    .append($('<th class="text-center">').text("{{ lang._('On by default') }}"))
                    .append($('<th>'))))
                .append($tbody);
            $body.append($('<div class="table-responsive">').append($table));
            $body.append($('<button type="button" class="btn btn-default btn-xs">')
                .append('<span class="fa fa-plus fa-fw"></span> ')
                .append(document.createTextNode("{{ lang._('Add subnet') }}"))
                .on('click', function () {
                    $tbody.append(subnetRow({}));
                    $tbody.find('tr:last .paart-subnet-label').focus();
                }));
            var $error = $('<div class="alert alert-danger" style="margin-top: 10px">').hide();
            $body.append($error);

            BootstrapDialog.show({
                // BootstrapDialog takes a jQuery title: the label is data,
                // rendered by .text() like everything else on this page.
                title: $('<span>').text("{{ lang._('Subnets of') }} \"" + label + "\""),
                type: BootstrapDialog.TYPE_PRIMARY,
                size: BootstrapDialog.SIZE_WIDE,
                message: $body,
                buttons: [
                    {label: "{{ lang._('Cancel') }}", action: function (dialog) { dialog.close(); }},
                    {label: "{{ lang._('Save') }}", cssClass: 'btn-primary', action: function (dialog) {
                        var subnets = [];
                        $tbody.find('tr').each(function () {
                            var $tr = $(this);
                            subnets.push({
                                id: $tr.data('id'),
                                label: $tr.find('.paart-subnet-label').val(),
                                cidr: $tr.find('.paart-subnet-cidr').val(),
                                default_on: $tr.find('.paart-subnet-default').is(':checked')
                            });
                        });
                        $error.hide();
                        ajaxCall('/api/paart/networks/subnets/' + row.uuid, {subnets: subnets},
                            function (data, status) {
                                if (status !== 'success' || data === undefined || data.result !== 'saved') {
                                    // The refusal names the row and what to fix;
                                    // keep the admin's edits in front of it.
                                    var message = (data && data.error && data.error.message)
                                        ? data.error.message
                                        : "{{ lang._('The request failed. Nothing is known to have changed.') }}";
                                    $error.text(message).show();
                                    return;
                                }
                                dialog.close();
                            });
                    }}
                ]
            });
        }

        // Repaints the read-only instance table. The dialog's wgInstanceRef
        // dropdown is NOT touched here: it is a ModelRelationField, fed by
        // the framework from getNetwork's option map (setFormData() empties
        // and refills every <select> on each dialog open, so any JS-injected
        // options would be wiped anyway). The domain still refuses a
        // duplicate declaration server-side.
        function refreshAvailable() {
            ajaxGet('/api/paart/networks/available', {}, function(data, status) {
                if (status !== 'success' || data.instances === undefined) {
                    return;
                }
                var $tbody = $("#available-instances tbody").empty();
                data.instances.forEach(function(row) {
                    var status_text = row.declared
                        ? "{{ lang._('Managed as') }} \"" + (row.label || '') + "\""
                        : "{{ lang._('Not managed') }}";
                    $tbody.append($("<tr>")
                        .append($("<td>").text(row.name))
                        .append($("<td>").text(status_text))
                        .append($("<td>").text(row.peer_count)));
                });
            });
        }
        refreshAvailable();
        $("#grid-networks").on("loaded.rs.jquery.bootgrid", refreshAvailable);

        // Deep refusals (range overlap, devices still attached, WireGuard
        // service unreachable) arrive as the M01 envelope: show the
        // actionable message, which always states whether anything changed.
        $(document).ajaxError(function(event, jqxhr) {
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
        $(document).ajaxSuccess(function() {
            $("#errorAlert").addClass('hidden');
        });
    });
</script>

{{ partial("layout_partials/base_dialog",['fields':formDialogNetwork,'id':'DialogNetwork','label':lang._('Edit network')]) }}

{{ partial("OPNsense/Paart/footer") }}
