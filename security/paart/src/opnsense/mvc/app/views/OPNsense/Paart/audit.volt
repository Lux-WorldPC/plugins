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
 # Audit screen (M07): the full journal, paginated newest-first — the spec
 # fixes the order, so no column sorts. Filter bar above the grid: date
 # range, user, device, action type, outcome (bootgrid's own search box
 # carries the text search); every filter travels with the grid request
 # and the feed applies them server-side over the WHOLE log, not the
 # loaded page. The detail dialog shows one entry complete, including its
 # decoded detail payload (key fingerprints at most — the log never holds
 # a secret, M07). Consultation only: this screen has no write of any
 # kind, deliberately — there is no "clear log" control (M07 integrity).
 #
 # A warning banner appears when the configured retention is below the
 # spec's warning threshold — decided server-side (AuditScreen), served by
 # the overview together with the threshold the banner quotes.
 #
 # 26.1 bootgrid pitfalls apply: no column named "commands", datakey
 # pinned to the real row key.
 #}

<div class="alert alert-danger hidden" role="alert" id="errorAlert">
    <span id="errorMessage"></span>
</div>
<div class="alert alert-warning hidden" role="alert" id="retentionAlert">
    <span id="retentionMessage"></span>
</div>

<div class="content-box">
    <div class="content-box-main">
        <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:8px 8px 0 8px;">
            <label for="filter-from" style="margin:0;">{{ lang._('From') }}</label>
            <input type="date" id="filter-from" class="form-control" style="width:auto;"/>
            <label for="filter-to" style="margin:0 0 0 6px;">{{ lang._('To') }}</label>
            <input type="date" id="filter-to" class="form-control" style="width:auto;"/>
            {# width:auto shrinks a select to its text; the theme paints its
             # caret inside the padding, so leave that room or the two overlap. #}
            <select id="filter-user" class="form-control" style="width:auto;padding-right:28px;margin-left:6px;">
                <option value="">{{ lang._('All users') }}</option>
            </select>
            <select id="filter-device" class="form-control" style="width:auto;padding-right:28px;">
                <option value="">{{ lang._('All devices') }}</option>
            </select>
            <select id="filter-action" class="form-control" style="width:auto;padding-right:28px;">
                <option value="">{{ lang._('All actions') }}</option>
            </select>
            <select id="filter-outcome" class="form-control" style="width:auto;padding-right:28px;">
                <option value="">{{ lang._('Any outcome') }}</option>
                <option value="success">{{ lang._('Success') }}</option>
                <option value="failure">{{ lang._('Failure') }}</option>
            </select>
            <button type="button" id="filter-clear" class="btn btn-default">{{ lang._('Clear filters') }}</button>
        </div>
        <table id="grid-audit" class="table table-condensed table-hover table-striped">
            <thead>
                <tr>
                    <th data-sortable="false" data-column-id="id" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-sortable="false" data-column-id="occurred_at" data-formatter="occurredAt" data-width="11em">{{ lang._('When (UTC)') }}</th>
                    <th data-sortable="false" data-column-id="actor_ref" data-formatter="actor" data-width="12em">{{ lang._('Actor') }}</th>
                    <th data-sortable="false" data-column-id="action" data-type="string" data-width="12em">{{ lang._('Action') }}</th>
                    <th data-sortable="false" data-column-id="subject_ref" data-formatter="subject">{{ lang._('Subject') }}</th>
                    <th data-sortable="false" data-column-id="outcome" data-formatter="outcome" data-width="6em">{{ lang._('Outcome') }}</th>
                    {# NOT data-column-id="commands" — the 26.1 bootgrid compat
                       layer reserves that name for its own formatter. #}
                    <th data-sortable="false" data-column-id="actions" data-formatter="entryCommands" data-width="5em">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
</div>

<script>
    $(document).ready(function() {
        var currentRows = {};

        $("#grid-audit").UIBootgrid({
            search: '/api/paart/audit/searchEntry',
            datakey: 'id',
            options: {
                // The whole filter bar travels with every grid request;
                // the plumbing reads them as plain bootgrid parameters.
                requestHandler: function (request) {
                    request['from'] = $("#filter-from").val();
                    request['to'] = $("#filter-to").val();
                    request['user_id'] = $("#filter-user").val();
                    request['device_id'] = $("#filter-device").val();
                    // 'action_id', not 'action': the feed (Api\AuditController)
                    // reads exactly this name — keep the two in step.
                    request['action_id'] = $("#filter-action").val();
                    request['outcome'] = $("#filter-outcome").val();
                    return request;
                },
                formatters: {
                    occurredAt: function (column, row) {
                        // Stored as ISO UTC ("...T...Z"); render it readable
                        // without re-zoning — audit times stay UTC (spec).
                        return row.occurred_at.replace('T', ' ').replace('Z', '');
                    },
                    actor: function (column, row) {
                        var label = row.actor_label !== null ? row.actor_label : row.actor_ref;
                        return $('<div>').text(label).html() +
                            ' <span class="text-muted">(' + row.actor_type + ')</span>';
                    },
                    subject: function (column, row) {
                        var label = row.subject_label !== null ? row.subject_label : row.subject_ref;
                        return $('<div>').text(label).html() +
                            ' <span class="text-muted">(' + row.subject_type + ')</span>';
                    },
                    outcome: function (column, row) {
                        return row.outcome === 'success'
                            ? '<span class="label label-success">' + "{{ lang._('Success') }}" + '</span>'
                            : '<span class="label label-danger">' + "{{ lang._('Failure') }}" + '</span>';
                    },
                    entryCommands: function (column, row) {
                        return '<button type="button" class="btn btn-xs btn-default command-entry-detail" ' +
                            'data-row-id="' + row.id + '" title="' + "{{ lang._('Details') }}" + '">' +
                            '<span class="fa fa-fw fa-info-circle"></span></button>';
                    }
                }
            }
        });

        $("#grid-audit").on("loaded.rs.jquery.bootgrid", function () {
            currentRows = {};
            $("#grid-audit").bootgrid("getCurrentRows").forEach(function (row) {
                currentRows[row.id] = row;
            });
            $("#grid-audit").find('.command-entry-detail').off('click.paart').on('click.paart', function () {
                var row = currentRows[$(this).data('row-id')];
                if (row !== undefined) {
                    showDetail(row);
                }
            });
        });

        // Populate the filter pickers once; changing any filter reloads
        // the grid. Users and devices come complete — disabled and
        // revoked included: the journal is history.
        ajaxGet('/api/paart/audit/overview', {}, function (data, status) {
            if (status !== 'success' || data.retention === undefined) {
                return;
            }
            data.users.forEach(function (u) {
                $("#filter-user").append($('<option>').val(u.id).text(u.display_name + ' (' + u.slug + ')'));
            });
            data.devices.forEach(function (d) {
                $("#filter-device").append($('<option>').val(d.id).text(d.label + ' (' + d.user_display_name + ')'));
            });
            data.actions.forEach(function (a) {
                $("#filter-action").append($('<option>').val(a).text(a));
            });
            if (data.retention.warn) {
                $("#retentionMessage").text(
                    "{{ lang._('Audit retention is set to') }} " + data.retention.months + " " +
                    "{{ lang._('months — below the') }} " + data.retention.warn_below_months + " " +
                    "{{ lang._('months an access review usually needs. Raise it in Settings.') }}");
                $("#retentionAlert").removeClass('hidden');
            }
        });
        $("#filter-from, #filter-to, #filter-user, #filter-device, #filter-action, #filter-outcome")
            .on('change', reload);
        $("#filter-clear").on('click', function () {
            $("#filter-from, #filter-to, #filter-user, #filter-device, #filter-action, #filter-outcome").val('');
            reload();
        });

        function reload() {
            $("#grid-audit").bootgrid("reload");
        }

        function showDetail(row) {
            var kv = function ($tbody, label, value) {
                $tbody.append($('<tr>')
                    .append($('<th style="white-space:nowrap;padding-right:12px;">').text(label))
                    .append($('<td style="word-break:break-all;">').text(value)));
            };
            var $summary = $('<tbody>');
            var $table = $('<table class="table table-condensed">').append($summary);
            kv($summary, "{{ lang._('When (UTC)') }}", row.occurred_at);
            kv($summary, "{{ lang._('Actor') }}",
                (row.actor_label !== null ? row.actor_label + ' — ' + row.actor_ref : row.actor_ref) +
                ' (' + row.actor_type + ')');
            kv($summary, "{{ lang._('Action') }}", row.action);
            kv($summary, "{{ lang._('Subject') }}",
                (row.subject_label !== null ? row.subject_label + ' — ' + row.subject_ref : row.subject_ref) +
                ' (' + row.subject_type + ')');
            kv($summary, "{{ lang._('Outcome') }}", row.outcome);
            kv($summary, "{{ lang._('Source IP') }}", row.source_ip === null ? '—' : row.source_ip);

            var $message = $('<div>').append($table);
            var keys = Object.keys(row.detail || {});
            if (keys.length > 0) {
                {# Detail values may be nested (a reconciliation report);
                   render scalars bare and anything else as JSON. #}
                var $detail = $('<tbody>');
                keys.forEach(function (key) {
                    var value = row.detail[key];
                    kv($detail, key, (typeof value === 'object' && value !== null)
                        ? JSON.stringify(value) : String(value));
                });
                $message
                    .append($('<strong>').text("{{ lang._('Detail') }}"))
                    .append($('<table class="table table-condensed" style="font-family:monospace;">')
                        .append($detail));
            }
            BootstrapDialog.show({
                title: "{{ lang._('Audit entry') }}",
                message: $message,
                buttons: [{label: "{{ lang._('Close') }}", action: function (d) { d.close(); }}]
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
