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
 # Dashboard screen (M08): the landing page — five counters, the health of
 # every declared network, the spec's alert banners (pool above the
 # threshold the payload publishes, unhandled drift, rotations past their
 # grace TTL, unreachable network) and the most recent journal entries —
 # how many is the API's call, not the view's. Everything arrives from one
 # read (/api/paart/dashboard/overview), so the page is consistent with
 # itself and the firewall is probed once.
 #
 # Deliberately NOT auto-refreshing: each read runs a reachability probe
 # and a full reconciliation pass on the firewall. Refreshing is an
 # explicit act, on the button.
 #
 # Alert wording lives here, not in PHP: the API sends codes and numbers,
 # the view holds every string (M08: English, externalized for later
 # translation).
 #}

<div class="alert alert-danger hidden" role="alert" id="errorAlert">
    <span id="errorMessage"></span>
</div>

<div class="alert alert-warning hidden" role="alert" id="offlineAlert">
    {{ lang._('The WireGuard service is unreachable. Counters and journal below come from the plugin store; network health and drift are unknown. Nothing was changed.') }}
</div>

<div id="alertBanners"></div>

<div class="row" id="counters" style="margin-bottom:10px;">
    <div class="col-xs-6 col-md-3">
        <div class="content-box" style="padding:12px;text-align:center;">
            <div style="font-size:28px;font-weight:600;" id="count-users">—</div>
            <div class="text-muted">{{ lang._('Active users') }}</div>
        </div>
    </div>
    <div class="col-xs-6 col-md-3">
        <div class="content-box" style="padding:12px;text-align:center;">
            <div style="font-size:28px;font-weight:600;" id="count-devices">—</div>
            <div class="text-muted">{{ lang._('Active devices') }}</div>
        </div>
    </div>
    <div class="col-xs-6 col-md-2">
        <div class="content-box" style="padding:12px;text-align:center;">
            <div style="font-size:28px;font-weight:600;" id="count-managed">—</div>
            <div class="text-muted">{{ lang._('Managed') }}</div>
        </div>
    </div>
    <div class="col-xs-6 col-md-2">
        <div class="content-box" style="padding:12px;text-align:center;">
            <div style="font-size:28px;font-weight:600;" id="count-rotating">—</div>
            <div class="text-muted">{{ lang._('Devices rotating') }}</div>
        </div>
    </div>
    <div class="col-xs-6 col-md-2">
        <div class="content-box" style="padding:12px;text-align:center;">
            <div style="font-size:28px;font-weight:600;" id="count-drift">—</div>
            <div class="text-muted">{{ lang._('Drift findings') }}</div>
        </div>
    </div>
</div>

<section class="content-box">
    <div class="content-box-main">
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px;">
            <strong>{{ lang._('Networks') }}</strong>
            <button type="button" class="btn btn-xs btn-default" id="refresh">
                <span class="fa fa-refresh fa-fw"></span> {{ lang._('Refresh') }}
            </button>
        </div>
        <div class="table-responsive">
            <table class="table table-condensed table-hover table-striped">
                <thead>
                    <tr>
                        <th>{{ lang._('Network') }}</th>
                        <th>{{ lang._('Service') }}</th>
                        <th>{{ lang._('Address pool') }}</th>
                        <th>{{ lang._('Drift') }}</th>
                    </tr>
                </thead>
                <tbody id="health-rows">
                    <tr><td colspan="4" class="text-muted">{{ lang._('Loading…') }}</td></tr>
                </tbody>
            </table>
        </div>
        <div style="padding:8px;" class="text-muted" id="health-footer"></div>
    </div>
</section>

<section class="content-box" style="margin-top:10px;">
    <div class="content-box-main">
        <div style="padding:8px;"><strong>{{ lang._('Recent activity') }}</strong></div>
        <div class="table-responsive">
            <table class="table table-condensed table-hover table-striped">
                <thead>
                    <tr>
                        <th>{{ lang._('When') }}</th>
                        <th>{{ lang._('Who') }}</th>
                        <th>{{ lang._('Action') }}</th>
                        <th>{{ lang._('Subject') }}</th>
                        <th>{{ lang._('Outcome') }}</th>
                    </tr>
                </thead>
                <tbody id="audit-rows">
                    <tr><td colspan="5" class="text-muted">{{ lang._('Loading…') }}</td></tr>
                </tbody>
            </table>
        </div>
    </div>
</section>

<script>
    $(document).ready(function() {

        // The API sends codes and numbers; the sentences live here.
        function alertText(alert) {
            switch (alert.code) {
                case 'instance_unreachable':
                    return "{{ lang._('Network') }} “" + alert.instance + "” " +
                        "{{ lang._('is unreachable. Nothing was changed; its live state and drift are unknown.') }}";
                case 'drift':
                    var parts = [];
                    if (alert.stale_revoked > 0) {
                        parts.push(alert.stale_revoked + " {{ lang._('revoked device(s) whose peer is still live — access is NOT cut') }}");
                    }
                    if (alert.missing > 0) {
                        parts.push(alert.missing + " {{ lang._('expected peer(s) missing from the firewall') }}");
                    }
                    if (alert.conflict > 0) {
                        parts.push(alert.conflict + " {{ lang._('peer(s) on an unexpected address') }}");
                    }
                    return "{{ lang._('Network') }} “" + alert.instance + "”: " + parts.join(', ') + '. ' +
                        "{{ lang._('The plugin never corrects drift by itself — review it and act.') }}";
                case 'pool_high':
                    return "{{ lang._('Network') }} “" + alert.instance + "”: " +
                        "{{ lang._('address pool at') }} " + alert.occupancy_pct + "% " +
                        "{{ lang._('of its capacity. New enrollments will fail once it is full.') }}";
                case 'overdue_rotations':
                    return alert.count + " {{ lang._('rotation(s) are past their grace period. Access is not cut — those devices still work with their old key.') }}";
                default:
                    return alert.code;
            }
        }

        // ISO-8601 UTC (Database::utcNow) -> the browser's local format.
        function localTime(iso) {
            var t = Date.parse(iso);
            return isNaN(t) ? iso : new Date(t).toLocaleString();
        }

        function label(cls, text, title) {
            return $('<span class="label">').addClass('label-' + cls).text(text)
                .attr('title', title || '');
        }

        function renderAlerts(alerts) {
            var $box = $("#alertBanners").empty();
            alerts.forEach(function (alert) {
                $box.append($('<div role="alert">')
                    .addClass('alert alert-' + (alert.level === 'danger' ? 'danger' : 'warning'))
                    .text(alertText(alert)));
            });
        }

        function renderCounters(counters) {
            $("#count-users").text(counters.active_users);
            $("#count-devices").text(counters.active_devices);
            // A count, not a verdict: the plugin never says what a licence
            // covers (ADR 0018, D16). The title says what the number means.
            $("#count-managed").text(counters.managed_devices)
                .attr('title', "{{ lang._('Devices this site manages: apps polling the server, active or rotating. Devices set up by hand from a .conf file are not counted.') }}");
            $("#count-rotating").text(counters.rotating_devices);
            // null means no reconciliation ran (firewall down): "0 drift"
            // would be a claim nobody verified.
            $("#count-drift").text(counters.drift_findings === null ? '—' : counters.drift_findings)
                .attr('title', counters.drift_findings === null
                    ? "{{ lang._('Unknown — the WireGuard service could not be reached.') }}" : '');
        }

        function renderHealth(health, poolAlertPct) {
            var $rows = $("#health-rows").empty();
            if (health === null) {
                $rows.append($('<tr>').append($('<td colspan="4" class="text-muted">')
                    .text("{{ lang._('Unavailable — the WireGuard service could not be reached.') }}")));
                $("#health-footer").empty();
                return;
            }
            if (health.instances.length === 0) {
                $rows.append($('<tr>').append($('<td colspan="4" class="text-muted">')
                    .text("{{ lang._('No network is declared yet. Declare one under VPN Access > Networks.') }}")));
            }
            health.instances.forEach(function (instance) {
                var $service = instance.reachable
                    ? label('success', "{{ lang._('Reachable') }}")
                    : label('danger', "{{ lang._('Unreachable') }}");

                var pool = instance.pool;
                var $pool = $('<span>');
                if (pool !== undefined) {
                    $pool.append(document.createTextNode(
                        pool.used + ' / ' + pool.size + ' (' + pool.occupancy_pct + '%)'));
                    if (pool.occupancy_pct > poolAlertPct) {
                        $pool.append(' ').append(label('warning', "{{ lang._('Filling up') }}"));
                    }
                }

                var $drift = $('<span>');
                var drift = instance.drift;
                if (drift === undefined) {
                    $drift.append($('<span class="text-muted">').text('—')
                        .attr('title', "{{ lang._('Not reconciled — the network could not be read.') }}"));
                } else {
                    if (drift.stale_revoked > 0) {
                        $drift.append(label('danger', drift.stale_revoked + " {{ lang._('still live') }}",
                            "{{ lang._('Revoked devices whose peer is still on the firewall — access is not cut.') }}")).append(' ');
                    }
                    if (drift.missing > 0) {
                        $drift.append(label('warning', drift.missing + " {{ lang._('missing') }}",
                            "{{ lang._('Expected peers absent from the firewall — removed out of band.') }}")).append(' ');
                    }
                    if (drift.conflict > 0) {
                        $drift.append(label('warning', drift.conflict + " {{ lang._('conflict') }}",
                            "{{ lang._('Peers present under an unexpected address.') }}")).append(' ');
                    }
                    if (drift.stale_revoked === 0 && drift.missing === 0 && drift.conflict === 0) {
                        $drift.append(label('default', "{{ lang._('None') }}")).append(' ');
                    }
                    if (drift.unmanaged > 0) {
                        // Hand-managed peers are normal on an attached
                        // instance (D8) — informational, never an alert.
                        $drift.append($('<span class="text-muted">')
                            .text(drift.unmanaged + " {{ lang._('unmanaged') }}")
                            .attr('title', "{{ lang._('Peers this plugin does not manage. Normal — it never touches them.') }}"));
                    }
                }

                $rows.append($('<tr>')
                    .append($('<td>').text(instance.label))
                    .append($('<td>').append($service))
                    .append($('<td>').append($pool))
                    .append($('<td>').append($drift)));
            });

            var exposure = health.enrollment_exposure;
            $("#health-footer").empty()
                .append(document.createTextNode(
                    "{{ lang._('Store') }}: " + health.storage.engine +
                    ", {{ lang._('schema version') }} " + health.storage.schema_version + '. '))
                .append(document.createTextNode(
                    "{{ lang._('Enrollment exposure') }}: " +
                    (exposure.mode === 'internal_only'
                        ? "{{ lang._('not publicly exposed by the plugin') }}"
                        : exposure.mode) +
                    (exposure.last_verified_at === null
                        ? " ({{ lang._('never verified') }})"
                        : ' (' + "{{ lang._('verified') }} " + localTime(exposure.last_verified_at) + ')') + '.'));
        }

        function renderAudit(entries) {
            var $rows = $("#audit-rows").empty();
            if (entries.length === 0) {
                $rows.append($('<tr>').append($('<td colspan="5" class="text-muted">')
                    .text("{{ lang._('The journal is empty.') }}")));
                return;
            }
            entries.forEach(function (entry) {
                $rows.append($('<tr>')
                    .append($('<td style="white-space:nowrap;">').text(localTime(entry.occurred_at)))
                    .append($('<td>').text(entry.actor_ref))
                    .append($('<td>').text(entry.action))
                    .append($('<td>').text(entry.subject_type + ' ' + entry.subject_ref))
                    .append($('<td>').append(entry.outcome === 'success'
                        ? label('success', "{{ lang._('Success') }}")
                        : label('danger', "{{ lang._('Failure') }}"))));
            });
        }

        function load() {
            $("#refresh").prop('disabled', true);
            ajaxGet('/api/paart/dashboard/overview', {}, function (data, status) {
                $("#refresh").prop('disabled', false);
                if (status !== 'success' || data.counters === undefined) {
                    return; // envelope shown by the page alert
                }
                $("#offlineAlert").toggleClass('hidden', data.live);
                renderAlerts(data.alerts);
                renderCounters(data.counters);
                renderHealth(data.health, data.pool_alert_pct);
                renderAudit(data.audit);
            });
        }

        $("#refresh").click(load);
        load();

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
