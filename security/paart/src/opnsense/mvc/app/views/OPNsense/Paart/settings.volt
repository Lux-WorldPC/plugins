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
 # Settings screen (M08): global plugin settings, stored in config.xml
 # (M02 separation rule). Values apply immediately — every API request
 # composes its service graph from the current settings, no restart.
 #
 # Below the form, the public exposure panel (M09): what os-haproxy
 # holds for the plugin, and the three actions — Apply (saves the form
 # first, so the generated frontend uses the bind and certificate on
 # screen), Remove, Verify. Refusals arrive as the M01 envelope and are
 # surfaced in the alert box; verification results render as a check
 # list plus the certificate facts and the guided outside test.
 #}

<div class="alert alert-danger hidden" role="alert" id="errorAlert">
    <span id="errorMessage"></span>
</div>

<div class="content-box" style="padding-bottom: 1.5em;">
    {{ partial("layout_partials/base_form",['fields':formSettings,'id':'frm_settings']) }}
    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="saveAct" type="button">
            <b>{{ lang._('Save') }}</b> <i id="saveAct_progress"></i>
        </button>
    </div>
</div>

<div class="alert alert-info hidden" role="alert" id="responseMsg">
    {{ lang._('Settings saved. Changes apply immediately.') }}
</div>

<div class="content-box" style="margin-top: 1em; padding-bottom: 1.5em;">
    <div class="content-box-main">
        <div class="col-md-12">
            <h2>{{ lang._('Public exposure') }}</h2>
            <p>
                {{ lang._('Enrollment must work before a device has a tunnel. When the exposure is applied, the plugin adds its own objects to the HAProxy plugin (all named paart_…): a frontend on the address above that accepts only the public enrollment path, refuses everything else with 403, and forwards to this firewall over TLS. Nothing else in HAProxy is touched — except turning the HAProxy service on if it was off — and Remove takes exactly those objects away, leaving the service as it is.') }}
            </p>
            <div class="alert alert-warning hidden" role="alert" id="exposure-absent">
                {{ lang._('The os-haproxy plugin is not installed. The plugin never installs it: install it from System > Firmware > Plugins if you want to expose enrollment on the Internet — or keep enrollment internal-only, where devices enroll from the office network. That is a legitimate setup, not a fallback.') }}
            </div>
            <div class="alert alert-warning hidden" role="alert" id="exposure-unreachable">
                <span id="exposure-unreachable-text"></span>
            </div>
            <table class="table table-condensed" style="max-width: 60em; margin-bottom: 1.5em;">
                <tbody>
                    <tr><th style="width: 14em;">{{ lang._('Mode') }}</th><td id="exposure-mode"></td></tr>
                    <tr><th>{{ lang._('HAProxy plugin') }}</th><td id="exposure-haproxy"></td></tr>
                    <tr><th>{{ lang._('HAProxy service') }}</th><td id="exposure-service"></td></tr>
                    <tr><th>{{ lang._('Public path') }}</th><td id="exposure-path"></td></tr>
                    <tr><th>{{ lang._('Forwards to') }}</th><td id="exposure-backend"></td></tr>
                    <tr><th>{{ lang._('Generated objects') }}</th><td id="exposure-objects"></td></tr>
                    <tr><th>{{ lang._('Last verified') }}</th><td id="exposure-verified"></td></tr>
                </tbody>
            </table>
            <button class="btn btn-primary" id="exposure-apply" type="button">
                <b>{{ lang._('Apply exposure') }}</b> <i id="exposure-apply_progress"></i>
            </button>
            <button class="btn btn-default" id="exposure-verify" type="button">
                {{ lang._('Verify my configuration') }} <i id="exposure-verify_progress"></i>
            </button>
            <button class="btn btn-default" id="exposure-remove" type="button">
                {{ lang._('Remove exposure') }} <i id="exposure-remove_progress"></i>
            </button>
            <button class="btn btn-default" id="exposure-refresh" type="button">
                <i class="fa fa-refresh"></i>
            </button>

            <div id="exposure-result" class="hidden" style="margin-top: 1.5em; max-width: 60em;">
                <h3 id="exposure-result-title"></h3>
                <table class="table table-condensed">
                    <thead><tr>
                        <th>{{ lang._('Check') }}</th><th>{{ lang._('Path') }}</th>
                        <th>{{ lang._('Expected') }}</th><th>{{ lang._('Got') }}</th><th></th>
                    </tr></thead>
                    <tbody id="exposure-checks"></tbody>
                </table>
                <table class="table table-condensed" id="exposure-cert">
                    <tbody>
                        <tr><th style="width: 14em;">{{ lang._('Certificate') }}</th><td id="cert-subject"></td></tr>
                        <tr><th>{{ lang._('Names') }}</th><td id="cert-names"></td></tr>
                        <tr><th>{{ lang._('Valid until') }}</th><td id="cert-validity"></td></tr>
                        <tr><th>{{ lang._('SPKI SHA-256 (pin)') }}</th><td><code id="cert-spki"></code></td></tr>
                    </tbody>
                </table>
                <div class="alert alert-info" role="alert">
                    <b>{{ lang._('From the outside') }}</b> —
                    <span id="external-hint"></span>
                    <br/><a id="external-url" target="_blank" rel="noopener"></a>
                    <br/>
                    <label style="font-weight: normal; margin-top: 0.5em;">
                        <input type="checkbox" id="external-confirmed"/>
                        {{ lang._('I opened it from outside and the policy came back; Verify again to record it.') }}
                    </label>
                </div>
            </div>
        </div>
    </div>
</div>

<!--
    Uninstall cleanup (M10). Last on the page on purpose: an end-of-life
    action, not a daily one. Nothing here reads until the admin asks — the
    figures come from one call, and the button that destroys stays disabled
    until this site's own name has been typed.
-->
<div class="content-box" style="margin-top: 1em; padding-bottom: 1.5em;">
    <div class="content-box-main">
        <div class="col-md-12">
            <h2>{{ lang._('Uninstall cleanup') }}</h2>
            <p>
                {{ lang._('Removing the package keeps everything: your VPNs stay up, the peers of managed devices stay in place, and this data stays on disk. Cleaning up is the other choice, and it is made here, while the plugin can still reach the firewall.') }}
            </p>
            <button class="btn btn-default" id="cleanup-impact" type="button">
                {{ lang._('Show what a cleanup would destroy') }} <i id="cleanup-impact_progress"></i>
            </button>

            <div id="cleanup-panel" class="hidden" style="margin-top: 1.5em; max-width: 60em;">
                <table class="table table-condensed">
                    <tbody>
                        <tr><th style="width: 18em;">{{ lang._('People and devices') }}</th><td id="cleanup-people"></td></tr>
                        <tr><th>{{ lang._('Peers to delete from WireGuard') }}</th><td id="cleanup-peers"></td></tr>
                        <tr><th>{{ lang._('Generated HAProxy objects') }}</th><td id="cleanup-objects"></td></tr>
                        <tr><th>{{ lang._('Audit entries') }}</th><td id="cleanup-audit"></td></tr>
                        <tr><th>{{ lang._('Database') }}</th><td><code id="cleanup-store"></code></td></tr>
                    </tbody>
                </table>
                <table class="table table-condensed" id="cleanup-instances-table">
                    <thead>
                        <tr>
                            <th>{{ lang._('Declared instance') }}</th>
                            <th>{{ lang._('WireGuard') }}</th>
                            <th>{{ lang._('Peers deleted') }}</th>
                        </tr>
                    </thead>
                    <tbody id="cleanup-instances"></tbody>
                </table>
                <div class="alert alert-warning" role="alert" id="cleanup-unreachable">
                    <span id="cleanup-unreachable-text"></span>
                </div>
                <div class="alert alert-danger" role="alert">
                    <p>
                        <b>{{ lang._('This cannot be undone.') }}</b>
                        {{ lang._('Peers this plugin did not create are never touched, and your WireGuard instances themselves are left running.') }}
                        {{ lang._('The settings, the WireGuard API credentials and the TLS pins are removed from the firewall configuration with the rest.') }}
                    </p>
                    <label style="font-weight: normal; display: block;">
                        <input type="radio" name="cleanup-export" value="export" checked="checked"/>
                        {{ lang._('Write a snapshot of the data first, on this firewall at:') }}
                        <code id="cleanup-export-target"></code>
                    </label>
                    <label style="font-weight: normal; display: block;">
                        <input type="radio" name="cleanup-export" value="skip"/>
                        {{ lang._('Keep no copy') }}
                    </label>
                    <div style="margin-top: 1em;">
                        <label for="cleanup-confirm" style="font-weight: normal;">
                            {{ lang._('Type this site\'s name to confirm:') }}
                            <code id="cleanup-phrase"></code>
                        </label>
                        <input type="text" class="form-control" id="cleanup-confirm"
                               autocomplete="off" style="max-width: 28em;"/>
                    </div>
                    <button class="btn btn-danger" id="cleanup-purge" type="button"
                            disabled="disabled" style="margin-top: 1em;">
                        <b>{{ lang._('Clean up now') }}</b> <i id="cleanup-purge_progress"></i>
                    </button>
                </div>
            </div>

            <div id="cleanup-done" class="hidden alert alert-success" role="alert"
                 style="margin-top: 1.5em; max-width: 60em;">
                <span id="cleanup-done-text"></span>
                <div id="cleanup-done-export" class="hidden">
                    {{ lang._('The snapshot is on this firewall at') }} <code id="cleanup-done-path"></code>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    $(document).ready(function() {
        mapDataToFormUI({'frm_settings': "/api/paart/settings/get"}).done(function() {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        $("#saveAct").click(function() {
            $("#responseMsg").addClass("hidden");
            saveFormToEndpoint("/api/paart/settings/set", 'frm_settings', function() {
                $("#responseMsg").removeClass("hidden");
                loadExposure();
            });
        });

        // -------------------------------------------------- exposure (M09)

        function localTime(iso) {
            return iso === null || iso === undefined ? '' : new Date(iso).toLocaleString();
        }

        function busy(id, on) {
            $("#" + id).prop('disabled', on);
            $("#" + id + "_progress").toggleClass('fa fa-spinner fa-pulse', on);
        }

        function renderStatus(s) {
            $("#exposure-absent").toggleClass('hidden', s.haproxy !== 'absent');
            $("#exposure-unreachable").toggleClass('hidden', s.haproxy !== 'unreachable');
            $("#exposure-unreachable-text").text(s.error || '');
            $("#exposure-mode").text(s.mode === 'haproxy'
                ? "{{ lang._('Exposed through HAProxy') }}"
                : "{{ lang._('Internal only — enrollment from the local network') }}");
            $("#exposure-haproxy").text({
                absent: "{{ lang._('not installed') }}",
                present: "{{ lang._('installed') }}",
                unreachable: "{{ lang._('API unreachable') }}"
            }[s.haproxy] || s.haproxy);
            $("#exposure-service").text(s.service === null ? '—'
                : s.service + (s.service_enabled === false ? " ({{ lang._('disabled in HAProxy settings') }})" : ''));
            $("#exposure-path").text(s.public_prefix + "  →  " + s.bind + (s.enroll_host !== ''
                ? "  (" + "{{ lang._('links say') }} " + s.enroll_host + ")" : ''));
            $("#exposure-backend").text('127.0.0.1:' + s.backend_port + " ({{ lang._('this web GUI, over TLS') }})");
            $("#exposure-objects").text(s.objects.length === 0
                ? "{{ lang._('none') }}"
                : s.objects.length + ' / ' + (s.objects.length + s.missing.length)
                    + (s.missing.length > 0 ? " — {{ lang._('missing') }}: " + s.missing.join(', ') : ''));
            $("#exposure-verified").text(s.last_verified_at === null
                ? "{{ lang._('never') }}"
                : localTime(s.last_verified_at) + (s.external_confirmed_at !== null
                    ? " — {{ lang._('outside test confirmed') }} " + localTime(s.external_confirmed_at) : ''));
            var canAct = s.haproxy === 'present';
            $("#exposure-apply").prop('disabled', !canAct);
            $("#exposure-verify").prop('disabled', !(canAct && s.mode === 'haproxy'));
            $("#exposure-remove").prop('disabled', !(canAct && s.objects.length > 0));
        }

        function loadExposure() {
            ajaxGet('/api/paart/exposure/status', {}, function (data, status) {
                if (status === 'success' && data.mode !== undefined) {
                    renderStatus(data);
                }
            });
        }

        function renderVerification(r) {
            $("#exposure-result").removeClass('hidden');
            $("#exposure-result-title")
                .text(r.ok ? "{{ lang._('Verified: the endpoint answers as it should') }}"
                           : "{{ lang._('Verification failed') }}")
                .attr('class', r.ok ? 'text-success' : 'text-danger');
            var $rows = $("#exposure-checks").empty();
            r.checks.forEach(function (check) {
                $rows.append($('<tr>')
                    .append($('<td>').text(check.label))
                    .append($('<td>').append($('<code>').text(check.path)))
                    .append($('<td>').text(check.expected))
                    .append($('<td>').text(check.actual))
                    .append($('<td>').append($('<i>').attr('class',
                        check.ok ? 'fa fa-check text-success' : 'fa fa-times text-danger'))));
            });
            var c = r.certificate;
            $("#exposure-cert").toggleClass('hidden', c === null);
            if (c !== null) {
                $("#cert-subject").text(c.subject);
                $("#cert-names").text(c.sans.join(', ') + (c.matches_host ? '' : "  — {{ lang._('does not name the enrollment host') }}"))
                    .attr('class', c.matches_host ? '' : 'text-danger');
                $("#cert-validity").text(localTime(c.not_after) + ' (' + c.days_left + " {{ lang._('days') }})"
                        + (c.valid_now ? '' : "  — {{ lang._('not valid now') }}"))
                    .attr('class', c.valid_now ? '' : 'text-danger');
                $("#cert-spki").text(c.spki_sha256 + (c.matches_pin === false ? "  ≠ {{ lang._('configured pin') }}" : ''))
                    .attr('class', c.matches_pin === false ? 'text-danger' : '');
            }
            $("#external-hint").text(r.external_test.hint);
            $("#external-url").text(r.external_test.url).attr('href', r.external_test.url);
        }

        $("#exposure-refresh").click(loadExposure);

        $("#exposure-apply").click(function () {
            busy('exposure-apply', true);
            saveFormToEndpoint("/api/paart/settings/set", 'frm_settings', function () {
                ajaxCall('/api/paart/exposure/apply', {}, function (data, status) {
                    busy('exposure-apply', false);
                    if (status === 'success' && data.status !== undefined) {
                        renderStatus(data.status);
                        $("#exposure-result").addClass('hidden');
                    } else {
                        loadExposure();
                    }
                });
            }, false, function () { busy('exposure-apply', false); });
        });

        $("#exposure-verify").click(function () {
            busy('exposure-verify', true);
            ajaxCall('/api/paart/exposure/verify', {external_confirmed: $("#external-confirmed").is(':checked')},
                function (data, status) {
                    busy('exposure-verify', false);
                    if (status === 'success' && data.checks !== undefined) {
                        renderVerification(data);
                    }
                    loadExposure();
                });
        });

        $("#exposure-remove").click(function () {
            BootstrapDialog.confirm({
                title: "{{ lang._('Remove exposure') }}",
                message: "{{ lang._('Delete the paart_ objects from HAProxy and reload it? Devices will no longer enroll from the Internet; nothing else in HAProxy changes and existing tunnels are not affected.') }}",
                type: BootstrapDialog.TYPE_WARNING,
                btnOKLabel: "{{ lang._('Remove') }}",
                btnOKClass: 'btn-warning',
                callback: function (confirmed) {
                    if (!confirmed) {
                        return;
                    }
                    busy('exposure-remove', true);
                    ajaxCall('/api/paart/exposure/remove', {}, function (data, status) {
                        busy('exposure-remove', false);
                        $("#exposure-result").addClass('hidden');
                        if (status === 'success' && data.status !== undefined) {
                            renderStatus(data.status);
                        } else {
                            loadExposure();
                        }
                    });
                }
            });
        });

        // -------------------------------------------------- cleanup (M10)

        // The phrase that authorises the purge, as the server computed it.
        // Held here only to enable the button; the server checks it again
        // and is the one that decides.
        var cleanupPhrase = null;

        function renderImpact(d) {
            var live = d.totals.devices_live;
            $("#cleanup-people").text(d.totals.users + " {{ lang._('people') }}, "
                + live + " {{ lang._('devices in service') }}, "
                + d.totals.devices_revoked + " {{ lang._('revoked') }}, "
                + d.totals.tokens_active + " {{ lang._('unused enrollment tokens') }}");
            $("#cleanup-peers").text(live === 0
                ? "{{ lang._('none') }}"
                : live + " {{ lang._('peer(s), across') }} " + d.instances.length
                    + " {{ lang._('declared instance(s)') }}");
            $("#cleanup-objects").text(d.exposure.reachable
                ? (d.exposure.objects === 0 ? "{{ lang._('none') }}" : d.exposure.objects)
                : "{{ lang._('unknown — HAProxy did not answer') }}");
            $("#cleanup-audit").text(d.totals.audit_entries);
            $("#cleanup-store").text(d.store.path + (d.store.bytes === null
                ? '' : '  (' + Math.round(d.store.bytes / 1024) + " {{ lang._('KB') }})"));

            var $rows = $("#cleanup-instances").empty();
            d.instances.forEach(function (i) {
                $rows.append($('<tr>')
                    .append($('<td>').text(i.label))
                    .append($('<td>').append($('<code>').text(i.wg_instance_ref)))
                    .append($('<td>').text(i.live_peers)));
            });
            $("#cleanup-instances-table").toggleClass('hidden', d.instances.length === 0);

            // HAProxy being unreachable is shown, not hidden: the purge stops
            // on it rather than leaving objects no code will own after
            // uninstall, so the admin needs to see it before starting.
            $("#cleanup-unreachable").toggleClass('hidden', d.exposure.reachable);
            $("#cleanup-unreachable-text").text("{{ lang._('HAProxy did not answer, so its generated objects cannot be counted or removed. A cleanup would stop there and delete nothing.') }} "
                + (d.exposure.error || ''));

            $("#cleanup-export-target").text(d.export_target);
            cleanupPhrase = d.confirm_phrase;
            $("#cleanup-phrase").text(cleanupPhrase);
            $("#cleanup-confirm").val('');
            $("#cleanup-purge").prop('disabled', true);
            $("#cleanup-panel").removeClass('hidden');
            $("#cleanup-done").addClass('hidden');
        }

        $("#cleanup-impact").click(function () {
            busy('cleanup-impact', true);
            ajaxGet('/api/paart/cleanup/impact', {}, function (data, status) {
                busy('cleanup-impact', false);
                if (status === 'success' && data.totals !== undefined) {
                    renderImpact(data);
                }
            });
        });

        $("#cleanup-confirm").on('input', function () {
            $("#cleanup-purge").prop('disabled',
                cleanupPhrase === null || $(this).val().trim() !== cleanupPhrase);
        });

        $("#cleanup-purge").click(function () {
            busy('cleanup-purge', true);
            ajaxCall('/api/paart/cleanup/purge', {
                export: $("input[name='cleanup-export']:checked").val(),
                confirm: $("#cleanup-confirm").val()
            }, function (data, status) {
                busy('cleanup-purge', false);
                if (status !== 'success' || data.result !== 'purged') {
                    // The error alert at the top of the page carries the
                    // message, and it states whether anything was destroyed.
                    return;
                }
                $("#cleanup-panel").addClass('hidden');
                $("#cleanup-done-text").text(data.peers_deleted + " {{ lang._('peer(s) deleted') }}, "
                    + data.exposure_removed + " {{ lang._('HAProxy object(s) removed') }}, "
                    + "{{ lang._('settings and data removed.') }} "
                    + "{{ lang._('Your WireGuard instances are still running. You can now remove the package.') }}");
                $("#cleanup-done-export").toggleClass('hidden', data.export_path === null);
                $("#cleanup-done-path").text(data.export_path || '');
                $("#cleanup-done").removeClass('hidden');
                loadExposure();
            });
        });

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

        loadExposure();
    });
</script>

{{ partial("OPNsense/Paart/footer") }}
