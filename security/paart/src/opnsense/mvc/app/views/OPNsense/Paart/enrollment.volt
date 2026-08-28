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
 # Enrollment screen (M08): hand someone a VPN access. Choose the person
 # and the target network — the admin fixes the network, never the
 # enrolling user — then the number of uses and the validity, and the QR
 # code appears large with its link and a copy button underneath. Below,
 # the tokens still valid, each with a live countdown and a revoke button.
 #
 # The token and its links are shown ONCE, at issuance — the lwpcvpn://
 # app link and, since M15, the browser portal link (portal_link), with
 # a choice of which one the QR encodes: the store keeps
 # hashes only (M04), so nothing on this page can bring them back. The
 # active-token table therefore lists what a token is for, never what it
 # is.
 #
 # The QR is drawn in the page by the QR library OPNsense already ships
 # (/ui/js/qrcode.js and its jQuery binding jquery.qrcode.js, used by the
 # core's OTP screens): no remote
 # generator, no call to an editor's server (forbidden rule #6). The link
 # carries a live credential, and it travels to the admin's browser and
 # nowhere else — no third party ever sees it.
 # Error correction level M, as protocol/enrollment-link.md prescribes:
 # fewer modules than level H for the same link, so larger modules and an
 # easier scan at arm's length.
 #
 # Reads come from one call (/api/paart/enrollment/overview), writes go to
 # the recetted contract routes (/api/paart/admin/tokens), whose refusals
 # arrive as the M01 envelope and are surfaced in the alert box.
 #
 # Countdowns are anchored on the server clock: the payload carries 'now'
 # alongside every expiry, and the page keeps the offset from the browser's
 # own clock, so a drifting workstation still shows the time the firewall
 # will honour.
 #}

<script src="{{ cache_safe('/ui/js/jquery.qrcode.js') }}"></script>
<script src="{{ cache_safe('/ui/js/qrcode.js') }}"></script>

<div class="alert alert-danger hidden" role="alert" id="errorAlert">
    <span id="errorMessage"></span>
</div>

<div class="alert alert-warning hidden" role="alert" id="noHostAlert">
    {{ lang._('No enrollment host is configured, so no enrollment link can be built and no token can be issued. Set it under VPN Access > Settings.') }}
</div>

<div class="alert alert-warning hidden" role="alert" id="noNetworkAlert">
    {{ lang._('No network is declared yet, so there is nothing to enroll onto. Declare one under VPN Access > Networks.') }}
</div>

<div class="alert alert-warning hidden" role="alert" id="noUserAlert">
    {{ lang._('No active user yet. Create one under VPN Access > Users.') }}
</div>

<section class="content-box">
    <div class="content-box-main">
        <div style="padding:8px;"><strong>{{ lang._('Issue an enrollment token') }}</strong></div>
        <div style="padding:0 8px 8px 8px;" class="row">
            <div class="col-md-3 col-sm-6">
                <label style="display:block;" for="issue-user">{{ lang._('Person') }}</label>
                {# no input-sm on selects: the theme clips the option text #}
                <select class="form-control" id="issue-user"></select>
            </div>
            <div class="col-md-3 col-sm-6">
                <label style="display:block;" for="issue-instance">{{ lang._('Network') }}</label>
                <select class="form-control" id="issue-instance"></select>
            </div>
            <div class="col-md-2 col-sm-4">
                {# maxlength mirrors the contract's token label maxLength
                   (protocol/openapi.yaml). #}
                <label style="display:block;" for="issue-label">{{ lang._('Label (optional)') }}</label>
                <input type="text" class="form-control input-sm" id="issue-label" maxlength="64"
                       placeholder="{{ lang._('e.g. new phone') }}">
            </div>
            <div class="col-md-2 col-sm-4">
                <label style="display:block;" for="issue-uses">{{ lang._('Maximum uses') }}</label>
                <input type="number" class="form-control input-sm" id="issue-uses" min="1" value="1">
            </div>
            <div class="col-md-2 col-sm-4">
                <label style="display:block;" for="issue-ttl">{{ lang._('Valid for') }}</label>
                <select class="form-control" id="issue-ttl">
                    <option value="3600">{{ lang._('1 hour') }}</option>
                    <option value="28800">{{ lang._('8 hours') }}</option>
                    <option value="86400" selected="selected">{{ lang._('24 hours') }}</option>
                    <option value="259200">{{ lang._('3 days') }}</option>
                    <option value="604800">{{ lang._('7 days') }}</option>
                </select>
            </div>
        </div>
        <div style="padding:0 8px 8px 8px;">
            <button type="button" class="btn btn-primary" id="issue">
                <span class="fa fa-qrcode fa-fw"></span> {{ lang._('Issue') }}
            </button>
        </div>
    </div>
</section>

<section class="content-box hidden" style="margin-top:10px;" id="issuedBox">
    <div class="content-box-main">
        <div style="padding:8px;">
            <strong id="issuedTitle"></strong>
        </div>
        <div class="alert alert-info" style="margin:0 8px 8px 8px;">
            {{ lang._('Shown once. Scan it now, or copy the link and send it. Once you leave this page it cannot be shown again — issue a new token instead.') }}
        </div>
        <div style="padding:0 8px 8px 8px;text-align:center;">
            <div id="qr" style="display:inline-block;background:#fff;padding:12px;"></div>
            <div id="qrChoice" class="hidden" style="margin-top:6px;">
                <label class="radio-inline"><input type="radio" name="qrKind" id="qrApp" checked="checked"> {{ lang._('QR for the app') }}</label>
                <label class="radio-inline"><input type="radio" name="qrKind" id="qrPortal"> {{ lang._('QR for the browser portal') }}</label>
            </div>
        </div>
        <div style="padding:0 8px 12px 8px;max-width:760px;margin:0 auto;">
            <div id="issuedLink"></div>
            <div id="issuedToken"></div>
            <p class="text-muted" style="margin-top:6px;" id="issuedExpiry"></p>
        </div>
    </div>
</section>

<section class="content-box" style="margin-top:10px;">
    <div class="content-box-main">
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px;">
            <strong>{{ lang._('Active tokens') }}</strong>
            <button type="button" class="btn btn-xs btn-default" id="refresh">
                <span class="fa fa-refresh fa-fw"></span> {{ lang._('Refresh') }}
            </button>
        </div>
        <div class="table-responsive">
            <table class="table table-condensed table-hover table-striped">
                <thead>
                    <tr>
                        <th>{{ lang._('Person') }}</th>
                        <th>{{ lang._('Network') }}</th>
                        <th>{{ lang._('Label') }}</th>
                        <th>{{ lang._('Uses left') }}</th>
                        <th>{{ lang._('Expires in') }}</th>
                        <th>{{ lang._('Commands') }}</th>
                    </tr>
                </thead>
                <tbody id="token-rows">
                    <tr><td colspan="6" class="text-muted">{{ lang._('Loading…') }}</td></tr>
                </tbody>
            </table>
        </div>
    </div>
</section>

<script>
    $(document).ready(function() {

        // Server clock minus browser clock, in milliseconds: every
        // countdown is measured against the firewall's time, not the
        // workstation's (see the header).
        var clockSkew = 0;

        // ISO-8601 UTC (Database::utcNow) -> the browser's local format.
        function localTime(iso) {
            var t = Date.parse(iso);
            return isNaN(t) ? iso : new Date(t).toLocaleString();
        }

        // Whole seconds until an ISO-8601 UTC instant, server-anchored.
        function secondsUntil(iso) {
            var t = Date.parse(iso);
            return isNaN(t) ? null : Math.round((t - (Date.now() + clockSkew)) / 1000);
        }

        // Coarse on purpose: an enrollment window is minutes or days, and
        // a ticking seconds counter would only invite watching it.
        function humanDuration(seconds) {
            if (seconds === null) {
                return '—';
            }
            if (seconds <= 0) {
                return "{{ lang._('expired') }}";
            }
            if (seconds < 3600) {
                return Math.max(1, Math.round(seconds / 60)) + " {{ lang._('min') }}";
            }
            if (seconds < 172800) {
                return Math.round(seconds / 3600) + " {{ lang._('h') }}";
            }
            return Math.round(seconds / 86400) + " {{ lang._('days') }}";
        }

        function secretField(label, value) {
            var $input = $('<input type="text" readonly class="form-control input-sm" style="margin-bottom:4px;">').val(value);
            var $copy = $('<button type="button" class="btn btn-sm btn-default" style="margin-left:4px;">')
                .append($('<span class="fa fa-clipboard fa-fw">'))
                .append(document.createTextNode(' ' + "{{ lang._('Copy') }}"))
                .on('click', function () { $input.trigger('select'); document.execCommand('copy'); });
            return $('<div style="margin-bottom:6px;">')
                .append($('<strong>').text(label))
                .append($('<div style="display:flex;align-items:center;">').append($input).append($copy));
        }

        // -------------------------------------------------- pickers

        // Rebuilt on every load; the current choice survives a refresh so
        // issuing several tokens in a row does not mean re-picking.
        function fillSelect($select, items, textOf) {
            var previous = $select.val();
            $select.empty();
            items.forEach(function (item) {
                $select.append($('<option>').val(item.id).text(textOf(item)));
            });
            if (previous !== null && $select.find('option[value="' + previous + '"]').length > 0) {
                $select.val(previous);
            }
        }

        // -------------------------------------------------- active tokens

        function renderTokens(tokens) {
            var $rows = $("#token-rows").empty();
            if (tokens.length === 0) {
                $rows.append($('<tr>').append($('<td colspan="6" class="text-muted">')
                    .text("{{ lang._('No active enrollment token.') }}")));
                return;
            }
            tokens.forEach(function (token) {
                var $revoke = $('<button type="button" class="btn btn-xs btn-default">')
                    .attr('title', "{{ lang._('Revoke this token') }}")
                    .append($('<span class="fa fa-ban fa-fw">'))
                    .on('click', function () { revokeToken(token); });
                $rows.append($('<tr>')
                    .append($('<td>').text(token.user_display_name)
                        .attr('title', token.user_slug))
                    .append($('<td>').text(token.instance_label))
                    .append($('<td>').text(token.label))
                    .append($('<td>').text(token.uses_left + ' / ' + token.max_uses))
                    .append($('<td style="white-space:nowrap;" class="token-expiry">')
                        .attr('data-expires', token.expires_at)
                        .attr('title', localTime(token.expires_at))
                        .text(humanDuration(secondsUntil(token.expires_at))))
                    .append($('<td>').append($revoke)));
            });
        }

        // Re-read from each cell's own expiry, so the table stays honest
        // between two loads without asking the server again.
        function tickCountdowns() {
            $(".token-expiry").each(function () {
                var $cell = $(this);
                $cell.text(humanDuration(secondsUntil($cell.attr('data-expires'))));
            });
        }

        function revokeToken(token) {
            BootstrapDialog.confirm({
                title: "{{ lang._('Revoke enrollment token') }}",
                type: BootstrapDialog.TYPE_WARNING,
                message: $('<div>').text(
                    "{{ lang._('Revoke the enrollment token issued for') }} \"" +
                    token.user_display_name + "\"? " +
                    "{{ lang._('Anyone still holding its link or QR code will no longer be able to enroll. Devices already enrolled with it keep working.') }}"),
                btnOKLabel: "{{ lang._('Revoke') }}",
                btnCancelLabel: "{{ lang._('Cancel') }}",
                callback: function (confirmed) {
                    if (!confirmed) {
                        return;
                    }
                    $.ajax({
                        url: '/api/paart/admin/tokens/' + token.id,
                        type: 'DELETE',
                        dataType: 'json'
                    }).done(function () {
                        load();
                    });
                }
            });
        }

        // -------------------------------------------------- issue

        // Level M and a large drawing (320 px a side, so big modules): the
        // code has to scan from a phone held about 40 cm from the screen
        // (M08 acceptance criterion, verified on a phone).
        function drawQr(text) {
            $("#qr").empty().qrcode({
                text: text,
                width: 320,
                height: 320,
                correctLevel: QRErrorCorrectLevel.M
            });
        }

        function showIssued(data, personName) {
            $("#issuedTitle").text(
                "{{ lang._('Enrollment token for') }} " + personName);
            $("#qr").empty();
            $("#issuedLink").empty();
            $("#qrChoice").addClass('hidden');
            var hasApp = data.enroll_link !== null && data.enroll_link !== undefined;
            var hasPortal = data.portal_link !== null && data.portal_link !== undefined;
            if (hasApp) {
                drawQr(data.enroll_link);
                $("#issuedLink").append(
                    secretField("{{ lang._('App link (scan with the app)') }}", data.enroll_link));
            }
            if (hasPortal) {
                // The browser flow (M15): Windows, Linux, Android, any
                // device with a classic WireGuard client.
                $("#issuedLink").append(
                    secretField("{{ lang._('Portal link (open in a browser)') }}", data.portal_link));
            }
            if (hasApp && hasPortal) {
                $("#qrChoice").removeClass('hidden');
                $("#qrApp").prop('checked', true);
                $("#qrChoice input").off('change').on('change', function () {
                    drawQr($("#qrPortal").prop('checked') ? data.portal_link : data.enroll_link);
                });
            } else if (hasPortal && !hasApp) {
                drawQr(data.portal_link);
            }
            $("#issuedToken").empty().append(
                secretField("{{ lang._('Token') }}", data.token));
            $("#issuedExpiry").text(
                "{{ lang._('Valid until') }} " + localTime(data.expires_at) +
                ' — ' + data.max_uses + " {{ lang._('use(s).') }}");
            $("#issuedBox").removeClass('hidden');
            $("#issuedBox")[0].scrollIntoView({block: 'start'});
        }

        function issue() {
            var userId = $("#issue-user").val();
            var instanceId = $("#issue-instance").val();
            if (userId === null || instanceId === null) {
                return; // the banners above already say what is missing
            }
            var body = {
                user_id: userId,
                instance_id: instanceId,
                max_uses: $("#issue-uses").val(),
                ttl_seconds: $("#issue-ttl").val()
            };
            if ($("#issue-label").val() !== '') {
                body.label = $("#issue-label").val();
            }
            var personName = $("#issue-user").find('option:selected').text();
            $("#issue").prop('disabled', true);
            ajaxCall('/api/paart/admin/tokens', body, function (data, status) {
                $("#issue").prop('disabled', false);
                if (status !== 'success' || data.token === undefined) {
                    return; // envelope shown by the page alert
                }
                showIssued(data, personName);
                $("#issue-label").val('');
                load();
            });
        }

        // -------------------------------------------------- load

        function load() {
            $("#refresh").prop('disabled', true);
            ajaxGet('/api/paart/enrollment/overview', {}, function (data, status) {
                $("#refresh").prop('disabled', false);
                if (status !== 'success' || data.tokens === undefined) {
                    return; // envelope shown by the page alert
                }
                clockSkew = Date.parse(data.now) - Date.now();

                fillSelect($("#issue-user"), data.users, function (user) {
                    return user.display_name + ' (' + user.slug + ')';
                });
                fillSelect($("#issue-instance"), data.instances, function (instance) {
                    return instance.label;
                });

                $("#noHostAlert").toggleClass('hidden', data.enroll_host_configured);
                $("#noNetworkAlert").toggleClass('hidden', data.instances.length > 0);
                $("#noUserAlert").toggleClass('hidden', data.users.length > 0);
                $("#issue").prop('disabled',
                    !data.enroll_host_configured ||
                    data.instances.length === 0 ||
                    data.users.length === 0);

                renderTokens(data.tokens);
            });
        }

        $("#issue").click(issue);
        $("#refresh").click(load);
        load();
        window.setInterval(tickCountdowns, 30000);

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
