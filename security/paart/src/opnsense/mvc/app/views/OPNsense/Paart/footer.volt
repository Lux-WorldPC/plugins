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
 # Publisher footer, included by every screen of the plugin
 # ({{ partial("OPNsense/Paart/footer") }} as the last line of each view),
 # so the notice exists in exactly one place.
 #
 # The site and mail addresses are links, never loaded resources: the page
 # fetches nothing from outside the firewall (D2 — no dependency on an
 # editor's server, forbidden rule #6).
 #
 # Not passed through lang._(): a company name, a person's name and two
 # addresses are proper nouns, and translating them would be wrong.
 #}
<div class="text-muted"
     style="margin-top:14px;padding:8px;text-align:center;font-size:11px;">
    © Lux-World PC SARL — Developed &amp; maintained by François MAYMIL —
    <a href="https://www.lwpc.lu" target="_blank" rel="noopener noreferrer">www.lwpc.lu</a> —
    <a href="mailto:fm@lwpc.lu">fm@lwpc.lu</a>
</div>
