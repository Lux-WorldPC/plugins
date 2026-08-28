/*
 * Copyright (C) 2026 Lux-World PC SARL
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * X25519 in plain JavaScript — the enrollment portal's fallback when the
 * browser's WebCrypto has no X25519 (M15). Inlined into the portal page by
 * Enroll\Portal; never loaded from a URL (the page carries no external
 * resource, and the exposure ACL would refuse one anyway).
 *
 * Derived from TweetNaCl-js (crypto_scalarmult, public domain,
 * https://tweetnacl.js.org): 16 x 16-bit limbs in Float64Array, the
 * Montgomery ladder of RFC 7748. Only key generation is needed here
 * (public = scalarmult(clamped secret, 9)); the shared-secret path is
 * not exposed. Verified against the RFC 7748 §6.1 vectors and WebCrypto
 * (plugin/tests/portal-x25519.test.js under Node).
 */
var PaartX25519 = (function () {
    'use strict';

    function gf(init) {
        var r = new Float64Array(16);
        if (init) { for (var i = 0; i < init.length; i++) r[i] = init[i]; }
        return r;
    }
    var _9 = new Uint8Array(32); _9[0] = 9;
    var _121665 = gf([0xdb41, 1]);

    function car25519(o) {
        var i, v, c = 1;
        for (i = 0; i < 16; i++) {
            v = o[i] + c + 65535;
            c = Math.floor(v / 65536);
            o[i] = v - c * 65536;
        }
        o[0] += c - 1 + 37 * (c - 1);
    }
    function sel25519(p, q, b) {
        var t, c = ~(b - 1);
        for (var i = 0; i < 16; i++) {
            t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }
    function pack25519(o, n) {
        var i, j, b, m = gf(), t = gf();
        for (i = 0; i < 16; i++) t[i] = n[i];
        car25519(t); car25519(t); car25519(t);
        for (j = 0; j < 2; j++) {
            m[0] = t[0] - 0xffed;
            for (i = 1; i < 15; i++) {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            b = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            sel25519(t, m, 1 - b);
        }
        for (i = 0; i < 16; i++) {
            o[2 * i] = t[i] & 0xff;
            o[2 * i + 1] = t[i] >> 8;
        }
    }
    function unpack25519(o, n) {
        for (var i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
        o[15] &= 0x7fff;
    }
    function A(o, a, b) { for (var i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
    function Z(o, a, b) { for (var i = 0; i < 16; i++) o[i] = a[i] - b[i]; }
    function M(o, a, b) {
        var i, j, t = new Float64Array(31);
        for (i = 0; i < 31; i++) t[i] = 0;
        for (i = 0; i < 16; i++) { for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j]; }
        for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
        for (i = 0; i < 16; i++) o[i] = t[i];
        car25519(o); car25519(o);
    }
    function S(o, a) { M(o, a, a); }
    function inv25519(o, i) {
        var c = gf(), a;
        for (a = 0; a < 16; a++) c[a] = i[a];
        for (a = 253; a >= 0; a--) {
            S(c, c);
            if (a !== 2 && a !== 4) M(c, c, i);
        }
        for (a = 0; a < 16; a++) o[a] = c[a];
    }

    /** q = n * p on the Montgomery curve; n is clamped as RFC 7748 requires. */
    function scalarmult(q, n, p) {
        var z = new Uint8Array(32), x = new Float64Array(80), r, i;
        var a = gf(), b = gf(), c = gf(), d = gf(), e = gf(), f = gf();
        for (i = 0; i < 31; i++) z[i] = n[i];
        z[31] = (n[31] & 127) | 64;
        z[0] &= 248;
        unpack25519(x, p);
        for (i = 0; i < 16; i++) { b[i] = x[i]; d[i] = a[i] = c[i] = 0; }
        a[0] = d[0] = 1;
        for (i = 254; i >= 0; --i) {
            r = (z[i >>> 3] >>> (i & 7)) & 1;
            sel25519(a, b, r); sel25519(c, d, r);
            A(e, a, c); Z(a, a, c); A(c, b, d); Z(b, b, d);
            S(d, e); S(f, a);
            M(a, c, a); M(c, b, e);
            A(e, a, c); Z(a, a, c);
            S(b, a); Z(c, d, f);
            M(a, c, _121665); A(a, a, d);
            M(c, c, a); M(a, d, f); M(d, b, x); S(b, e);
            sel25519(a, b, r); sel25519(c, d, r);
        }
        for (i = 0; i < 16; i++) { x[i + 16] = a[i]; x[i + 32] = c[i]; x[i + 48] = b[i]; x[i + 64] = d[i]; }
        var x32 = x.subarray(32), x16 = x.subarray(16);
        inv25519(x32, x32);
        M(x16, x16, x32);
        pack25519(q, x16);
        for (i = 0; i < 32; i++) z[i] = 0;
    }

    /** The public key (32 bytes) of a 32-byte secret; the secret is read, never kept. */
    function publicKey(secret) {
        var q = new Uint8Array(32);
        scalarmult(q, secret, _9);
        return q;
    }

    return { publicKey: publicKey };
})();
if (typeof module !== 'undefined' && module.exports) { module.exports = PaartX25519; }
