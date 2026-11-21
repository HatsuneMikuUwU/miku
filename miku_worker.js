import { connect } from 'cloudflare:sockets';
// Pure-JS Web-standard crypto & binary helpers (zero Node.js dependencies)
function randomBytes(n) {
    const out = new Uint8Array(n);
    for (let off = 0; off < n; off += 65536) {
        crypto.getRandomValues(out.subarray(off, Math.min(n, off + 65536)));
    }
    return out;
}

function timingSafeEqual(a, b) {
    if (a.byteLength !== b.byteLength) return false;
    let diff = 0;
    for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

function hexToBytes(hex) {
    const clean = String(hex);
    const out = new Uint8Array(clean.length >>> 1);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

function bytesToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
}

function bytesToAscii(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i] & 0x7f);
    return out;
}

const MD5_S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const MD5_K = Uint32Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0);

function md5Raw(input) {
    const len = input.byteLength;
    const bitLen = len * 8;
    const padLen = ((len + 9 + 63) & ~63);
    const buf = new Uint8Array(padLen);
    buf.set(input);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, bitLen >>> 0, true);
    dv.setUint32(padLen - 4, Math.floor(bitLen / 0x100000000) >>> 0, true);
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    const M = new Uint32Array(16);
    for (let off = 0; off < padLen; off += 64) {
        for (let j = 0; j < 16; j++) M[j] = dv.getUint32(off + j * 4, true);
        let A = a0, B = b0, C = c0, D = d0;
        for (let i = 0; i < 64; i++) {
            let F, g;
            if (i < 16) { F = (B & C) | ((~B) & D); g = i; }
            else if (i < 32) { F = (D & B) | ((~D) & C); g = (5 * i + 1) & 15; }
            else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
            else { F = C ^ (B | (~D)); g = (7 * i) & 15; }
            const tmp = D;
            D = C;
            C = B;
            const x = (A + F + MD5_K[i] + M[g]) >>> 0;
            const s = MD5_S[i];
            B = (B + (((x << s) | (x >>> (32 - s))) >>> 0)) >>> 0;
            A = tmp;
        }
        a0 = (a0 + A) >>> 0;
        b0 = (b0 + B) >>> 0;
        c0 = (c0 + C) >>> 0;
        d0 = (d0 + D) >>> 0;
    }
    const out = new Uint8Array(16);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, a0, true);
    odv.setUint32(4, b0, true);
    odv.setUint32(8, c0, true);
    odv.setUint32(12, d0, true);
    return out;
}

function sha1Raw(input) {
    const len = input.byteLength;
    const bitLen = len * 8;
    const padLen = ((len + 9 + 63) & ~63);
    const buf = new Uint8Array(padLen);
    buf.set(input);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000) >>> 0, false);
    dv.setUint32(padLen - 4, bitLen >>> 0, false);
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const W = new Uint32Array(80);
    for (let off = 0; off < padLen; off += 64) {
        for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4, false);
        for (let i = 16; i < 80; i++) {
            const t = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
            W[i] = ((t << 1) | (t >>> 31)) >>> 0;
        }
        let a = h0, b = h1, c = h2, d = h3, e = h4;
        for (let i = 0; i < 80; i++) {
            let f, k;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5a827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
            else { f = b ^ c ^ d; k = 0xca62c1d6; }
            const temp = ((((a << 5) | (a >>> 27)) >>> 0) + f + e + k + W[i]) >>> 0;
            e = d; d = c; c = ((b << 30) | (b >>> 2)) >>> 0; b = a; a = temp;
        }
        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
    }
    const out = new Uint8Array(20);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, h0, false);
    odv.setUint32(4, h1, false);
    odv.setUint32(8, h2, false);
    odv.setUint32(12, h3, false);
    odv.setUint32(16, h4, false);
    return out;
}

const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const SHA256_IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const SHA224_IV = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];

function sha256Core(input, iv, outBytes) {
    const len = input.byteLength;
    const bitLen = len * 8;
    const padLen = ((len + 9 + 63) & ~63);
    const buf = new Uint8Array(padLen);
    buf.set(input);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000) >>> 0, false);
    dv.setUint32(padLen - 4, bitLen >>> 0, false);
    let h0 = iv[0], h1 = iv[1], h2 = iv[2], h3 = iv[3], h4 = iv[4], h5 = iv[5], h6 = iv[6], h7 = iv[7];
    const W = new Uint32Array(64);
    for (let off = 0; off < padLen; off += 64) {
        for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4, false);
        for (let i = 16; i < 64; i++) {
            const w15 = W[i - 15], w2 = W[i - 2];
            const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
            const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
        }
        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (let i = 0; i < 64; i++) {
            const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
            const ch = (e & f) ^ ((~e) & g);
            const t1 = (h + S1 + ch + SHA256_K[i] + W[i]) >>> 0;
            const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + maj) >>> 0;
            h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }
    const words = [h0, h1, h2, h3, h4, h5, h6, h7];
    const out = new Uint8Array(outBytes);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < outBytes / 4; i++) odv.setUint32(i * 4, words[i], false);
    return out;
}

// Pure-JS AES-128 / AES-256 (FIPS 197) + AES-GCM (NIST SP 800-38D)
const AES_SBOX = new Uint8Array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);
const AES_INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) AES_INV_SBOX[AES_SBOX[i]] = i;
const AES_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

function aesXtime(a) { return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff; }
function aesMul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        a = aesXtime(a);
        b >>>= 1;
    }
    return p;
}

function aesExpandKey(key) {
    const nk = key.byteLength >>> 2;
    if (nk !== 4 && nk !== 8) throw new Error(`unsupported AES key size ${key.byteLength}`);
    const nr = nk + 6;
    const w = new Uint8Array((nr + 1) * 16);
    w.set(key);
    for (let i = nk; i < (nr + 1) * 4; i++) {
        let t0 = w[(i - 1) * 4], t1 = w[(i - 1) * 4 + 1], t2 = w[(i - 1) * 4 + 2], t3 = w[(i - 1) * 4 + 3];
        if (i % nk === 0) {
            const tmp = t0;
            t0 = AES_SBOX[t1] ^ AES_RCON[i / nk];
            t1 = AES_SBOX[t2];
            t2 = AES_SBOX[t3];
            t3 = AES_SBOX[tmp];
        } else if (nk > 6 && i % nk === 4) {
            t0 = AES_SBOX[t0]; t1 = AES_SBOX[t1]; t2 = AES_SBOX[t2]; t3 = AES_SBOX[t3];
        }
        const p = (i - nk) * 4;
        w[i * 4] = w[p] ^ t0;
        w[i * 4 + 1] = w[p + 1] ^ t1;
        w[i * 4 + 2] = w[p + 2] ^ t2;
        w[i * 4 + 3] = w[p + 3] ^ t3;
    }
    return { w, nr };
}

function aesEncryptBlockRaw(rk, input) {
    const { w, nr } = rk;
    const s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = input[i] ^ w[i];
    for (let r = 1; r <= nr; r++) {
        // SubBytes + ShiftRows
        const t0 = AES_SBOX[s[0]],  t1 = AES_SBOX[s[5]],  t2 = AES_SBOX[s[10]], t3 = AES_SBOX[s[15]];
        const t4 = AES_SBOX[s[4]],  t5 = AES_SBOX[s[9]],  t6 = AES_SBOX[s[14]], t7 = AES_SBOX[s[3]];
        const t8 = AES_SBOX[s[8]],  t9 = AES_SBOX[s[13]], t10 = AES_SBOX[s[2]], t11 = AES_SBOX[s[7]];
        const t12 = AES_SBOX[s[12]], t13 = AES_SBOX[s[1]], t14 = AES_SBOX[s[6]], t15 = AES_SBOX[s[11]];
        const ro = r * 16;
        if (r < nr) {
            const cols = [[t0,t1,t2,t3],[t4,t5,t6,t7],[t8,t9,t10,t11],[t12,t13,t14,t15]];
            for (let c = 0; c < 4; c++) {
                const [a0, a1, a2, a3] = cols[c];
                const x = a0 ^ a1 ^ a2 ^ a3;
                const o = c * 4;
                s[o]     = a0 ^ x ^ aesXtime(a0 ^ a1) ^ w[ro + o];
                s[o + 1] = a1 ^ x ^ aesXtime(a1 ^ a2) ^ w[ro + o + 1];
                s[o + 2] = a2 ^ x ^ aesXtime(a2 ^ a3) ^ w[ro + o + 2];
                s[o + 3] = a3 ^ x ^ aesXtime(a3 ^ a0) ^ w[ro + o + 3];
            }
        } else {
            s[0]=t0^w[ro]; s[1]=t1^w[ro+1]; s[2]=t2^w[ro+2]; s[3]=t3^w[ro+3];
            s[4]=t4^w[ro+4]; s[5]=t5^w[ro+5]; s[6]=t6^w[ro+6]; s[7]=t7^w[ro+7];
            s[8]=t8^w[ro+8]; s[9]=t9^w[ro+9]; s[10]=t10^w[ro+10]; s[11]=t11^w[ro+11];
            s[12]=t12^w[ro+12]; s[13]=t13^w[ro+13]; s[14]=t14^w[ro+14]; s[15]=t15^w[ro+15];
        }
    }
    return s;
}

function aesDecryptBlockRaw(rk, input) {
    const { w, nr } = rk;
    const s = new Uint8Array(16);
    const ro0 = nr * 16;
    for (let i = 0; i < 16; i++) s[i] = input[i] ^ w[ro0 + i];
    for (let r = nr - 1; r >= 0; r--) {
        // InvShiftRows + InvSubBytes
        const t0 = AES_INV_SBOX[s[0]],  t1 = AES_INV_SBOX[s[13]], t2 = AES_INV_SBOX[s[10]], t3 = AES_INV_SBOX[s[7]];
        const t4 = AES_INV_SBOX[s[4]],  t5 = AES_INV_SBOX[s[1]],  t6 = AES_INV_SBOX[s[14]], t7 = AES_INV_SBOX[s[11]];
        const t8 = AES_INV_SBOX[s[8]],  t9 = AES_INV_SBOX[s[5]],  t10 = AES_INV_SBOX[s[2]], t11 = AES_INV_SBOX[s[15]];
        const t12 = AES_INV_SBOX[s[12]], t13 = AES_INV_SBOX[s[9]], t14 = AES_INV_SBOX[s[6]], t15 = AES_INV_SBOX[s[3]];
        const ro = r * 16;
        s[0]=t0^w[ro]; s[1]=t1^w[ro+1]; s[2]=t2^w[ro+2]; s[3]=t3^w[ro+3];
        s[4]=t4^w[ro+4]; s[5]=t5^w[ro+5]; s[6]=t6^w[ro+6]; s[7]=t7^w[ro+7];
        s[8]=t8^w[ro+8]; s[9]=t9^w[ro+9]; s[10]=t10^w[ro+10]; s[11]=t11^w[ro+11];
        s[12]=t12^w[ro+12]; s[13]=t13^w[ro+13]; s[14]=t14^w[ro+14]; s[15]=t15^w[ro+15];
        if (r > 0) {
            for (let c = 0; c < 4; c++) {
                const o = c * 4;
                const a0 = s[o], a1 = s[o + 1], a2 = s[o + 2], a3 = s[o + 3];
                s[o]     = aesMul(a0, 14) ^ aesMul(a1, 11) ^ aesMul(a2, 13) ^ aesMul(a3, 9);
                s[o + 1] = aesMul(a0, 9)  ^ aesMul(a1, 14) ^ aesMul(a2, 11) ^ aesMul(a3, 13);
                s[o + 2] = aesMul(a0, 13) ^ aesMul(a1, 9)  ^ aesMul(a2, 14) ^ aesMul(a3, 11);
                s[o + 3] = aesMul(a0, 11) ^ aesMul(a1, 13) ^ aesMul(a2, 9)  ^ aesMul(a3, 14);
            }
        }
    }
    return s;
}

function ghashMul(X, Y) {
    const Z = new Uint8Array(16);
    const V = Y.slice();
    for (let i = 0; i < 16; i++) {
        let byte = X[i];
        for (let b = 7; b >= 0; b--) {
            if ((byte >>> b) & 1) {
                for (let k = 0; k < 16; k++) Z[k] ^= V[k];
            }
            const lsb = V[15] & 1;
            for (let k = 15; k > 0; k--) V[k] = (V[k] >>> 1) | ((V[k - 1] & 1) << 7);
            V[0] >>>= 1;
            if (lsb) V[0] ^= 0xe1;
        }
    }
    return Z;
}

function ghash(H, aad, cipher) {
    let Y = new Uint8Array(16);
    const feed = (data) => {
        for (let off = 0; off < data.byteLength; off += 16) {
            const end = Math.min(off + 16, data.byteLength);
            for (let i = 0; i < end - off; i++) Y[i] ^= data[off + i];
            Y = ghashMul(Y, H);
        }
    };
    if (aad && aad.byteLength) feed(aad);
    if (cipher && cipher.byteLength) feed(cipher);
    const lenBlock = new Uint8Array(16);
    const dv = new DataView(lenBlock.buffer);
    const aadBits = (aad ? aad.byteLength : 0) * 8;
    const ctBits = (cipher ? cipher.byteLength : 0) * 8;
    dv.setUint32(0, Math.floor(aadBits / 0x100000000) >>> 0, false);
    dv.setUint32(4, aadBits >>> 0, false);
    dv.setUint32(8, Math.floor(ctBits / 0x100000000) >>> 0, false);
    dv.setUint32(12, ctBits >>> 0, false);
    for (let i = 0; i < 16; i++) Y[i] ^= lenBlock[i];
    return ghashMul(Y, H);
}

function gcmInc32(cb) {
    const out = cb.slice();
    const dv = new DataView(out.buffer);
    dv.setUint32(12, (dv.getUint32(12, false) + 1) >>> 0, false);
    return out;
}

function aesGcmCtr(rk, icb, input) {
    const out = new Uint8Array(input.byteLength);
    let cb = icb.slice();
    for (let off = 0; off < input.byteLength; off += 16) {
        const ks = aesEncryptBlockRaw(rk, cb);
        const end = Math.min(off + 16, input.byteLength);
        for (let i = 0; i < end - off; i++) out[off + i] = input[off + i] ^ ks[i];
        cb = gcmInc32(cb);
    }
    return out;
}

function aesGcmJ0(H, nonce) {
    if (nonce.byteLength === 12) {
        const j0 = new Uint8Array(16);
        j0.set(nonce, 0);
        j0[15] = 1;
        return j0;
    }
    return ghash(H, null, nonce);
}

function aesGcmSeal(key, nonce, plain, aad = null) {
    const rk = aesExpandKey(key);
    const H = aesEncryptBlockRaw(rk, new Uint8Array(16));
    const J0 = aesGcmJ0(H, nonce);
    const ct = aesGcmCtr(rk, gcmInc32(J0), plain);
    const S = ghash(H, aad, ct);
    const mask = aesEncryptBlockRaw(rk, J0);
    const tag = new Uint8Array(16);
    for (let i = 0; i < 16; i++) tag[i] = S[i] ^ mask[i];
    const out = new Uint8Array(ct.byteLength + 16);
    out.set(ct, 0);
    out.set(tag, ct.byteLength);
    return out;
}

function aesGcmOpen(key, nonce, sealed, aad = null) {
    if (sealed.byteLength < 16) throw new Error('AEAD ciphertext too short');
    const rk = aesExpandKey(key);
    const H = aesEncryptBlockRaw(rk, new Uint8Array(16));
    const J0 = aesGcmJ0(H, nonce);
    const ct = sealed.subarray(0, sealed.byteLength - 16);
    const tag = sealed.subarray(sealed.byteLength - 16);
    const S = ghash(H, aad, ct);
    const mask = aesEncryptBlockRaw(rk, J0);
    const expected = new Uint8Array(16);
    for (let i = 0; i < 16; i++) expected[i] = S[i] ^ mask[i];
    if (!timingSafeEqual(expected, tag)) throw new Error('Unsupported state or unable to authenticate data');
    return aesGcmCtr(rk, gcmInc32(J0), ct);
}

// Pure-JS ChaCha20-Poly1305 (RFC 8439)
function chacha20Block(key, counter, nonce) {
    const dvK = new DataView(key.buffer, key.byteOffset, key.byteLength);
    const dvN = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
    const state = new Uint32Array([
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        dvK.getUint32(0, true), dvK.getUint32(4, true), dvK.getUint32(8, true), dvK.getUint32(12, true),
        dvK.getUint32(16, true), dvK.getUint32(20, true), dvK.getUint32(24, true), dvK.getUint32(28, true),
        counter >>> 0,
        dvN.getUint32(0, true), dvN.getUint32(4, true), dvN.getUint32(8, true),
    ]);
    const w = state.slice();
    const rotl = (v, n) => ((v << n) | (v >>> (32 - n))) >>> 0;
    const qr = (a, b, c, d) => {
        w[a] = (w[a] + w[b]) >>> 0; w[d] = rotl(w[d] ^ w[a], 16);
        w[c] = (w[c] + w[d]) >>> 0; w[b] = rotl(w[b] ^ w[c], 12);
        w[a] = (w[a] + w[b]) >>> 0; w[d] = rotl(w[d] ^ w[a], 8);
        w[c] = (w[c] + w[d]) >>> 0; w[b] = rotl(w[b] ^ w[c], 7);
    };
    for (let i = 0; i < 10; i++) {
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    const out = new Uint8Array(64);
    const dvO = new DataView(out.buffer);
    for (let i = 0; i < 16; i++) dvO.setUint32(i * 4, (w[i] + state[i]) >>> 0, true);
    return out;
}

function chacha20Xor(key, counter, nonce, input) {
    const out = new Uint8Array(input.byteLength);
    for (let off = 0, c = counter >>> 0; off < input.byteLength; off += 64, c = (c + 1) >>> 0) {
        const block = chacha20Block(key, c, nonce);
        const end = Math.min(off + 64, input.byteLength);
        for (let i = 0; i < end - off; i++) out[off + i] = input[off + i] ^ block[i];
    }
    return out;
}

const POLY1305_P = (1n << 130n) - 5n;
function bytesToBigIntLE(bytes) {
    let n = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
    return n;
}

function poly1305Mac(otk, msg) {
    const rBytes = otk.slice(0, 16);
    rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15;
    rBytes[4] &= 252; rBytes[8] &= 252; rBytes[12] &= 252;
    const r = bytesToBigIntLE(rBytes);
    const s = bytesToBigIntLE(otk.subarray(16, 32));
    let acc = 0n;
    for (let off = 0; off < msg.byteLength; off += 16) {
        const chunk = msg.subarray(off, Math.min(off + 16, msg.byteLength));
        let n = bytesToBigIntLE(chunk) | (1n << BigInt(chunk.byteLength * 8));
        acc = ((acc + n) * r) % POLY1305_P;
    }
    acc = (acc + s) & ((1n << 128n) - 1n);
    const tag = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        tag[i] = Number((acc >> BigInt(i * 8)) & 0xffn);
    }
    return tag;
}

function chacha20Poly1305MacData(aad, ct) {
    const aadLen = aad ? aad.byteLength : 0;
    const ctLen = ct.byteLength;
    const aadPad = (16 - (aadLen % 16)) % 16;
    const ctPad = (16 - (ctLen % 16)) % 16;
    const out = new Uint8Array(aadLen + aadPad + ctLen + ctPad + 16);
    if (aadLen) out.set(aad, 0);
    out.set(ct, aadLen + aadPad);
    const dv = new DataView(out.buffer);
    const lenOff = aadLen + aadPad + ctLen + ctPad;
    dv.setUint32(lenOff, aadLen >>> 0, true);
    dv.setUint32(lenOff + 4, Math.floor(aadLen / 0x100000000) >>> 0, true);
    dv.setUint32(lenOff + 8, ctLen >>> 0, true);
    dv.setUint32(lenOff + 12, Math.floor(ctLen / 0x100000000) >>> 0, true);
    return out;
}

function chacha20Poly1305Seal(key, nonce, plain, aad = null) {
    const otk = chacha20Block(key, 0, nonce).subarray(0, 32);
    const ct = chacha20Xor(key, 1, nonce, plain);
    const tag = poly1305Mac(otk, chacha20Poly1305MacData(aad, ct));
    const out = new Uint8Array(ct.byteLength + 16);
    out.set(ct, 0);
    out.set(tag, ct.byteLength);
    return out;
}

function chacha20Poly1305Open(key, nonce, sealed, aad = null) {
    if (sealed.byteLength < 16) throw new Error('AEAD ciphertext too short');
    const ct = sealed.subarray(0, sealed.byteLength - 16);
    const tag = sealed.subarray(sealed.byteLength - 16);
    const otk = chacha20Block(key, 0, nonce).subarray(0, 32);
    const expected = poly1305Mac(otk, chacha20Poly1305MacData(aad, ct));
    if (!timingSafeEqual(expected, tag)) throw new Error('Unsupported state or unable to authenticate data');
    return chacha20Xor(key, 1, nonce, ct);
}

function pureAeadSeal(name, key, nonce, plain, aad = null) {
    if (name === 'chacha20-poly1305') return chacha20Poly1305Seal(key, nonce, plain, aad);
    if (name === 'aes-128-gcm' || name === 'aes-256-gcm') return aesGcmSeal(key, nonce, plain, aad);
    throw new Error(`unsupported AEAD cipher ${name}`);
}

function pureAeadOpen(name, key, nonce, sealed, aad = null) {
    if (name === 'chacha20-poly1305') return chacha20Poly1305Open(key, nonce, sealed, aad);
    if (name === 'aes-128-gcm' || name === 'aes-256-gcm') return aesGcmOpen(key, nonce, sealed, aad);
    throw new Error(`unsupported AEAD cipher ${name}`);
}


// Miku subscription compatibility routes.
const SUB_PORTS = [443, 80];
const SUB_PROTOCOLS = ['trojan', 'vmess', 'vless', 'ss'];
const SUB_TYPES = ['ws', 'xhttp'];
const SUB_PROXY_LIST_URL = 'https://raw.githubusercontent.com/HatsuneMikuUwU/miku/refs/heads/main/proxyList.txt';
const SUB_CORS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,HEAD,POST,OPTIONS',
    'Access-Control-Max-Age': '86400',
};
let subProxyCache = [];

async function subGetProxyList(url = SUB_PROXY_LIST_URL) {
    if (!url) throw new Error('No proxy list URL provided');
    const response = await fetch(url);
    if (response.status !== 200) return subProxyCache;
    const text = (await response.text()) || '';
    subProxyCache = text.split(/\r?\n/).filter(Boolean).map((entry) => {
        const [prxIP, prxPort, country, org] = entry.split(',');
        return { prxIP: prxIP || 'Unknown', prxPort: prxPort || '443', country: country || 'Unknown', org: org || 'Unknown Org' };
    });
    return subProxyCache;
}

function subShuffle(items) {
    for (let i = items.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [items[i], items[j]] = [items[j], items[i]];
    }
    return items;
}

function subFlag(country) {
    const code = String(country || 'UN').toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) return '🌐';
    return String.fromCodePoint(...code.split('').map((char) => 127397 + char.charCodeAt(0)));
}

async function subResponse(request, env) {
    const url = new URL(request.url);
    const appDomain = url.hostname;
    const apiPath = url.pathname.replace(/^\/api\/v1/, '');
    if (apiPath.startsWith('/myip')) {
        return new Response(JSON.stringify({
            ip: request.headers.get('cf-connecting-ipv6') || request.headers.get('cf-connecting-ip') || request.headers.get('x-real-ip'),
            colo: request.headers.get('cf-ray')?.split('-')[1],
            ...(request.cf || {}),
        }), { headers: { ...SUB_CORS, 'Content-Type': 'application/json' } });
    }
    if (!apiPath.startsWith('/sub')) return null;
    const countries = url.searchParams.get('cc')?.split(',').filter(Boolean) || [];
    const ports = url.searchParams.get('port')?.split(',').filter(Boolean) || SUB_PORTS.map(String);
    const protocols = url.searchParams.get('vpn')?.split(',').filter(Boolean).map((p) => p.toLowerCase()) || SUB_PROTOCOLS;
    const requestedType = (url.searchParams.get('type') || 'ws').toLowerCase();
    const transportType = SUB_TYPES.includes(requestedType) ? requestedType : 'ws';
    const rawLimit = Number.parseInt(url.searchParams.get('limit') || '10', 10);
    const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 1000) : 10;
    const requestedFormat = (url.searchParams.get('format') || 'raw').toLowerCase();
    const format = requestedFormat === 'base64' ? 'base64' : 'raw';
    const fillerDomain = url.searchParams.get('domain') || appDomain;
    const proxyListUrl = url.searchParams.get('prx-list') || env?.PRX_BANK_URL || SUB_PROXY_LIST_URL;
    let proxies = await subGetProxyList(proxyListUrl);
    if (countries.length) proxies = proxies.filter((proxy) => countries.includes(proxy.country));
    subShuffle(proxies);
    const credential = CONFIG.UUID;
    const result = [];
    for (const proxy of proxies) {
        for (const port of ports) {
            for (const protocol of protocols) {
                if (result.length >= limit) break;
                if (!SUB_PROTOCOLS.includes(protocol)) continue;
                const uri = new URL(`${protocol}://${fillerDomain}`);
                uri.port = String(port);
                uri.username = protocol === 'ss' ? btoa(`aes-128-gcm:${credential}`) : credential;
                uri.searchParams.set('type', transportType);
                uri.searchParams.set('host', appDomain);
                const workerPath = `/${protocol}/${proxy.prxIP}-${proxy.prxPort}`;
                uri.searchParams.set('path', workerPath);
                uri.searchParams.set('security', String(port) === '443' ? 'tls' : 'none');
                uri.searchParams.set('sni', String(port) === '80' && protocol === 'vmess' ? '' : appDomain);
                if (protocol === 'ss' && transportType === 'ws') uri.searchParams.set('plugin', `v2ray-plugin${String(port) === '80' ? '' : ';tls'};mux=0;mode=websocket;path=${workerPath};host=${appDomain}`);
                if (protocol === 'trojan') uri.searchParams.set('encryption', 'none');
                uri.hash = `${result.length + 1} ${subFlag(proxy.country)} ${proxy.org} ${transportType.toUpperCase()} ${String(port) === '443' ? 'TLS' : 'NTLS'} [${appDomain.split('.')[0]}]`;
                result.push(uri.toString());
            }
            if (result.length >= limit) break;
        }
        if (result.length >= limit) break;
    }
    let body = result.join('\n');
    if (format === 'base64') body = btoa(body);
    return new Response(body, { status: 200, headers: { ...SUB_CORS, 'Cache-Control': 'no-store' } });
}

const CONFIG = Object.freeze({
    // One credential root for all four protocols:
    // VLESS UUID = this UUID
    // VMess ID   = this UUID
    // Trojan password = this UUID string
    UUID: '0d285c5a-58d9-4b66-922b-af428c4edf7c',
    // Shadowsocks inbound method. methods supported:
    // aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305,
    // 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305.
    SS_METHOD: 'aes-128-gcm',
    // UDP relay transport. TCP host+port takes priority when both forms are set.
    // Examples:
    // UDP_RELAY: { host: '203.0.113.10', port: 8443 },
    // UDP_RELAY: { websocket: 'wss://relay.example.com/' },
    // UDP_RELAY: { websocket: 'ws://127.0.0.1:8080/' },
    UDP_RELAY: {
       websocket: 'ws://38.253.224.79.sslip.io:6052/'
    },
    MAX_PROTOCOL_HEADER: 4096,
    MAX_TCP_PROXY_REPLAY: 4 * 1024 * 1024,
    // Force HTTP/3 / QUIC (UDP/443) to fail so browsers fall back to TCP/443.
    // This prevents normal web browsing from egressing through the VPS UDP relay.
    REJECT_UDP_443: true,
    // DNS UDP/53 is resolved directly from the Worker over HTTPS so normal
    // browsing does not depend on the external UDP relay being reachable.
    DNS_DOH_URLS: [
        'https://cloudflare-dns.com/dns-query',
        'https://dns.google/dns-query',
    ],
    DNS_DOH_TIMEOUT_MS: 5000,
});

const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_IPV6 = 0x03;
const CMD_TCP = 0x01;
const CMD_UDP = 0x02;
const CMD_MUX = 0x03;
const CMD_RVS = 0x04;
const MUX_STATUS_NEW = 0x01;
const MUX_STATUS_KEEP = 0x02;
const MUX_STATUS_END = 0x03;
const MUX_STATUS_KEEPALIVE = 0x04;
const MUX_OPTION_DATA = 0x01;
const MUX_OPTION_ERROR = 0x02;
const MUX_NETWORK_TCP = 0x01;
const MUX_NETWORK_UDP = 0x02;
const MAX_MUX_META_LEN = 512;
const MAX_MUX_DATA_LEN = 65535;
const VMESS_VERSION = 1;
const VMESS_SECURITY_AUTO = 2;
const VMESS_SECURITY_AES128_GCM = 3;
const VMESS_SECURITY_CHACHA20_POLY1305 = 4;
const VMESS_SECURITY_NONE = 5;
const VMESS_SECURITY_ZERO = 6;
const VMESS_OPT_CHUNK_STREAM = 0x01;
const VMESS_OPT_CONNECTION_REUSE = 0x02;
const VMESS_OPT_CHUNK_MASKING = 0x04;
const VMESS_OPT_GLOBAL_PADDING = 0x08;
const VMESS_OPT_AUTHENTICATED_LENGTH = 0x10;
const VMESS_CMD_KEY_SALT = 'c48619fe-8f02-49e0-b9e9-edf763e17e21';
const KDF_ROOT = utf8('VMess AEAD KDF');
const KDF_AUTH_ID = utf8('AES Auth ID Encryption');
const KDF_HDR_LEN_KEY = utf8('VMess Header AEAD Key_Length');
const KDF_HDR_LEN_IV = utf8('VMess Header AEAD Nonce_Length');
const KDF_HDR_KEY = utf8('VMess Header AEAD Key');
const KDF_HDR_IV = utf8('VMess Header AEAD Nonce');
const KDF_RESP_LEN_KEY = utf8('AEAD Resp Header Len Key');
const KDF_RESP_LEN_IV = utf8('AEAD Resp Header Len IV');
const KDF_RESP_KEY = utf8('AEAD Resp Header Key');
const KDF_RESP_IV = utf8('AEAD Resp Header IV');
const KDF_AUTH_LEN = utf8('auth_len');
const CRC32_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let j = 0; j < 8; j++) {
            c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        }
        t[i] = c >>> 0;
    }
    return t;
})();
function utf8(text) {
    return new TextEncoder().encode(String(text));
}

function concatBytes(...parts) {
    const list = parts.filter((p) => p && p.byteLength !== 0).map(toU8Sync);
    const total = list.reduce((n, p) => n + p.byteLength, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of list) {
        out.set(p, off);
        off += p.byteLength;
    }
    return out;
}

function toU8Sync(value) {
    if (value instanceof Uint8Array) {
        return value;
    }
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    throw new TypeError('expected binary data');
}

function bytesToHex(bytes) {
    const u8 = toU8Sync(bytes);
    let out = '';
    for (let i = 0; i < u8.length; i++) out += u8[i].toString(16).padStart(2, '0');
    return out;
}

function normalizeUUID(text) {
    const s = String(text || '').trim().toLowerCase();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) {
        throw new Error(`invalid UUID: ${text}`);
    }
    return s;
}

function uuidToBytes(text) {
    const s = normalizeUUID(text).replaceAll('-', '');
    return hexToBytes(s);
}

function formatUUID(bytes) {
    const h = bytesToHex(bytes);
    if (h.length !== 32) {
        throw new Error('UUID needs 16 bytes');
    }
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function processVlessUUID(bytes) {
    const out = toU8Sync(bytes).slice();
    if (out.byteLength !== 16) {
        throw new Error('VLESS UUID must be 16 bytes');
    }
    out[6] = 0;
    out[7] = 0;
    return out;
}

function secureEqual(a, b) {
    return timingSafeEqual(toU8Sync(a), toU8Sync(b));
}

function md5(data) {
    return md5Raw(toU8Sync(data));
}

function sha256(data) {
    return sha256Core(toU8Sync(data), SHA256_IV, 32);
}

function sha224Hex(text) {
    return bytesToHex(sha256Core(utf8(text), SHA224_IV, 28));
}

function crc32(bytes) {
    let c = 0xffffffff;
    for (const b of toU8Sync(bytes)) {
        c = CRC32_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
}

function fnv1a32(bytes) {
    let h = 0x811c9dc5;
    for (const b of toU8Sync(bytes)) {
        h ^= b;
        h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
}

function hmacSha256(key, data) {
    return hmacWithHash(sha256, toU8Sync(key), toU8Sync(data));
}

function hmacWithHash(hashFn, key, data) {
    let k = toU8Sync(key);
    if (k.byteLength > 64) {
        k = hashFn(k);
    }
    const kb = new Uint8Array(64);
    kb.set(k);
    const ipad = new Uint8Array(64);
    const opad = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
        ipad[i] = kb[i] ^ 0x36;
        opad[i] = kb[i] ^ 0x5c;
    }
    return hashFn(concatBytes(opad, hashFn(concatBytes(ipad, data))));
}

function vmessKdf(key, ...pathParts) {
    let hashFn = (data) => hmacSha256(KDF_ROOT, data);
    for (const p of pathParts) {
        const prev = hashFn;
        const path = typeof p === 'string' ? utf8(p) : toU8Sync(p).slice();
        hashFn = (data) => hmacWithHash(prev, path, data);
    }
    return hashFn(toU8Sync(key));
}

function vmessKdf16(key, ...pathParts) {
    return vmessKdf(key, ...pathParts).slice(0, 16);
}

function vmessCmdKey(uuidBytes) {
    return md5(concatBytes(uuidBytes, utf8(VMESS_CMD_KEY_SALT)));
}

function cipherAeadName(security) {
    if (security === VMESS_SECURITY_AES128_GCM) {
        return 'aes-128-gcm';
    }
    if (security === VMESS_SECURITY_CHACHA20_POLY1305) {
        return 'chacha20-poly1305';
    }
    throw new Error(`security ${security} is not AEAD`);
}

function chachaKey(key16) {
    const a = md5(key16);
    const b = md5(a);
    return concatBytes(a, b);
}

function normalizeAeadKey(security, key) {
    const k = toU8Sync(key);
    return security === VMESS_SECURITY_CHACHA20_POLY1305 ? chachaKey(k) : k.slice(0, 16);
}

function aeadSeal(security, key, nonce, plain, aad = null) {
    const name = cipherAeadName(security);
    const aadBytes = aad && toU8Sync(aad).byteLength ? toU8Sync(aad) : null;
    return pureAeadSeal(name, normalizeAeadKey(security, key), toU8Sync(nonce), toU8Sync(plain), aadBytes);
}

function aeadOpen(security, key, nonce, sealed, aad = null) {
    const input = toU8Sync(sealed);
    if (input.byteLength < 16) {
        throw new Error('AEAD ciphertext too short');
    }
    const name = cipherAeadName(security);
    const aadBytes = aad && toU8Sync(aad).byteLength ? toU8Sync(aad) : null;
    return pureAeadOpen(name, normalizeAeadKey(security, key), toU8Sync(nonce), input, aadBytes);
}

function aesEcbDecryptBlock(key, block) {
    const k = toU8Sync(key);
    const b = toU8Sync(block);
    if (k.byteLength !== 16) {
        throw new Error(`VMess AuthID AES key must be 16 bytes, got ${k.byteLength}`);
    }
    if (b.byteLength !== 16) {
        throw new Error(`VMess AuthID block must be 16 bytes, got ${b.byteLength}`);
    }
    return aesDecryptBlockRaw(aesExpandKey(k), b);
}

function aesEcbEncryptBlock(key, block) {
    const k = toU8Sync(key);
    const b = toU8Sync(block);
    if (k.byteLength !== 16) {
        throw new Error(`VMess AuthID AES key must be 16 bytes, got ${k.byteLength}`);
    }
    if (b.byteLength !== 16) {
        throw new Error(`VMess AuthID block must be 16 bytes, got ${b.byteLength}`);
    }
    return aesEncryptBlockRaw(aesExpandKey(k), b);
}

function parseRelayEndpoint(bytes, offset = 0) {
    const b = toU8Sync(bytes);
    if (b.byteLength < offset + 3) {
        return null;
    }
    const port = (b[offset] << 8) | b[offset + 1];
    const atyp = b[offset + 2];
    let p = offset + 3;
    if (port === 0) {
        throw new Error('zero endpoint port');
    }
    if (atyp === ATYP_IPV4) {
        if (b.byteLength < p + 4) {
            return null;
        }
        const address = Array.from(b.subarray(p, p + 4)).join('.');
        return { address, port, addressType: atyp, next: p + 4 };
    }
    if (atyp === ATYP_DOMAIN) {
        if (b.byteLength < p + 1) {
            return null;
        }
        const len = b[p++];
        if (!len) {
            throw new Error('empty endpoint domain');
        }
        if (b.byteLength < p + len) {
            return null;
        }
        const address = new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(p, p + len));
        return { address, port, addressType: atyp, next: p + len };
    }
    if (atyp === ATYP_IPV6) {
        if (b.byteLength < p + 16) {
            return null;
        }
        return { address: ipv6FromBytes(b.subarray(p, p + 16)), port, addressType: atyp, next: p + 16 };
    }
    throw new Error(`invalid endpoint address type ${atyp}`);
}

function encodeRelayEndpoint(endpoint) {
    const port = Number(endpoint.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`invalid endpoint port ${endpoint.port}`);
    }
    const head = new Uint8Array([(port >>> 8) & 0xff, port & 0xff]);
    const type = endpoint.addressType || inferAddressType(endpoint.address);
    if (type === ATYP_IPV4) {
        return concatBytes(head, new Uint8Array([ATYP_IPV4]), ipv4ToBytes(endpoint.address));
    }
    if (type === ATYP_IPV6) {
        return concatBytes(head, new Uint8Array([ATYP_IPV6]), ipv6ToBytes(endpoint.address));
    }
    const d = utf8(endpoint.address);
    if (!d.byteLength || d.byteLength > 255) {
        throw new Error('invalid endpoint domain');
    }
    return concatBytes(head, new Uint8Array([ATYP_DOMAIN, d.byteLength]), d);
}

class MuxFrameDecoder {
    constructor(maxMetaLen = MAX_MUX_META_LEN, maxDataLen = MAX_MUX_DATA_LEN) {
        this.maxMetaLen = maxMetaLen;
        this.maxDataLen = maxDataLen;
        this.pending = new Uint8Array(0);
    }
    push(chunk) {
        const input = toU8Sync(chunk);
        if (input.byteLength) {
            this.pending = concatBytes(this.pending, input);
        }
        const out = [];
        while (this.pending.byteLength >= 2) {
            const metaLen = (this.pending[0] << 8) | this.pending[1];
            if (metaLen < 4 || metaLen > this.maxMetaLen) {
                throw new Error(`invalid Mux.Cool metadata length ${metaLen}`);
            }
            const metaEnd = 2 + metaLen;
            if (this.pending.byteLength < metaEnd) {
                break;
            }
            const meta = this.pending.subarray(2, metaEnd);
            const option = meta[3];
            let total = metaEnd;
            let data = new Uint8Array(0);
            if ((option & MUX_OPTION_DATA) !== 0) {
                if (this.pending.byteLength < total + 2) {
                    break;
                }
                const dataLen = (this.pending[total] << 8) | this.pending[total + 1];
                if (dataLen > this.maxDataLen) {
                    throw new Error(`Mux.Cool payload too large: ${dataLen}`);
                }
                if (this.pending.byteLength < total + 2 + dataLen) {
                    break;
                }
                data = this.pending.slice(total + 2, total + 2 + dataLen);
                total += 2 + dataLen;
            }
            const frame = parseMuxMetadata(meta, data);
            frame.raw = this.pending.slice(0, total);
            out.push(frame);
            this.pending = this.pending.slice(total);
        }
        return out;
    }
}

function parseMuxMetadata(metaBytes, data = new Uint8Array(0)) {
    const meta = toU8Sync(metaBytes);
    if (meta.byteLength < 4 || meta.byteLength > MAX_MUX_META_LEN) {
        throw new Error(`invalid Mux.Cool metadata length ${meta.byteLength}`);
    }
    const frame = {
        id: (meta[0] << 8) | meta[1],
        status: meta[2],
        option: meta[3],
        network: 0,
        target: null,
        globalID: null,
        data: toU8Sync(data).slice(),
        raw: null,
    };
    let cursor = 4;
    if (frame.status === MUX_STATUS_NEW) {
        if (cursor >= meta.byteLength) {
            throw new Error('Mux.Cool New is missing network type');
        }
        frame.network = meta[cursor++];
        if (frame.network !== MUX_NETWORK_TCP && frame.network !== MUX_NETWORK_UDP) {
            throw new Error(`invalid Mux.Cool network type ${frame.network}`);
        }
        const endpoint = parseRelayEndpoint(meta, cursor);
        if (!endpoint) {
            throw new Error('truncated Mux.Cool New destination');
        }
        frame.target = endpoint;
        cursor = endpoint.next;
        if (frame.network === MUX_NETWORK_UDP && meta.byteLength - cursor >= 8) {
            const gid = meta.slice(cursor, cursor + 8);
            let nonZero = false;
            for (const value of gid) {
                if (value !== 0) {
                    nonZero = true;
                    break;
                }
            }
            if (nonZero) {
                frame.globalID = gid;
            }
            cursor += 8;
        }
    }
    else if (frame.status === MUX_STATUS_KEEP) {
        if (meta.byteLength > cursor) {
            if (meta[cursor] !== MUX_NETWORK_UDP) {
                throw new Error(`invalid Mux.Cool Keep extension ${meta[cursor]}`);
            }
            frame.network = meta[cursor++];
            const endpoint = parseRelayEndpoint(meta, cursor);
            if (!endpoint) {
                throw new Error('truncated Mux.Cool UDP Keep destination');
            }
            frame.target = endpoint;
            cursor = endpoint.next;
        }
    }
    else if (frame.status !== MUX_STATUS_END && frame.status !== MUX_STATUS_KEEPALIVE) {
        throw new Error(`invalid Mux.Cool status ${frame.status}`);
    }
    if (cursor !== meta.byteLength) {
        throw new Error(`unexpected ${meta.byteLength - cursor} byte(s) in Mux.Cool metadata`);
    }
    return frame;
}

function encodeMuxMeta(metaBytes) {
    const meta = toU8Sync(metaBytes);
    if (meta.byteLength < 4 || meta.byteLength > MAX_MUX_META_LEN) {
        throw new Error(`invalid Mux.Cool metadata length ${meta.byteLength}`);
    }
    return concatBytes(new Uint8Array([meta.byteLength >>> 8, meta.byteLength & 0xff]), meta);
}

function encodeMuxPacket(metaBytes, data) {
    const meta = toU8Sync(metaBytes);
    const payload = toU8Sync(data);
    if (payload.byteLength > MAX_MUX_DATA_LEN) {
        throw new Error(`Mux.Cool payload too large: ${payload.byteLength}`);
    }
    if ((meta[3] & MUX_OPTION_DATA) === 0) {
        throw new Error('Mux.Cool data frame is missing DATA option');
    }
    return concatBytes(encodeMuxMeta(meta), new Uint8Array([payload.byteLength >>> 8, payload.byteLength & 0xff]), payload);
}

function encodeMuxTcpData(id, data) {
    const payload = toU8Sync(data);
    const meta = new Uint8Array([id >>> 8, id & 0xff, MUX_STATUS_KEEP, MUX_OPTION_DATA]);
    return encodeMuxPacket(meta, payload);
}

function encodeMuxUdpData(id, endpoint, data) {
    const meta = concatBytes(new Uint8Array([id >>> 8, id & 0xff, MUX_STATUS_KEEP, MUX_OPTION_DATA, MUX_NETWORK_UDP]), encodeRelayEndpoint(endpoint));
    return encodeMuxPacket(meta, data);
}

function encodeMuxEnd(id, hasError = false) {
    return encodeMuxMeta(new Uint8Array([
        id >>> 8,
        id & 0xff,
        MUX_STATUS_END,
        hasError ? MUX_OPTION_ERROR : 0,
    ]));
}

function inferAddressType(address) {
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(String(address))) {
        return ATYP_IPV4;
    }
    if (String(address).includes(':')) {
        return ATYP_IPV6;
    }
    return ATYP_DOMAIN;
}

function parseProxyAddress(value) {
    const text = String(value || '').trim();
    const bracket = text.match(/^\[([^\]]+)](?::|=|-)(\d+)$/);
    const generic = bracket ? null : text.match(/^(.+?)(?::|=|-)(\d+)$/);
    const hostname = bracket ? bracket[1] : generic?.[1];
    const port = Number(bracket ? bracket[2] : generic?.[2]);
    if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`invalid proxy address ${value}`);
    }
    return { hostname, port };
}

function parseProtocolPath(pathname) {
    const match = String(pathname || '').match(/^\/(vless|trojan|vmess|ss)(?:\/([^/]+))?\/?$/i);
    if (!match) {
        return null;
    }
    const protocol = match[1].toLowerCase();
    const suffix = match[2] || '';
    if (!suffix) {
        return { protocol, proxyAddress: '' };
    }
    if (suffix.includes('/')) {
        return null;
    }
    try {
        parseProxyAddress(suffix);
    }
    catch {
        return null;
    }
    return { protocol, proxyAddress: suffix };
}

function ipv4ToBytes(address) {
    const a = String(address).split('.').map(Number);
    if (a.length !== 4 || a.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
        throw new Error(`invalid IPv4 ${address}`);
    }
    return new Uint8Array(a);
}

function ipv6ToBytes(address) {
    let input = String(address).split('%')[0].toLowerCase();
    let ipv4Tail = null;
    const lastColon = input.lastIndexOf(':');
    if (input.includes('.') && lastColon >= 0) {
        const v4 = ipv4ToBytes(input.slice(lastColon + 1));
        ipv4Tail = [((v4[0] << 8) | v4[1]).toString(16), ((v4[2] << 8) | v4[3]).toString(16)];
        input = input.slice(0, lastColon) + ':' + ipv4Tail.join(':');
    }
    const halves = input.split('::');
    if (halves.length > 2) {
        throw new Error(`invalid IPv6 ${address}`);
    }
    const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const missing = 8 - left.length - right.length;
    if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
        throw new Error(`invalid IPv6 ${address}`);
    }
    const words = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
    if (words.length !== 8) {
        throw new Error(`invalid IPv6 ${address}`);
    }
    const out = new Uint8Array(16);
    words.forEach((w, i) => {
        if (!/^[0-9a-f]{1,4}$/i.test(w)) {
            throw new Error(`invalid IPv6 ${address}`);
        }
        const n = parseInt(w, 16);
        out[i * 2] = n >>> 8;
        out[i * 2 + 1] = n & 0xff;
    });
    return out;
}

function ipv6FromBytes(bytes) {
    const b = toU8Sync(bytes);
    const words = [];
    for (let i = 0; i < 16; i += 2) {
        words.push(((b[i] << 8) | b[i + 1]).toString(16));
    }
    let bestStart = -1, bestLen = 0;
    for (let i = 0; i < words.length;) {
        if (words[i] !== '0') {
            i++;
            continue;
        }
        let j = i;
        while (j < words.length && words[j] === '0') {
            j++;
        }
        if (j - i > bestLen && j - i >= 2) {
            bestStart = i;
            bestLen = j - i;
        }
        i = j;
    }
    if (bestStart < 0) {
        return words.join(':');
    }
    const left = words.slice(0, bestStart).join(':');
    const right = words.slice(bestStart + bestLen).join(':');
    return left && right ? `${left}::${right}` : left ? `${left}::` : right ? `::${right}` : '::';
}

function tryParsePortFirstAddress(bytes, cursor, addressType) {
    const b = toU8Sync(bytes);
    if (addressType === ATYP_IPV4) {
        if (b.byteLength < cursor + 4) {
            return null;
        }
        return { address: Array.from(b.subarray(cursor, cursor + 4)).join('.'), next: cursor + 4 };
    }
    if (addressType === ATYP_DOMAIN) {
        if (b.byteLength < cursor + 1) {
            return null;
        }
        const len = b[cursor++];
        if (!len) {
            throw new Error('empty domain');
        }
        if (b.byteLength < cursor + len) {
            return null;
        }
        return { address: new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(cursor, cursor + len)), next: cursor + len };
    }
    if (addressType === ATYP_IPV6) {
        if (b.byteLength < cursor + 16) {
            return null;
        }
        return { address: ipv6FromBytes(b.subarray(cursor, cursor + 16)), next: cursor + 16 };
    }
    throw new Error(`invalid address type ${addressType}`);
}

function tryParseVlessHeader(bytes) {
    const b = toU8Sync(bytes);
    if (b.byteLength < 18) {
        return null;
    }
    if (b[0] !== 0) {
        throw new Error(`invalid VLESS version ${b[0]}`);
    }
    const user = b.slice(1, 17);
    const addonLength = b[17];
    const commandIndex = 18 + addonLength;
    if (b.byteLength < commandIndex + 1) {
        return null;
    }
    const command = b[commandIndex];
    if (![CMD_TCP, CMD_UDP, CMD_MUX, CMD_RVS].includes(command)) {
        throw new Error(`invalid VLESS command ${command}`);
    }
    if (command === CMD_MUX || command === CMD_RVS) {
        return { version: 0, user, addonLength, command, address: command === CMD_MUX ? 'v1.mux.cool' : 'v1.rvs.cool', port: 0, addressType: ATYP_DOMAIN, headerLength: commandIndex + 1 };
    }
    let p = commandIndex + 1;
    if (b.byteLength < p + 3) {
        return null;
    }
    const port = (b[p] << 8) | b[p + 1];
    p += 2;
    if (!port) {
        throw new Error('zero VLESS port');
    }
    const addressType = b[p++];
    const a = tryParsePortFirstAddress(b, p, addressType);
    if (!a) {
        return null;
    }
    return { version: 0, user, addonLength, command, address: a.address, port, addressType, headerLength: a.next };
}

function tryParseSocksAddress(bytes, cursor) {
    const b = toU8Sync(bytes);
    if (b.byteLength < cursor + 1) {
        return null;
    }
    const atyp = b[cursor++];
    let address;
    if (atyp === 0x01) {
        if (b.byteLength < cursor + 4 + 2) {
            return null;
        }
        address = Array.from(b.subarray(cursor, cursor + 4)).join('.');
        cursor += 4;
    }
    else if (atyp === 0x03) {
        if (b.byteLength < cursor + 1) {
            return null;
        }
        const len = b[cursor++];
        if (!len) {
            throw new Error('empty Trojan domain');
        }
        if (b.byteLength < cursor + len + 2) {
            return null;
        }
        address = new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(cursor, cursor + len));
        cursor += len;
    }
    else if (atyp === 0x04) {
        if (b.byteLength < cursor + 16 + 2) {
            return null;
        }
        address = ipv6FromBytes(b.subarray(cursor, cursor + 16));
        cursor += 16;
    }
    else {
        throw new Error(`invalid Trojan address type ${atyp}`);
    }
    const port = (b[cursor] << 8) | b[cursor + 1];
    cursor += 2;
    if (!port) {
        throw new Error('zero Trojan port');
    }
    return { address, port, addressType: atyp === 1 ? ATYP_IPV4 : atyp === 4 ? ATYP_IPV6 : ATYP_DOMAIN, next: cursor };
}

function encodeSocksAddress(endpoint) {
    const type = endpoint.addressType || inferAddressType(endpoint.address);
    let addr;
    if (type === ATYP_IPV4) {
        addr = concatBytes(new Uint8Array([0x01]), ipv4ToBytes(endpoint.address));
    }
    else if (type === ATYP_IPV6) {
        addr = concatBytes(new Uint8Array([0x04]), ipv6ToBytes(endpoint.address));
    }
    else {
        const d = utf8(endpoint.address);
        if (!d.byteLength || d.byteLength > 255) {
            throw new Error('invalid Trojan domain');
        }
        addr = concatBytes(new Uint8Array([0x03, d.byteLength]), d);
    }
    const port = Number(endpoint.port);
    return concatBytes(addr, new Uint8Array([(port >>> 8) & 0xff, port & 0xff]));
}

function tryParseTrojanHeader(bytes, expectedHashHex) {
    const b = toU8Sync(bytes);
    if (b.byteLength < 59) {
        return null;
    }
    const got = bytesToAscii(b.subarray(0, 56));
    if (got.length !== 56 || got.toLowerCase() !== String(expectedHashHex).toLowerCase()) {
        throw new Error('invalid Trojan password hash');
    }
    if (b[56] !== 0x0d || b[57] !== 0x0a) {
        throw new Error('invalid Trojan CRLF after password');
    }
    const command = b[58];
    if (command !== 0x01 && command !== 0x03) {
        throw new Error(`unsupported Trojan command ${command}`);
    }
    const ep = tryParseSocksAddress(b, 59);
    if (!ep) {
        return null;
    }
    if (b.byteLength < ep.next + 2) {
        return null;
    }
    if (b[ep.next] !== 0x0d || b[ep.next + 1] !== 0x0a) {
        throw new Error('invalid Trojan CRLF after destination');
    }
    return { command: command === 0x01 ? CMD_TCP : CMD_UDP, address: ep.address, port: ep.port, addressType: ep.addressType, headerLength: ep.next + 2 };
}

class TrojanUdpDecoder {
    constructor() { this.pending = new Uint8Array(0); }
    push(chunk) {
        this.pending = concatBytes(this.pending, chunk);
        const out = [];
        while (this.pending.byteLength) {
            const ep = tryParseSocksAddress(this.pending, 0);
            if (!ep) {
                break;
            }
            if (this.pending.byteLength < ep.next + 4) {
                break;
            }
            const len = (this.pending[ep.next] << 8) | this.pending[ep.next + 1];
            if (len > 8192) {
                throw new Error(`Trojan UDP payload too large: ${len}`);
            }
            if (this.pending[ep.next + 2] !== 0x0d || this.pending[ep.next + 3] !== 0x0a) {
                throw new Error('invalid Trojan UDP CRLF');
            }
            const end = ep.next + 4 + len;
            if (this.pending.byteLength < end) {
                break;
            }
            out.push({ endpoint: { address: ep.address, port: ep.port, addressType: ep.addressType }, payload: this.pending.slice(ep.next + 4, end) });
            this.pending = this.pending.slice(end);
        }
        return out;
    }
}

function encodeTrojanUdpPacket(endpoint, payload) {
    const p = toU8Sync(payload);
    if (p.byteLength > 8192) {
        throw new Error(`Trojan UDP payload too large: ${p.byteLength}`);
    }
    return concatBytes(encodeSocksAddress(endpoint), new Uint8Array([(p.byteLength >>> 8) & 0xff, p.byteLength & 0xff, 0x0d, 0x0a]), p);
}

class VmessReplayCache {
    constructor(ttlMs = 120000) { this.ttlMs = ttlMs; this.map = new Map(); }
    checkAndAdd(authId) {
        const now = Date.now();
        for (const [k, exp] of this.map) {
            if (exp <= now) {
                this.map.delete(k);
            }
        }
        const key = bytesToHex(authId);
        if (this.map.has(key)) {
            return false;
        }
        this.map.set(key, now + this.ttlMs);
        return true;
    }
}

function tryParseVmessHeader(bytes, uuidBytes, replayCache = null, nowSec = Math.floor(Date.now() / 1000)) {
    const b = toU8Sync(bytes);
    if (b.byteLength < 16) {
        return null;
    }
    const cmdKey = vmessCmdKey(uuidBytes);
    const authID = b.slice(0, 16);
    let authPlain;
    try {
        authPlain = aesEcbDecryptBlock(vmessKdf16(cmdKey, KDF_AUTH_ID), authID);
    }
    catch (error) {
        throw new Error(`VMess AuthID AES failure: ${error?.message || error}`);
    }
    const dv = new DataView(authPlain.buffer, authPlain.byteOffset, authPlain.byteLength);
    const timestamp = Number(dv.getBigInt64(0, false));
    const expectedCrc = dv.getUint32(12, false);
    if (expectedCrc !== crc32(authPlain.subarray(0, 12))) {
        throw new Error('invalid VMess AuthID CRC32');
    }
    if (!Number.isSafeInteger(timestamp) || timestamp < 0 || Math.abs(timestamp - nowSec) > 120) {
        throw new Error('invalid VMess AuthID timestamp');
    }
    if (b.byteLength < 42) {
        return null;
    }
    const encLen = b.subarray(16, 34);
    const connNonce = b.subarray(34, 42);
    let lengthPlain;
    try {
        lengthPlain = aeadOpen(VMESS_SECURITY_AES128_GCM, vmessKdf16(cmdKey, KDF_HDR_LEN_KEY, authID, connNonce), vmessKdf(cmdKey, KDF_HDR_LEN_IV, authID, connNonce).slice(0, 12), encLen, authID);
    }
    catch {
        throw new Error('invalid VMess AEAD header length');
    }
    if (lengthPlain.byteLength !== 2) {
        throw new Error('invalid VMess header length plaintext');
    }
    const plainLen = (lengthPlain[0] << 8) | lengthPlain[1];
    if (plainLen < 42 || plainLen > 2048) {
        throw new Error(`invalid VMess request header length ${plainLen}`);
    }
    const total = 42 + plainLen + 16;
    if (b.byteLength < total) {
        return null;
    }
    let plain;
    try {
        plain = aeadOpen(VMESS_SECURITY_AES128_GCM, vmessKdf16(cmdKey, KDF_HDR_KEY, authID, connNonce), vmessKdf(cmdKey, KDF_HDR_IV, authID, connNonce).slice(0, 12), b.subarray(42, total), authID);
    }
    catch {
        throw new Error('invalid VMess AEAD request header');
    }
    if (plain.byteLength !== plainLen || plain.byteLength < 42) {
        throw new Error('invalid VMess request header payload');
    }
    if (plain[0] !== VMESS_VERSION) {
        throw new Error(`invalid VMess version ${plain[0]}`);
    }
    const requestBodyIV = plain.slice(1, 17);
    const requestBodyKey = plain.slice(17, 33);
    const responseHeader = plain[33];
    let option = plain[34];
    const padLen = plain[35] >>> 4;
    const wireSecurity = plain[35] & 0x0f;
    const command = plain[37];
    if (![CMD_TCP, CMD_UDP, CMD_MUX].includes(command)) {
        throw new Error(`unsupported VMess command ${command}`);
    }
    if (wireSecurity === 0 || wireSecurity === VMESS_SECURITY_AUTO) {
        throw new Error('VMess AUTO/UNKNOWN is resolved client-side and is invalid on wire');
    }
    if (![VMESS_SECURITY_AES128_GCM, VMESS_SECURITY_CHACHA20_POLY1305, VMESS_SECURITY_NONE, VMESS_SECURITY_ZERO].includes(wireSecurity)) {
        throw new Error(`unsupported VMess security ${wireSecurity}`);
    }
    let security = wireSecurity;
    if (security === VMESS_SECURITY_ZERO) {
        security = VMESS_SECURITY_NONE;
        option &= ~(VMESS_OPT_CHUNK_STREAM | VMESS_OPT_CHUNK_MASKING | VMESS_OPT_GLOBAL_PADDING | VMESS_OPT_AUTHENTICATED_LENGTH);
    }
    let p = 38;
    let address = 'v1.mux.cool', port = 0, addressType = ATYP_DOMAIN;
    if (command !== CMD_MUX) {
        if (plain.byteLength < p + 3) {
            throw new Error('truncated VMess destination');
        }
        port = (plain[p] << 8) | plain[p + 1];
        p += 2;
        if (!port) {
            throw new Error('zero VMess destination port');
        }
        addressType = plain[p++];
        const a = tryParsePortFirstAddress(plain, p, addressType);
        if (!a) {
            throw new Error('truncated VMess destination address');
        }
        address = a.address;
        p = a.next;
    }
    const checksumPos = plain.byteLength - 4;
    if (p + padLen !== checksumPos) {
        throw new Error('invalid VMess header padding length');
    }
    const expected = new DataView(plain.buffer, plain.byteOffset + checksumPos, 4).getUint32(0, false);
    if (fnv1a32(plain.subarray(0, checksumPos)) !== expected) {
        throw new Error('invalid VMess request checksum');
    }
    if (replayCache && !replayCache.checkAndAdd(authID)) {
        throw new Error('replayed VMess AuthID');
    }
    return {
        command, address, port, addressType, option, security, wireSecurity,
        requestBodyIV, requestBodyKey, responseHeader, headerLength: total, authID,
        responseBodyKey: sha256(requestBodyKey).slice(0, 16),
        responseBodyIV: sha256(requestBodyIV).slice(0, 16),
    };
}

class NonceCounter {
    constructor(iv) { this.base = toU8Sync(iv).slice(); this.count = 0; }
    next(size = 12) {
        const out = this.base.slice();
        out[0] = (this.count >>> 8) & 0xff;
        out[1] = this.count & 0xff;
        this.count = (this.count + 1) & 0xffff;
        return out.slice(0, size);
    }
}

const KECCAK64_MASK = (1n << 64n) - 1n;
const KECCAK_ROTC = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
];
const KECCAK_RC = [
    0x0000000000000001n, 0x0000000000008082n,
    0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n,
    0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n,
    0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn,
    0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n,
    0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n,
    0x0000000080000001n, 0x8000000080008008n,
];
function rotl64(value, shift) {
    const n = BigInt(shift & 63);
    if (n === 0n) {
        return value & KECCAK64_MASK;
    }
    return ((value << n) | (value >> (64n - n))) & KECCAK64_MASK;
}

function keccakF1600(state) {
    const c = new Array(5);
    const d = new Array(5);
    const b = new Array(25);
    for (const rc of KECCAK_RC) {
        // theta
        for (let x = 0; x < 5; x++) {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (let x = 0; x < 5; x++) {
            d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        }
        for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) {
                state[x + 5 * y] = (state[x + 5 * y] ^ d[x]) & KECCAK64_MASK;
            }
        }
        // rho + pi: B[y, 2*x+3*y] = ROT(A[x,y], r[x,y])
        for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) {
                const src = x + 5 * y;
                const nx = y;
                const ny = (2 * x + 3 * y) % 5;
                b[nx + 5 * ny] = rotl64(state[src], KECCAK_ROTC[src]);
            }
        }
        // chi
        for (let y = 0; y < 5; y++) {
            const row = 5 * y;
            for (let x = 0; x < 5; x++) {
                state[row + x] = (b[row + x] ^ ((~b[row + ((x + 1) % 5)]) & b[row + ((x + 2) % 5)])) & KECCAK64_MASK;
            }
        }
        // iota
        state[0] = (state[0] ^ rc) & KECCAK64_MASK;
    }
}

class Shake128Xof {
    constructor(input) {
        this.rate = 168;
        this.state = Array(25).fill(0n);
        this.squeezeOffset = 0;
        this.absorb(toU8Sync(input));
    }
    xorBlock(block) {
        for (let i = 0; i < block.byteLength; i++) {
            const lane = i >>> 3;
            const shift = BigInt((i & 7) * 8);
            this.state[lane] ^= BigInt(block[i]) << shift;
        }
    }
    absorb(input) {
        let offset = 0;
        while (input.byteLength - offset >= this.rate) {
            this.xorBlock(input.subarray(offset, offset + this.rate));
            keccakF1600(this.state);
            offset += this.rate;
        }
        const finalBlock = new Uint8Array(this.rate);
        finalBlock.set(input.subarray(offset));
        finalBlock[input.byteLength - offset] ^= 0x1f;
        finalBlock[this.rate - 1] ^= 0x80;
        this.xorBlock(finalBlock);
        keccakF1600(this.state);
    }
    read(length) {
        if (!Number.isInteger(length) || length < 0) {
            throw new RangeError('invalid SHAKE128 read length');
        }
        const out = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            if (this.squeezeOffset === this.rate) {
                keccakF1600(this.state);
                this.squeezeOffset = 0;
            }
            const p = this.squeezeOffset++;
            const lane = p >>> 3;
            const shift = BigInt((p & 7) * 8);
            out[i] = Number((this.state[lane] >> shift) & 0xffn);
        }
        return out;
    }
}

function shake128Bytes(input, length) {
    return new Shake128Xof(input).read(length);
}

class ShakeSizeParser {
    constructor(seed) { this.shake = new Shake128Xof(seed); }
    nextWord() {
        const b = this.shake.read(2);
        return (b[0] << 8) | b[1];
    }
    decodeSize(bytes) {
        const b = toU8Sync(bytes);
        return (((b[0] << 8) | b[1]) ^ this.nextWord()) & 0xffff;
    }
    encodeSize(size) {
        const v = (size ^ this.nextWord()) & 0xffff;
        return new Uint8Array([v >>> 8, v & 0xff]);
    }
    nextPaddingLen() { return this.nextWord() % 64; }
}

function randomPadding(n) { return n ? new Uint8Array(randomBytes(n)) : new Uint8Array(0); }
class VmessBodyDecoder {
    constructor(header) {
        this.header = header;
        this.pending = new Uint8Array(0);
        this.awaiting = null;
        this.done = false;
        this.transferType = header.command === CMD_UDP ? 'packet' : 'stream';
        this.zeroRaw = header.wireSecurity === VMESS_SECURITY_ZERO || (header.security === VMESS_SECURITY_NONE && !(header.option & VMESS_OPT_CHUNK_STREAM));
        this.sizeShake = (header.option & VMESS_OPT_CHUNK_MASKING) ? new ShakeSizeParser(header.requestBodyIV) : null;
        if ((header.option & VMESS_OPT_GLOBAL_PADDING) && !this.sizeShake) {
            throw new Error('VMess global padding requires chunk masking');
        }
        this.paddingShake = (header.option & VMESS_OPT_GLOBAL_PADDING) ? this.sizeShake : null;
        this.bodyNonce = new NonceCounter(header.requestBodyIV);
        this.lengthNonce = new NonceCounter(header.requestBodyIV);
        this.authLength = !!(header.option & VMESS_OPT_AUTHENTICATED_LENGTH) && [VMESS_SECURITY_AES128_GCM, VMESS_SECURITY_CHACHA20_POLY1305].includes(header.security);
        this.authLengthKey = this.authLength ? vmessKdf16(header.requestBodyKey, KDF_AUTH_LEN) : null;
    }
    push(chunk, messageBoundary = true) {
        if (this.done) {
            return [];
        }
        const c = toU8Sync(chunk);
        if (this.zeroRaw) {
            if (!c.byteLength) {
                return [];
            }
            // For legacy ZERO+UDP there is no protocol-level packet framing; the transport
            // message boundaries are the only usable packet boundary.
            return [c.slice()];
        }
        this.pending = concatBytes(this.pending, c);
        const out = [];
        for (;;) {
            if (!this.awaiting) {
                const sizeBytes = this.authLength ? 18 : 2;
                if (this.pending.byteLength < sizeBytes) {
                    break;
                }
                let padding = 0;
                if (this.paddingShake && (this.header.security !== VMESS_SECURITY_NONE || this.transferType === 'packet')) {
                    padding = this.paddingShake.nextPaddingLen();
                }
                let size;
                const raw = this.pending.slice(0, sizeBytes);
                if (this.authLength) {
                    const plain = aeadOpen(this.header.security, this.authLengthKey, this.lengthNonce.next(12), raw);
                    if (plain.byteLength !== 2) {
                        throw new Error('invalid VMess authenticated length');
                    }
                    size = ((plain[0] << 8) | plain[1]) + 16;
                }
                else if (this.sizeShake) {
                    size = this.sizeShake.decodeSize(raw);
                }
                else {
                    size = (raw[0] << 8) | raw[1];
                }
                this.pending = this.pending.slice(sizeBytes);
                if (size > 65535) {
                    throw new Error(`invalid VMess chunk size ${size}`);
                }
                this.awaiting = { size, padding };
            }
            const { size, padding } = this.awaiting;
            if (this.pending.byteLength < size) {
                break;
            }
            const frame = this.pending.slice(0, size);
            this.pending = this.pending.slice(size);
            this.awaiting = null;
            if (this.header.security === VMESS_SECURITY_NONE) {
                if (this.transferType === 'stream') {
                    if (size === 0) {
                        this.done = true;
                        break;
                    }
                    out.push(frame);
                }
                else {
                    const pad = padding;
                    if (size < pad) {
                        throw new Error('invalid VMess NONE padding');
                    }
                    if (size === pad) {
                        this.done = true;
                        break;
                    }
                    out.push(frame.slice(0, size - pad));
                }
                continue;
            }
            if (size < 16 + padding) {
                throw new Error('VMess AEAD chunk smaller than overhead/padding');
            }
            if (size === 16 + padding) {
                this.done = true;
                break;
            }
            const sealed = frame.slice(0, size - padding);
            const plain = aeadOpen(this.header.security, this.header.requestBodyKey, this.bodyNonce.next(12), sealed);
            out.push(plain);
        }
        return out;
    }
}

class VmessBodyEncoder {
    constructor(header) {
        this.header = header;
        this.responseKey = header.responseBodyKey;
        this.responseIV = header.responseBodyIV;
        this.transferType = header.command === CMD_UDP ? 'packet' : 'stream';
        this.zeroRaw = header.wireSecurity === VMESS_SECURITY_ZERO || (header.security === VMESS_SECURITY_NONE && !(header.option & VMESS_OPT_CHUNK_STREAM));
        this.sizeShake = (header.option & VMESS_OPT_CHUNK_MASKING) ? new ShakeSizeParser(this.responseIV) : null;
        if ((header.option & VMESS_OPT_GLOBAL_PADDING) && !this.sizeShake) {
            throw new Error('VMess global padding requires chunk masking');
        }
        this.paddingShake = (header.option & VMESS_OPT_GLOBAL_PADDING) ? this.sizeShake : null;
        this.bodyNonce = new NonceCounter(this.responseIV);
        this.lengthNonce = new NonceCounter(header.requestBodyIV);
        this.authLength = !!(header.option & VMESS_OPT_AUTHENTICATED_LENGTH) && [VMESS_SECURITY_AES128_GCM, VMESS_SECURITY_CHACHA20_POLY1305].includes(header.security);
        this.authLengthKey = this.authLength ? vmessKdf16(header.requestBodyKey, KDF_AUTH_LEN) : null;
    }
    encode(data) {
        const input = toU8Sync(data);
        if (this.zeroRaw) {
            return input.slice();
        }
        if (this.transferType === 'packet') {
            return this.encodeUnit(input);
        }
        const parts = [];
        for (let off = 0; off < input.byteLength; off += 8192) {
            parts.push(this.encodeUnit(input.slice(off, Math.min(input.byteLength, off + 8192))));
        }
        return concatBytes(...parts);
    }
    encodeUnit(plain) {
        const p = toU8Sync(plain);
        if (this.header.security === VMESS_SECURITY_NONE) {
            if (this.transferType === 'stream') {
                const size = p.byteLength;
                const sb = this.sizeShake ? this.sizeShake.encodeSize(size) : new Uint8Array([size >>> 8, size & 0xff]);
                return concatBytes(sb, p);
            }
            const padding = this.paddingShake ? this.paddingShake.nextPaddingLen() : 0;
            const size = p.byteLength + padding;
            const sb = this.sizeShake ? this.sizeShake.encodeSize(size) : new Uint8Array([size >>> 8, size & 0xff]);
            return concatBytes(sb, p, randomPadding(padding));
        }
        const padding = this.paddingShake ? this.paddingShake.nextPaddingLen() : 0;
        const sealed = aeadSeal(this.header.security, this.responseKey, this.bodyNonce.next(12), p);
        const size = sealed.byteLength + padding;
        let sb;
        if (this.authLength) {
            const plainSize = size - 16;
            sb = aeadSeal(this.header.security, this.authLengthKey, this.lengthNonce.next(12), new Uint8Array([plainSize >>> 8, plainSize & 0xff]));
        }
        else if (this.sizeShake) {
            sb = this.sizeShake.encodeSize(size);
        }
        else {
            sb = new Uint8Array([size >>> 8, size & 0xff]);
        }
        return concatBytes(sb, sealed, randomPadding(padding));
    }
}

function encodeVmessResponseHeader(header) {
    const plain = new Uint8Array([header.responseHeader, 0x00, 0x00, 0x00]);
    const lenPlain = new Uint8Array([0x00, plain.byteLength]);
    const lenKey = vmessKdf16(header.responseBodyKey, KDF_RESP_LEN_KEY);
    const lenIv = vmessKdf(header.responseBodyIV, KDF_RESP_LEN_IV).slice(0, 12);
    const payloadKey = vmessKdf16(header.responseBodyKey, KDF_RESP_KEY);
    const payloadIv = vmessKdf(header.responseBodyIV, KDF_RESP_IV).slice(0, 12);
    return concatBytes(aeadSeal(VMESS_SECURITY_AES128_GCM, lenKey, lenIv, lenPlain), aeadSeal(VMESS_SECURITY_AES128_GCM, payloadKey, payloadIv, plain));
}

function buildVmessClientRequestForTest({ uuid, security = VMESS_SECURITY_AES128_GCM, option = VMESS_OPT_CHUNK_STREAM | VMESS_OPT_CHUNK_MASKING | VMESS_OPT_GLOBAL_PADDING, command = CMD_TCP, address = 'example.com', port = 443, requestBodyKey = null, requestBodyIV = null, responseHeader = 0x42, authTime = Math.floor(Date.now() / 1000) }) {
    const uuidBytes = uuidToBytes(uuid);
    const cmdKey = vmessCmdKey(uuidBytes);
    const bodyKey = requestBodyKey || new Uint8Array(randomBytes(16));
    const bodyIV = requestBodyIV || new Uint8Array(randomBytes(16));
    let actualSecurity = security;
    let actualOption = option;
    if (security === VMESS_SECURITY_AUTO) {
        actualSecurity = VMESS_SECURITY_AES128_GCM;
    }
    if (security === VMESS_SECURITY_ZERO) {
        actualSecurity = VMESS_SECURITY_NONE;
        actualOption &= ~(VMESS_OPT_CHUNK_STREAM | VMESS_OPT_CHUNK_MASKING | VMESS_OPT_GLOBAL_PADDING | VMESS_OPT_AUTHENTICATED_LENGTH);
    }
    const fixed = [new Uint8Array([VMESS_VERSION]), bodyIV, bodyKey, new Uint8Array([responseHeader, actualOption])];
    const padding = new Uint8Array(0);
    fixed.push(new Uint8Array([actualSecurity, 0, command]));
    if (command !== CMD_MUX) {
        fixed.push(encodeVmessPortAddress(address, port));
    }
    let plain = concatBytes(...fixed, padding);
    const checksum = fnv1a32(plain);
    plain = concatBytes(plain, new Uint8Array([checksum >>> 24, (checksum >>> 16) & 0xff, (checksum >>> 8) & 0xff, checksum & 0xff]));
    const authPlain = new Uint8Array(16);
    const adv = new DataView(authPlain.buffer);
    adv.setBigInt64(0, BigInt(authTime), false);
    const rnd = randomBytes(4);
    authPlain.set(rnd, 8);
    adv.setUint32(12, crc32(authPlain.subarray(0, 12)), false);
    const authKey = vmessKdf16(cmdKey, KDF_AUTH_ID);
    const authID = aesEcbEncryptBlock(authKey, authPlain);
    const connNonce = new Uint8Array(randomBytes(8));
    const lenPlain = new Uint8Array([plain.byteLength >>> 8, plain.byteLength & 0xff]);
    return {
        bytes: concatBytes(authID, aeadSeal(VMESS_SECURITY_AES128_GCM, vmessKdf16(cmdKey, KDF_HDR_LEN_KEY, authID, connNonce), vmessKdf(cmdKey, KDF_HDR_LEN_IV, authID, connNonce).slice(0, 12), lenPlain, authID), connNonce, aeadSeal(VMESS_SECURITY_AES128_GCM, vmessKdf16(cmdKey, KDF_HDR_KEY, authID, connNonce), vmessKdf(cmdKey, KDF_HDR_IV, authID, connNonce).slice(0, 12), plain, authID)),
        header: { command, address, port, option: actualOption, security: actualSecurity, wireSecurity: actualSecurity, requestBodyKey: bodyKey, requestBodyIV: bodyIV, responseHeader, responseBodyKey: sha256(bodyKey).slice(0, 16), responseBodyIV: sha256(bodyIV).slice(0, 16) },
    };
}

function encodeVmessPortAddress(address, port) {
    const p = new Uint8Array([port >>> 8, port & 0xff]);
    const type = inferAddressType(address);
    if (type === ATYP_IPV4) {
        return concatBytes(p, new Uint8Array([ATYP_IPV4]), ipv4ToBytes(address));
    }
    if (type === ATYP_IPV6) {
        return concatBytes(p, new Uint8Array([ATYP_IPV6]), ipv6ToBytes(address));
    }
    const d = utf8(address);
    return concatBytes(p, new Uint8Array([ATYP_DOMAIN, d.byteLength]), d);
}
const SS_LEGACY_MAX_CHUNK = 0x3fff;
const SS2022_MAX_CHUNK = 0xffff;
const SS2022_CONTEXT = 'shadowsocks 2022 session subkey';
const SS_UOT_V1 = 'sp.udp-over-tcp.arpa';
const SS_UOT_V2 = 'sp.v2.udp-over-tcp.arpa';
function normalizeSsMethod(method) {
    const m = String(method || '').trim().toLowerCase();
    const aliases = {
        'aead_aes_128_gcm': 'aes-128-gcm', 'aead_aes_256_gcm': 'aes-256-gcm',
        'chacha20-poly1305': 'chacha20-ietf-poly1305', 'aead_chacha20_poly1305': 'chacha20-ietf-poly1305',
        'xchacha20-poly1305': 'xchacha20-ietf-poly1305', 'aead_xchacha20_poly1305': 'xchacha20-ietf-poly1305',
    };
    return aliases[m] || m;
}

function ssMethodSpec(method) {
    const m = normalizeSsMethod(method);
    const map = {
        'aes-128-gcm': { method: m, family: 'legacy', keySize: 16, saltSize: 16, aead: 'aes-128-gcm', nonceSize: 12, maxChunk: SS_LEGACY_MAX_CHUNK },
        'aes-256-gcm': { method: m, family: 'legacy', keySize: 32, saltSize: 32, aead: 'aes-256-gcm', nonceSize: 12, maxChunk: SS_LEGACY_MAX_CHUNK },
        'chacha20-ietf-poly1305': { method: m, family: 'legacy', keySize: 32, saltSize: 32, aead: 'chacha20-poly1305', nonceSize: 12, maxChunk: SS_LEGACY_MAX_CHUNK },
        'xchacha20-ietf-poly1305': { method: m, family: 'legacy', keySize: 32, saltSize: 32, aead: 'xchacha20-poly1305', nonceSize: 24, maxChunk: SS_LEGACY_MAX_CHUNK },
        '2022-blake3-aes-128-gcm': { method: m, family: '2022', keySize: 16, saltSize: 16, aead: 'aes-128-gcm', nonceSize: 12, maxChunk: SS2022_MAX_CHUNK },
        '2022-blake3-aes-256-gcm': { method: m, family: '2022', keySize: 32, saltSize: 32, aead: 'aes-256-gcm', nonceSize: 12, maxChunk: SS2022_MAX_CHUNK },
        '2022-blake3-chacha20-poly1305': { method: m, family: '2022', keySize: 32, saltSize: 32, aead: 'chacha20-poly1305', nonceSize: 12, maxChunk: SS2022_MAX_CHUNK },
    };
    if (!map[m]) {
        throw new Error(`unsupported Shadowsocks method ${method}`);
    }
    return map[m];
}

function ssLegacyMasterKey(password, keySize) {
    const p = utf8(password);
    let prev = new Uint8Array(0);
    let out = new Uint8Array(0);
    while (out.length < keySize) {
        prev = md5(concatBytes(prev, p));
        out = concatBytes(out, prev);
    }
    return out.slice(0, keySize);
}

function hmacSha1(key, data) { return hmacWithHash(sha1Raw, toU8Sync(key), toU8Sync(data)); }
function hkdfSha1(secret, salt, info, length) {
    const prk = hmacSha1(salt, secret);
    let t = new Uint8Array(0), out = new Uint8Array(0), c = 1;
    while (out.length < length) {
        t = hmacSha1(prk, concatBytes(t, info, new Uint8Array([c++])));
        out = concatBytes(out, t);
    }
    return out.slice(0, length);
}

function ssLegacySessionKey(master, salt, keySize) { return hkdfSha1(master, toU8Sync(salt), utf8('ss-subkey'), keySize); }
const B3_IV = new Uint32Array([0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]);
const B3_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const B3_CHUNK_START = 1, B3_CHUNK_END = 2, B3_ROOT = 8, B3_DERIVE_CONTEXT = 32, B3_DERIVE_MATERIAL = 64;
function b3Rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
function b3G(v, a, b, c, d, x, y) { v[a] = (v[a] + v[b] + x) >>> 0; v[d] = b3Rotr(v[d] ^ v[a], 16); v[c] = (v[c] + v[d]) >>> 0; v[b] = b3Rotr(v[b] ^ v[c], 12); v[a] = (v[a] + v[b] + y) >>> 0; v[d] = b3Rotr(v[d] ^ v[a], 8); v[c] = (v[c] + v[d]) >>> 0; v[b] = b3Rotr(v[b] ^ v[c], 7); }
function b3Round(v, m) { b3G(v, 0, 4, 8, 12, m[0], m[1]); b3G(v, 1, 5, 9, 13, m[2], m[3]); b3G(v, 2, 6, 10, 14, m[4], m[5]); b3G(v, 3, 7, 11, 15, m[6], m[7]); b3G(v, 0, 5, 10, 15, m[8], m[9]); b3G(v, 1, 6, 11, 12, m[10], m[11]); b3G(v, 2, 7, 8, 13, m[12], m[13]); b3G(v, 3, 4, 9, 14, m[14], m[15]); }
function b3Perm(m) {
    const o = new Uint32Array(16);
    for (let i = 0; i < 16; i++) {
        o[i] = m[B3_PERM[i]];
    }
    return o;
}

function b3Words(input) {
    const b = toU8Sync(input), w = new Uint32Array(16);
    for (let i = 0; i < b.length; i++) {
        w[i >>> 2] |= b[i] << ((i & 3) * 8);
    }
    return w;
}

function b3Compress(cv, bw, counter, blockLen, flags) {
    const v = new Uint32Array(16);
    v.set(cv);
    v[8] = B3_IV[0];
    v[9] = B3_IV[1];
    v[10] = B3_IV[2];
    v[11] = B3_IV[3];
    const c = BigInt(counter);
    v[12] = Number(c & 0xffffffffn);
    v[13] = Number((c >> 32n) & 0xffffffffn);
    v[14] = blockLen;
    v[15] = flags;
    let m = new Uint32Array(bw);
    for (let r = 0; r < 7; r++) {
        b3Round(v, m);
        if (r < 6) {
            m = b3Perm(m);
        }
    }
    const o = new Uint32Array(16);
    for (let i = 0; i < 8; i++) {
        o[i] = (v[i] ^ v[i + 8]) >>> 0;
        o[i + 8] = (v[i + 8] ^ cv[i]) >>> 0;
    }
    return o;
}

function b3Bytes(words, n = 32) {
    const o = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
        o[i] = (words[i >>> 2] >>> ((i & 3) * 8)) & 255;
    }
    return o;
}

function b3Single(input, keyWords, flags) {
    const b = toU8Sync(input);
    if (b.length > 64) {
        throw new Error('BLAKE3 small input overflow');
    }
    return b3Bytes(b3Compress(keyWords, b3Words(b), 0, b.length, flags | B3_CHUNK_START | B3_CHUNK_END | B3_ROOT), 32);
}

function blake3DeriveKey(context, material) {
    const ck = b3Single(utf8(context), B3_IV, B3_DERIVE_CONTEXT);
    const kw = new Uint32Array(8), dv = new DataView(ck.buffer, ck.byteOffset, ck.byteLength);
    for (let i = 0; i < 8; i++) {
        kw[i] = dv.getUint32(i * 4, true);
    }
    return b3Single(material, kw, B3_DERIVE_MATERIAL);
}

function ss2022RootPasswordBytesFromUuid(uuidBytes) {
    const u = toU8Sync(uuidBytes);
    if (u.length !== 16) {
        throw new Error('UUID bytes must be 16');
    }
    return sha256(u);
}

function ss2022NormalizePsk(decodedPassword, keySize) {
    const p = toU8Sync(decodedPassword);
    if (p.length < keySize) {
        throw new Error(`SS2022 decoded password is too short for ${keySize}-byte key`);
    }
    if (p.length === keySize) {
        return p.slice();
    }
    return sha256(p).slice(0, keySize);
}

function ss2022PasswordFromUuid(uuidBytes) { return bytesToBase64(ss2022RootPasswordBytesFromUuid(uuidBytes)); }
function ss2022PskCandidatesFromUuid(uuidBytes, keySize) {
    const u = toU8Sync(uuidBytes);
    if (u.length !== 16) {
        throw new Error('UUID bytes must be 16');
    }
    const root = ss2022RootPasswordBytesFromUuid(u);
    const candidates = [ss2022NormalizePsk(root, keySize)];
    const legacy = keySize === 16 ? u.slice() : root.slice();
    const seen = new Set(), out = [];
    for (const c of candidates.concat([legacy])) {
        const h = bytesToHex(c);
        if (!seen.has(h)) {
            seen.add(h);
            out.push(c);
        }
    }
    return out;
}

function ss2022SessionKey(psk, salt, keySize) { return blake3DeriveKey(SS2022_CONTEXT, concatBytes(psk, salt)).slice(0, keySize); }
function u32le(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
function put32le(b, o, v) { b[o] = v & 255; b[o + 1] = (v >>> 8) & 255; b[o + 2] = (v >>> 16) & 255; b[o + 3] = (v >>> 24) & 255; }
function qr(s, a, b, c, d) { s[a] = (s[a] + s[b]) >>> 0; s[d] ^= s[a]; s[d] = ((s[d] << 16) | (s[d] >>> 16)) >>> 0; s[c] = (s[c] + s[d]) >>> 0; s[b] ^= s[c]; s[b] = ((s[b] << 12) | (s[b] >>> 20)) >>> 0; s[a] = (s[a] + s[b]) >>> 0; s[d] ^= s[a]; s[d] = ((s[d] << 8) | (s[d] >>> 24)) >>> 0; s[c] = (s[c] + s[d]) >>> 0; s[b] ^= s[c]; s[b] = ((s[b] << 7) | (s[b] >>> 25)) >>> 0; }
function hchacha20(key, nonce16) {
    const k = toU8Sync(key), n = toU8Sync(nonce16);
    const s = new Uint32Array(16);
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for (let i = 0; i < 8; i++) {
        s[4 + i] = u32le(k, i * 4);
    }
    for (let i = 0; i < 4; i++) {
        s[12 + i] = u32le(n, i * 4);
    }
    for (let i = 0; i < 10; i++) {
        qr(s, 0, 4, 8, 12);
        qr(s, 1, 5, 9, 13);
        qr(s, 2, 6, 10, 14);
        qr(s, 3, 7, 11, 15);
        qr(s, 0, 5, 10, 15);
        qr(s, 1, 6, 11, 12);
        qr(s, 2, 7, 8, 13);
        qr(s, 3, 4, 9, 14);
    }
    const out = new Uint8Array(32);
    for (const [j, idx] of [0, 1, 2, 3, 12, 13, 14, 15].entries()) {
        put32le(out, j * 4, s[idx]);
    }
    return out;
}

function normalizeCipher(spec, key, nonce) {
    if (spec.aead !== 'xchacha20-poly1305') {
        return { name: spec.aead, key: toU8Sync(key), nonce: toU8Sync(nonce) };
    }
    const n = toU8Sync(nonce);
    return { name: 'chacha20-poly1305', key: hchacha20(key, n.slice(0, 16)), nonce: concatBytes(new Uint8Array(4), n.slice(16, 24)) };
}

function ssSeal(spec, key, nonce, plain) {
    const c = normalizeCipher(spec, key, nonce);
    return pureAeadSeal(c.name, c.key, c.nonce, toU8Sync(plain), null);
}
function ssOpen(spec, key, nonce, sealed) {
    const input = toU8Sync(sealed);
    if (input.length < 16) {
        throw new Error('SS AEAD short');
    }
    const c = normalizeCipher(spec, key, nonce);
    return pureAeadOpen(c.name, c.key, c.nonce, input, null);
}

function incNonce(n) {
    for (let i = 0; i < n.length; i++) {
        n[i] = (n[i] + 1) & 255;
        if (n[i]) {
            break;
        }
    }
}

class SsChunkDecoder {
    constructor(spec, sessionKey, nonce = null) { this.spec = spec; this.key = toU8Sync(sessionKey); this.nonce = nonce ? toU8Sync(nonce).slice() : new Uint8Array(spec.nonceSize); this.pending = new Uint8Array(0); this.want = -1; }
    push(data) {
        this.pending = concatBytes(this.pending, data);
        const out = [];
        for (;;) {
            if (this.want < 0) {
                if (this.pending.length < 18) {
                    break;
                }
                const p = ssOpen(this.spec, this.key, this.nonce, this.pending.slice(0, 18));
                incNonce(this.nonce);
                this.pending = this.pending.slice(18);
                this.want = (p[0] << 8) | p[1];
                if (this.want < 0 || this.want > this.spec.maxChunk) {
                    throw new Error(`invalid Shadowsocks chunk length ${this.want}`);
                }
            }
            if (this.pending.length < this.want + 16) {
                break;
            }
            const p = ssOpen(this.spec, this.key, this.nonce, this.pending.slice(0, this.want + 16));
            incNonce(this.nonce);
            this.pending = this.pending.slice(this.want + 16);
            this.want = -1;
            out.push(p);
        }
        return out;
    }
}

class SsChunkEncoder {
    constructor(spec, sessionKey, nonce = null) { this.spec = spec; this.key = toU8Sync(sessionKey); this.nonce = nonce ? toU8Sync(nonce).slice() : new Uint8Array(spec.nonceSize); }
    encode(data) {
        const p = toU8Sync(data);
        const parts = [];
        for (let o = 0; o < p.length; o += this.spec.maxChunk) {
            const chunk = p.slice(o, Math.min(p.length, o + this.spec.maxChunk));
            const l = new Uint8Array([chunk.length >>> 8, chunk.length & 255]);
            parts.push(ssSeal(this.spec, this.key, this.nonce, l));
            incNonce(this.nonce);
            parts.push(ssSeal(this.spec, this.key, this.nonce, chunk));
            incNonce(this.nonce);
        }
        return concatBytes(...parts);
    }
}

class SsSaltReplayCache {
    constructor(ttlMs = 60000, maxEntries = 8192) {
        this.ttlMs = ttlMs;
        this.maxEntries = maxEntries;
        this.map = new Map();
    }
    checkAndAdd(method, salt) {
        const now = Date.now();
        for (const [key, expires] of this.map) {
            if (expires <= now) {
                this.map.delete(key);
            }
        }
        const key = `${normalizeSsMethod(method)}:${bytesToHex(salt)}`;
        if (this.map.has(key)) {
            return false;
        }
        while (this.map.size >= this.maxEntries) {
            const oldest = this.map.keys().next().value;
            if (oldest === undefined) {
                break;
            }
            this.map.delete(oldest);
        }
        this.map.set(key, now + this.ttlMs);
        return true;
    }
}

class SsLegacyServerCodec {
    constructor(method, password, replayCache = null) {
        this.spec = ssMethodSpec(method);
        if (this.spec.family !== 'legacy') {
            throw new Error('not legacy');
        }
        this.master = ssLegacyMasterKey(password, this.spec.keySize);
        this.replayCache = replayCache;
        this.pending = new Uint8Array(0);
        this.decoder = null;
        this.encoder = null;
    }
    push(data) {
        this.pending = concatBytes(this.pending, data);
        if (!this.decoder) {
            if (this.pending.length < this.spec.saltSize) {
                return [];
            }
            const salt = this.pending.slice(0, this.spec.saltSize);
            if (this.replayCache && !this.replayCache.checkAndAdd(this.spec.method, salt)) {
                throw new Error('replayed Shadowsocks salt');
            }
            this.pending = this.pending.slice(this.spec.saltSize);
            const key = ssLegacySessionKey(this.master, salt, this.spec.keySize);
            this.decoder = new SsChunkDecoder(this.spec, key);
        }
        const pending = this.pending;
        this.pending = new Uint8Array(0);
        return this.decoder.push(pending);
    }
    encode(data) {
        if (!this.encoder) {
            const salt = new Uint8Array(randomBytes(this.spec.saltSize));
            const key = ssLegacySessionKey(this.master, salt, this.spec.keySize);
            this.encoder = new SsChunkEncoder(this.spec, key);
            return concatBytes(salt, this.encoder.encode(data));
        }
        return this.encoder.encode(data);
    }
}

class Ss2022ServerCodec {
    constructor(method, pskCandidates, replayCache = null, now = () => Math.floor(Date.now() / 1000)) {
        this.spec = ssMethodSpec(method);
        if (this.spec.family !== '2022') {
            throw new Error('not 2022');
        }
        const list = Array.isArray(pskCandidates) ? pskCandidates : [pskCandidates];
        this.pskCandidates = list.map((p) => toU8Sync(p).slice());
        if (!this.pskCandidates.length) {
            throw new Error('missing Shadowsocks 2022 PSK');
        }
        this.psk = null;
        this.replayCache = replayCache;
        this.now = now;
        this.pending = new Uint8Array(0);
        this.state = 'salt';
        this.requestSalt = null;
        this.key = null;
        this.nonce = null;
        this.variableLen = 0;
        this.streamDecoder = null;
        this.encoder = null;
        this.header = null;
    }
    push(data) {
        this.pending = concatBytes(this.pending, data);
        const out = [];
        for (;;) {
            if (this.state === 'salt') {
                const need = this.spec.saltSize + 11 + 16;
                if (this.pending.length < need) {
                    break;
                }
                this.requestSalt = this.pending.slice(0, this.spec.saltSize);
                if (this.replayCache && !this.replayCache.checkAndAdd(this.spec.method, this.requestSalt)) {
                    throw new Error('replayed Shadowsocks 2022 salt');
                }
                const sealedFixed = this.pending.slice(this.spec.saltSize, need);
                let fixed = null, chosenPsk = null, chosenKey = null;
                for (const candidate of this.pskCandidates) {
                    const candidateKey = ss2022SessionKey(candidate, this.requestSalt, this.spec.keySize);
                    try {
                        fixed = ssOpen(this.spec, candidateKey, new Uint8Array(this.spec.nonceSize), sealedFixed);
                        chosenPsk = candidate;
                        chosenKey = candidateKey;
                        break;
                    }
                    catch { }
                }
                if (!fixed) {
                    throw new Error(`Shadowsocks 2022 fixed-header authentication failed (method=${this.spec.method}; verify client method/password and transport framing)`);
                }
                this.psk = chosenPsk;
                this.key = chosenKey;
                this.nonce = new Uint8Array(this.spec.nonceSize);
                incNonce(this.nonce);
                this.pending = this.pending.slice(need);
                if (fixed[0] !== 0) {
                    throw new Error(`invalid Shadowsocks 2022 request header type ${fixed[0]}`);
                }
                const dv = new DataView(fixed.buffer, fixed.byteOffset, fixed.byteLength);
                const epoch = Number(dv.getBigUint64(1, false));
                if (Math.abs(epoch - this.now()) > 30) {
                    throw new Error('invalid Shadowsocks 2022 timestamp');
                }
                this.variableLen = dv.getUint16(9, false);
                if (this.variableLen < 1 || this.variableLen > 0xffff) {
                    throw new Error('invalid Shadowsocks 2022 variable header length');
                }
                this.state = 'variable';
            }
            else if (this.state === 'variable') {
                if (this.pending.length < this.variableLen + 16) {
                    break;
                }
                const variable = ssOpen(this.spec, this.key, this.nonce, this.pending.slice(0, this.variableLen + 16));
                incNonce(this.nonce);
                this.pending = this.pending.slice(this.variableLen + 16);
                const ep = parseSsAddress(variable, 0, true);
                if (!ep) {
                    throw new Error('truncated Shadowsocks 2022 destination');
                }
                if (variable.length < ep.next + 2) {
                    throw new Error('truncated Shadowsocks 2022 padding length');
                }
                const pad = (variable[ep.next] << 8) | variable[ep.next + 1];
                const start = ep.next + 2 + pad;
                if (start > variable.length) {
                    throw new Error('bad Shadowsocks 2022 padding');
                }
                if (pad === 0 && start === variable.length) {
                    throw new Error('Shadowsocks 2022 requires padding or initial payload');
                }
                this.header = ep;
                const initial = variable.slice(start);
                if (initial.length) {
                    out.push(initial);
                }
                this.streamDecoder = new SsChunkDecoder(this.spec, this.key, this.nonce);
                this.state = 'stream';
            }
            else {
                if (this.pending.length) {
                    const pending = this.pending;
                    this.pending = new Uint8Array(0);
                    out.push(...this.streamDecoder.push(pending));
                }
                break;
            }
        }
        return out;
    }
    encode(data) {
        const payload = toU8Sync(data);
        if (!this.encoder) {
            const salt = new Uint8Array(randomBytes(this.spec.saltSize));
            const key = ss2022SessionKey(this.psk, salt, this.spec.keySize);
            const nonce = new Uint8Array(this.spec.nonceSize);
            const take = Math.min(payload.length, this.spec.maxChunk);
            const fixed = new Uint8Array(1 + 8 + this.spec.saltSize + 2);
            const dv = new DataView(fixed.buffer);
            fixed[0] = 1;
            dv.setBigUint64(1, BigInt(this.now()), false);
            fixed.set(this.requestSalt, 9);
            dv.setUint16(9 + this.spec.saltSize, take, false);
            const sealedFixed = ssSeal(this.spec, key, nonce, fixed);
            incNonce(nonce);
            let first = new Uint8Array(0);
            if (take) {
                first = ssSeal(this.spec, key, nonce, payload.slice(0, take));
                incNonce(nonce);
            }
            this.encoder = new SsChunkEncoder(this.spec, key, nonce);
            return concatBytes(salt, sealedFixed, first, this.encoder.encode(payload.slice(take)));
        }
        return this.encoder.encode(payload);
    }
}

function encodeSsAddress(endpoint, allowZero = false) {
    let out;
    const a = String(endpoint.address), port = Number(endpoint.port);
    if (!allowZero && port === 0) {
        throw new Error('zero SS port');
    }
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(a)) {
        out = new Uint8Array([1, ...a.split('.').map(Number)]);
    }
    else if (a.includes(':')) {
        out = concatBytes(new Uint8Array([4]), ipv6ToBytes(a));
    }
    else {
        const d = utf8(a);
        out = concatBytes(new Uint8Array([3, d.length]), d);
    }
    return concatBytes(out, new Uint8Array([port >>> 8, port & 255]));
}

function parseSsAddress(bytes, offset = 0, allowZero = false) {
    const b = toU8Sync(bytes);
    if (b.length < offset + 1) {
        return null;
    }
    const type = b[offset++] & 0x0f;
    let address, addressType;
    if (type === 1) {
        if (b.length < offset + 6) {
            return null;
        }
        address = Array.from(b.slice(offset, offset + 4)).join('.');
        addressType = ATYP_IPV4;
        offset += 4;
    }
    else if (type === 3) {
        if (b.length < offset + 1) {
            return null;
        }
        const n = b[offset++];
        if (!n || b.length < offset + n + 2) {
            return null;
        }
        address = new TextDecoder().decode(b.slice(offset, offset + n));
        addressType = ATYP_DOMAIN;
        offset += n;
    }
    else if (type === 4) {
        if (b.length < offset + 18) {
            return null;
        }
        const arr = [];
        for (let i = 0; i < 8; i++) {
            arr.push(((b[offset + i * 2] << 8) | b[offset + i * 2 + 1]).toString(16));
        }
        address = ipv6FromBytes(b.slice(offset, offset + 16));
        addressType = ATYP_IPV6;
        offset += 16;
    }
    else {
        throw new Error(`invalid Shadowsocks address type ${type}`);
    }
    const port = (b[offset] << 8) | b[offset + 1];
    offset += 2;
    if (!allowZero && !port) {
        throw new Error('zero Shadowsocks port');
    }
    return { address, port, addressType, next: offset };
}

function parseUotAddress(bytes, offset = 0) {
    const b = toU8Sync(bytes);
    if (b.length < offset + 1) {
        return null;
    }
    const t = b[offset++];
    let address, addressType;
    if (t === 0) {
        if (b.length < offset + 6) {
            return null;
        }
        address = Array.from(b.slice(offset, offset + 4)).join('.');
        addressType = ATYP_IPV4;
        offset += 4;
    }
    else if (t === 1) {
        if (b.length < offset + 18) {
            return null;
        }
        const arr = [];
        for (let i = 0; i < 8; i++) {
            arr.push(((b[offset + i * 2] << 8) | b[offset + i * 2 + 1]).toString(16));
        }
        address = ipv6FromBytes(b.slice(offset, offset + 16));
        addressType = ATYP_IPV6;
        offset += 16;
    }
    else if (t === 2) {
        if (b.length < offset + 1) {
            return null;
        }
        const n = b[offset++];
        if (!n || b.length < offset + n + 2) {
            return null;
        }
        address = new TextDecoder().decode(b.slice(offset, offset + n));
        addressType = ATYP_DOMAIN;
        offset += n;
    }
    else {
        throw new Error(`invalid UoT address type ${t}`);
    }
    const port = (b[offset] << 8) | b[offset + 1];
    offset += 2;
    if (!port) {
        throw new Error('zero UoT port');
    }
    return { address, port, addressType, next: offset };
}

function encodeUotAddress(ep) {
    const a = String(ep.address), port = Number(ep.port);
    let head;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(a)) {
        head = new Uint8Array([0, ...a.split('.').map(Number)]);
    }
    else if (a.includes(':')) {
        head = concatBytes(new Uint8Array([1]), ipv6ToBytes(a));
    }
    else {
        const d = utf8(a);
        head = concatBytes(new Uint8Array([2, d.length]), d);
    }
    return concatBytes(head, new Uint8Array([port >>> 8, port & 255]));
}

class UotV1Decoder {
    constructor() { this.pending = new Uint8Array(0); }
    push(data) {
        this.pending = concatBytes(this.pending, data);
        const out = [];
        for (;;) {
            let ep;
            try {
                ep = parseUotAddress(this.pending, 0);
            }
            catch (e) {
                throw e;
            }
            if (!ep) {
                break;
            }
            if (this.pending.length < ep.next + 2) {
                break;
            }
            const len = (this.pending[ep.next] << 8) | this.pending[ep.next + 1];
            if (this.pending.length < ep.next + 2 + len) {
                break;
            }
            out.push({ endpoint: ep, payload: this.pending.slice(ep.next + 2, ep.next + 2 + len) });
            this.pending = this.pending.slice(ep.next + 2 + len);
        }
        return out;
    }
}

function encodeUotV1Packet(ep, payload) { const p = toU8Sync(payload); return concatBytes(encodeUotAddress(ep), new Uint8Array([p.length >>> 8, p.length & 255]), p); }
class UotV2Decoder {
    constructor() { this.pending = new Uint8Array(0); this.header = null; }
    push(data) {
        this.pending = concatBytes(this.pending, data);
        const out = [];
        if (!this.header) {
            if (this.pending.length < 1) {
                return out;
            }
            const isConnect = this.pending[0];
            const ep = parseUotAddress(this.pending, 1);
            if (!ep) {
                return out;
            }
            this.header = { isConnect: isConnect === 1, endpoint: ep };
            this.pending = this.pending.slice(ep.next);
        }
        if (this.header.isConnect) {
            for (;;) {
                if (this.pending.length < 2) {
                    break;
                }
                const n = (this.pending[0] << 8) | this.pending[1];
                if (this.pending.length < 2 + n) {
                    break;
                }
                out.push({ endpoint: this.header.endpoint, payload: this.pending.slice(2, 2 + n) });
                this.pending = this.pending.slice(2 + n);
            }
        }
        else {
            const d = new UotV1Decoder();
            d.pending = this.pending;
            out.push(...d.push(new Uint8Array(0)));
            this.pending = d.pending;
        }
        return out;
    }
}

function encodeUotV2ConnectPacket(payload) { const p = toU8Sync(payload); return concatBytes(new Uint8Array([p.length >>> 8, p.length & 255]), p); }

const WS_OPEN = 1;
const WS_CLOSING = 2;
const RELAY_MAGIC = new TextEncoder().encode('VLRLY004');
const RELAY_MODE_FIXED_UDP = 0x01;
const RELAY_MODE_MUX = 0x02;
const RELAY_MODE_PACKET_UDP = 0x03;
const UUID_TEXT = normalizeUUID(CONFIG.UUID);
const UUID_BYTES = uuidToBytes(UUID_TEXT);
const VLESS_USER_KEY = processVlessUUID(UUID_BYTES);
const TROJAN_HASH = sha224Hex(UUID_TEXT);
const VMESS_REPLAY = new VmessReplayCache();
const SS_REPLAY = new SsSaltReplayCache();
const SS_SPEC = ssMethodSpec(CONFIG.SS_METHOD);
const SS_2022_PSK_CANDIDATES = SS_SPEC.family === '2022' ? ss2022PskCandidatesFromUuid(UUID_BYTES, SS_SPEC.keySize) : null;
const SS_CLIENT_PASSWORD = SS_SPEC.family === '2022' ? ss2022PasswordFromUuid(UUID_BYTES) : UUID_TEXT;
function rejectUdpEndpoint(endpoint) {
    return Boolean(CONFIG.REJECT_UDP_443 && Number(endpoint?.port) === 443);
}

function assertUdpEndpointAllowed(endpoint) {
    if (rejectUdpEndpoint(endpoint)) {
        throw new Error('UDP/443 is rejected to force QUIC/HTTP3 fallback to TCP');
    }
}

function isDnsEndpoint(endpoint) {
    return Number(endpoint?.port) === 53;
}

async function resolveDnsOverHttps(payload) {
    const query = toU8Sync(payload);
    if (query.byteLength < 12 || query.byteLength > 65535) {
        throw new Error(`invalid DNS message length ${query.byteLength}`);
    }
    const errors = [];
    for (const url of CONFIG.DNS_DOH_URLS) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), CONFIG.DNS_DOH_TIMEOUT_MS);
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/dns-message',
                    'Accept': 'application/dns-message',
                },
                body: query,
                signal: controller.signal,
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const answer = new Uint8Array(await response.arrayBuffer());
            if (answer.byteLength < 12 || answer.byteLength > 65535) {
                throw new Error(`invalid DNS response length ${answer.byteLength}`);
            }
            if (answer[0] !== query[0] || answer[1] !== query[1]) {
                throw new Error('DNS response transaction ID mismatch');
            }
            return answer;
        }
        catch (error) {
            errors.push(`${url}: ${error?.message || error}`);
        }
        finally {
            clearTimeout(timer);
        }
    }
    throw new Error(`Worker DoH failed: ${errors.join('; ')}`);
}

class LengthPrefixedPacketDecoder {
    constructor() { this.pending = new Uint8Array(0); }
    push(chunk) {
        const input = toU8Sync(chunk);
        if (input.byteLength) {
            this.pending = concatBytes(this.pending, input);
        }
        const out = [];
        for (;;) {
            if (this.pending.byteLength < 2) {
                break;
            }
            const length = (this.pending[0] << 8) | this.pending[1];
            if (length > 65535) {
                throw new Error(`UDP packet too large: ${length}`);
            }
            if (this.pending.byteLength < 2 + length) {
                break;
            }
            out.push(this.pending.slice(2, 2 + length));
            this.pending = this.pending.slice(2 + length);
        }
        return out;
    }
}

class FixedDnsOverHttps {
    constructor(onPacket) {
        this.decoder = new LengthPrefixedPacketDecoder();
        this.onPacket = onPacket;
    }
    async writeRaw(bytes) {
        for (const packet of this.decoder.push(bytes)) {
            const answer = await resolveDnsOverHttps(packet);
            this.onPacket(answer);
        }
    }
}

function createProtocolSession(protocol, transport, proxyAddress) {
    switch (protocol) {
        case 'vless':
            return new VlessSession(transport, proxyAddress);
        case 'trojan':
            return new TrojanSession(transport, proxyAddress);
        case 'vmess':
            return new VmessSession(transport, proxyAddress);
        case 'ss':
            return new ShadowsocksSession(transport, proxyAddress);
        default:
            throw new Error(`unsupported protocol ${protocol}`);
    }
}

function isWebSocketUpgrade(request) {
    const upgrade = request.headers.get('Upgrade');
    return Boolean(upgrade && upgrade.toLowerCase() === 'websocket');
}

function isXHttpStreamOneRequest(request) {
    if (request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS') {
        return false;
    }
    return request.body !== null;
}

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: SUB_CORS });
            if (url.pathname.startsWith('/api/v1/')) {
                const compatibility = await subResponse(request, env || {});
                if (compatibility) return compatibility;
            }
            const route = parseProtocolPath(url.pathname);
            if (!route) {
                return new Response('Not Found', { status: 404 });
            }
            if (isWebSocketUpgrade(request)) {
                return handleWebSocket(request, route, url);
            }
            if (isXHttpStreamOneRequest(request)) {
                return handleXHttpStreamOne(request, route);
            }
            return new Response('Not Found', { status: 404 });
        }
        catch (error) {
            console.error('fetch error', error?.stack || String(error));
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};
async function handleWebSocket(request, route, url) {
    const pair = new WebSocketPair();
    const [client, ws] = Object.values(pair);
    ws.accept();
    const session = createProtocolSession(route.protocol, ws, route.proxyAddress);
    let chain = Promise.resolve();
    const enqueue = (data) => {
        chain = chain
            .then(async () => {
            if (session.closed) {
                return;
            }
            const bytes = await toUint8Array(data);
            await session.ingest(bytes);
        })
            .catch((error) => {
            console.error(`${route.protocol} session error`, error?.stack || String(error));
            session.close();
        });
    };
    const earlyHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
    const earlyLimit = parseEarlyDataLimit(url);
    const earlyData = earlyLimit > 0
        ? decodeEarlyData(earlyHeader, earlyLimit)
        : null;
    if (earlyData?.byteLength) {
        enqueue(earlyData);
    }
    ws.addEventListener('message', (event) => {
        enqueue(event.data);
    });
    ws.addEventListener('close', () => {
        chain.finally(() => session.close());
    });
    ws.addEventListener('error', (event) => {
        console.error('WebSocket error', event?.message || event);
        session.close();
    });
    const headers = new Headers();
    if (earlyData?.byteLength && earlyHeader) {
        headers.set('Sec-WebSocket-Protocol', earlyHeader);
    }
    return new Response(null, {
        status: 101,
        webSocket: client,
        headers,
    });
}

function handleXHttpStreamOne(request, route) {
    let session = null;
    let channel = null;
    const responseBody = new ReadableStream({
        start(controller) {
            channel = new XHttpStreamChannel(controller);
        },
        cancel() {
            if (channel) {
                channel.markCancelled();
            }
            if (session) {
                session.close();
            }
        },
    });
    session = createProtocolSession(route.protocol, channel, route.proxyAddress);
    void pumpXHttpRequestBody(request.body, session, route.protocol);
    const headers = new Headers({
        'Cache-Control': 'no-store',
        'Content-Type': 'application/octet-stream',
        'X-Accel-Buffering': 'no',
    });
    return new Response(responseBody, {
        status: 200,
        headers,
    });
}

async function pumpXHttpRequestBody(body, session, protocol) {
    if (!body) {
        session.close();
        return;
    }
    const reader = body.getReader();
    try {
        while (!session.closed) {
            const { value, done } = await reader.read();
            if (done) {
                break;
            }
            if (!value || value.byteLength === 0) {
                continue;
            }
            await session.ingest(toU8Sync(value));
        }
    }
    catch (error) {
        console.error(`${protocol} XHTTP stream-one session error`, error?.stack || String(error));
    }
    finally {
        try {
            reader.releaseLock();
        }
        catch {
            // The stream may already be detached/cancelled.
        }
        session.close();
    }
}

class WebSocketSessionChannel {
    constructor(ws) {
        this.ws = ws;
    }
    sendBytes(bytes) {
        if (this.ws.readyState !== WS_OPEN) {
            throw new Error('WebSocket is not open');
        }
        this.ws.send(toU8Sync(bytes));
    }
    close() {
        safeCloseWebSocket(this.ws);
    }
}

class XHttpStreamChannel {
    constructor(controller) {
        this.controller = controller;
        this.closed = false;
    }
    sendBytes(bytes) {
        if (this.closed) {
            throw new Error('XHTTP response stream is closed');
        }
        this.controller.enqueue(toU8Sync(bytes).slice());
    }
    markCancelled() {
        this.closed = true;
    }
    close() {
        if (this.closed) {
            return;
        }
        this.closed = true;
        try {
            this.controller.close();
        }
        catch {

        }
    }
}

function normalizeSessionChannel(value) {
    if (value && typeof value.sendBytes === 'function' && typeof value.close === 'function') {
        return value;
    }
    return new WebSocketSessionChannel(value);
}

class BaseSession {
    constructor(transport, proxyAddress) {
        this.channel = normalizeSessionChannel(transport);
        this.ws = transport && typeof transport.send === 'function'
            ? transport
            : null;
        this.proxyAddress = proxyAddress || '';
        this.closed = false;
        this.tcp = null;
        this.relay = null;
        this.muxRouter = null;
    }
    send(bytes) {
        if (this.closed) {
            throw new Error('session is closed');
        }
        this.channel.sendBytes(bytes);
    }
    close() {
        if (this.closed) {
            return;
        }
        this.closed = true;
        try {
            this.tcp?.close();
        }
        catch {

        }
        try {
            this.relay?.close();
        }
        catch {

        }
        try {
            this.muxRouter?.close();
        }
        catch {

        }
        this.tcp = null;
        this.relay = null;
        this.muxRouter = null;
        this.channel.close();
    }
}

class VlessSession extends BaseSession {
    constructor(ws, proxyAddress) {
        super(ws, proxyAddress);
        this.pendingHeader = new Uint8Array(0);
        this.header = null;
    }
    async ingest(chunk) {
        if (this.closed || !chunk.byteLength) {
            return;
        }
        if (!this.header) {
            this.pendingHeader = concatBytes(this.pendingHeader, chunk);
            const parsed = tryParseVlessHeader(this.pendingHeader);
            if (!parsed) {
                if (this.pendingHeader.byteLength > CONFIG.MAX_PROTOCOL_HEADER) {
                    throw new Error('VLESS request header is too large or incomplete');
                }
                return;
            }
            if (!secureEqual(processVlessUUID(parsed.user), VLESS_USER_KEY)) {
                throw new Error('invalid VLESS UUID');
            }
            if (parsed.addonLength !== 0) {
                throw new Error('VLESS addons/flow are not supported on this endpoint');
            }
            if (parsed.command === CMD_RVS) {
                throw new Error('VLESS reverse command is not supported');
            }
            this.header = parsed;
            const remainder = this.pendingHeader.slice(parsed.headerLength);
            this.pendingHeader = new Uint8Array(0);
            await this.openOutbound();
            this.send(new Uint8Array([0, 0]));
            if (remainder.byteLength) {
                await this.writeOutbound(remainder);
            }
            return;
        }
        await this.writeOutbound(chunk);
    }
    async openOutbound() {
        const h = this.header;
        if (h.command === CMD_TCP) {
            this.tcp = new TcpBridge(this.proxyAddress, (data) => this.send(data), () => this.close());
            await this.tcp.open(h.address, h.port);
            return;
        }
        if (h.command === CMD_UDP) {
            const endpoint = { address: h.address, port: h.port, addressType: h.addressType };
            assertUdpEndpointAllowed(endpoint);
            if (isDnsEndpoint(endpoint)) {
                this.dns = new FixedDnsOverHttps((payload) => this.send(concatBytes(uint16be(payload.byteLength), payload)));
                return;
            }
            this.relay = await RelayConnection.openFixedUDP(endpoint);
            this.relay.pumpFixedUDP((payload) => this.send(concatBytes(uint16be(payload.byteLength), payload)), () => this.close());
            return;
        }
        if (h.command === CMD_MUX) {
            this.muxRouter = new WorkerMuxRouter(this.proxyAddress, (data) => this.send(data));
            return;
        }
        throw new Error(`unsupported VLESS command ${h.command}`);
    }
    async writeOutbound(bytes) {
        if (this.header.command === CMD_TCP) {
            return this.tcp.write(bytes);
        }
        if (this.header.command === CMD_MUX) {
            return this.muxRouter.ingest(bytes);
        }
        if (this.dns) {
            return this.dns.writeRaw(bytes);
        }
        return this.relay.writeRaw(bytes);
    }
}

class TrojanSession extends BaseSession {
    constructor(ws, proxyAddress) {
        super(ws, proxyAddress);
        this.pendingHeader = new Uint8Array(0);
        this.header = null;
        this.udpDecoder = null;
        this.mux = false;
    }
    async ingest(chunk) {
        if (this.closed || !chunk.byteLength) {
            return;
        }
        if (!this.header) {
            this.pendingHeader = concatBytes(this.pendingHeader, chunk);
            const parsed = tryParseTrojanHeader(this.pendingHeader, TROJAN_HASH);
            if (!parsed) {
                if (this.pendingHeader.byteLength > CONFIG.MAX_PROTOCOL_HEADER) {
                    throw new Error('Trojan request header is too large or incomplete');
                }
                return;
            }
            this.header = parsed;
            const remainder = this.pendingHeader.slice(parsed.headerLength);
            this.pendingHeader = new Uint8Array(0);
            await this.openOutbound();
            if (remainder.byteLength) {
                await this.writeOutbound(remainder);
            }
            return;
        }
        await this.writeOutbound(chunk);
    }
    async openOutbound() {
        const h = this.header;
        if (h.command === CMD_TCP && h.address.toLowerCase() === 'v1.mux.cool') {
            this.mux = true;
            this.muxRouter = new WorkerMuxRouter(this.proxyAddress, (data) => this.send(data));
            return;
        }
        if (h.command === CMD_TCP) {
            this.tcp = new TcpBridge(this.proxyAddress, (data) => this.send(data), () => this.close());
            await this.tcp.open(h.address, h.port);
            return;
        }
        this.udpDecoder = new TrojanUdpDecoder();
    }
    async ensurePacketRelay() {
        if (this.relay && !this.relay.closed) {
            return this.relay;
        }
        if (this.relayOpening) {
            return this.relayOpening;
        }
        this.relayOpening = (async () => {
            const relay = await RelayConnection.openPacketUDP();
            this.relay = relay;
            relay.pumpPacketUDP((endpoint, payload) => this.send(encodeTrojanUdpPacket(endpoint, payload)), () => {
                if (this.relay === relay) {
                    this.relay = null;
                }
            });
            return relay;
        })();
        try {
            return await this.relayOpening;
        }
        finally {
            this.relayOpening = null;
        }
    }
    async writeOutbound(bytes) {
        if (this.header.command === CMD_TCP) {
            if (this.mux) {
                return this.muxRouter.ingest(bytes);
            }
            return this.tcp.write(bytes);
        }
        for (const packet of this.udpDecoder.push(bytes)) {
            if (rejectUdpEndpoint(packet.endpoint)) {
                console.warn(`rejecting Trojan UDP/443 to ${packet.endpoint.address}:443`);
                continue;
            }
            if (isDnsEndpoint(packet.endpoint)) {
                const answer = await resolveDnsOverHttps(packet.payload);
                this.send(encodeTrojanUdpPacket(packet.endpoint, answer));
                continue;
            }
            const relay = await this.ensurePacketRelay();
            await relay.writePacket(packet.endpoint, packet.payload);
        }
    }
}

class ShadowsocksSession extends BaseSession {
    constructor(ws, proxyAddress) {
        super(ws, proxyAddress);
        this.spec = SS_SPEC;
        this.codec = this.spec.family === '2022'
            ? new Ss2022ServerCodec(this.spec.method, SS_2022_PSK_CANDIDATES, SS_REPLAY)
            : new SsLegacyServerCodec(this.spec.method, UUID_TEXT, SS_REPLAY);
        this.header = null;
        this.plainPending = new Uint8Array(0);
        this.mode = null;
        this.uotDecoder = null;
        this.uotRelayOpening = null;
    }
    sendEncrypted(bytes) {
        const encoded = this.codec.encode(bytes);
        if (encoded.byteLength) {
            this.send(encoded);
        }
    }
    async ingest(chunk) {
        if (this.closed || !chunk.byteLength) {
            return;
        }
        const units = this.codec.push(chunk);
        if (!this.header && this.spec.family === '2022' && this.codec.header) {
            this.header = this.codec.header;
            await this.openOutbound();
        }
        for (const plain of units) {
            await this.consumePlain(plain);
        }
    }
    async consumePlain(bytes) {
        if (!this.header) {
            this.plainPending = concatBytes(this.plainPending, bytes);
            const parsed = parseSsAddress(this.plainPending, 0, true);
            if (!parsed) {
                if (this.plainPending.byteLength > CONFIG.MAX_PROTOCOL_HEADER) {
                    throw new Error('Shadowsocks destination header is too large or incomplete');
                }
                return;
            }
            if (parsed.port === 0 && !isSsSpecialTarget(parsed.address)) {
                throw new Error('zero Shadowsocks destination port');
            }
            this.header = parsed;
            const remainder = this.plainPending.slice(parsed.next);
            this.plainPending = new Uint8Array(0);
            await this.openOutbound();
            if (remainder.byteLength) {
                await this.writePlain(remainder);
            }
            return;
        }
        await this.writePlain(bytes);
    }
    async openOutbound() {
        const host = String(this.header.address || '').toLowerCase();
        if (host === 'v1.mux.cool') {
            this.mode = 'mux';
            this.muxRouter = new WorkerMuxRouter(this.proxyAddress, (data) => this.sendEncrypted(data));
            return;
        }
        if (host === SS_UOT_V1 || host === SS_UOT_V2) {
            this.mode = host === SS_UOT_V2 ? 'uot2' : 'uot1';
            this.uotDecoder = this.mode === 'uot2' ? new UotV2Decoder() : new UotV1Decoder();
            return;
        }
        if (!this.header.port) {
            throw new Error('zero Shadowsocks TCP destination port');
        }
        this.mode = 'tcp';
        this.tcp = new TcpBridge(this.proxyAddress, (data) => this.sendEncrypted(data), () => this.close());
        await this.tcp.open(this.header.address, this.header.port);
    }
    async writePlain(bytes) {
        if (this.mode === 'tcp') {
            return this.tcp.write(bytes);
        }
        if (this.mode === 'mux') {
            return this.muxRouter.ingest(bytes);
        }
        if (this.mode === 'uot1') {
            for (const packet of this.uotDecoder.push(bytes)) {
                if (rejectUdpEndpoint(packet.endpoint)) {
                    console.warn(`rejecting Shadowsocks UoT UDP/443 to ${packet.endpoint.address}:443`);
                    continue;
                }
                if (isDnsEndpoint(packet.endpoint)) {
                    const answer = await resolveDnsOverHttps(packet.payload);
                    this.sendEncrypted(encodeUotV1Packet(packet.endpoint, answer));
                    continue;
                }
                const relay = await this.ensureUotPacketRelay();
                await relay.writePacket(packet.endpoint, packet.payload);
            }
            return;
        }
        if (this.mode === 'uot2') {
            const packets = this.uotDecoder.push(bytes);
            for (const packet of packets) {
                if (rejectUdpEndpoint(packet.endpoint)) {
                    console.warn(`rejecting Shadowsocks UoT v2 UDP/443 to ${packet.endpoint.address}:443`);
                    continue;
                }
                if (isDnsEndpoint(packet.endpoint)) {
                    const answer = await resolveDnsOverHttps(packet.payload);
                    if (this.uotDecoder.header.isConnect) {
                        this.sendEncrypted(encodeUotV2ConnectPacket(answer));
                    }
                    else {
                        this.sendEncrypted(encodeUotV1Packet(packet.endpoint, answer));
                    }
                    continue;
                }
                const relay = await this.ensureUotV2Relay();
                if (this.uotDecoder.header.isConnect) {
                    await relay.writeFixedPacket(packet.payload);
                }
                else {
                    await relay.writePacket(packet.endpoint, packet.payload);
                }
            }
            return;
        }
        throw new Error('Shadowsocks outbound mode is not initialized');
    }
    async ensureUotPacketRelay() {
        if (this.relay && !this.relay.closed) {
            return this.relay;
        }
        if (this.uotRelayOpening) {
            return this.uotRelayOpening;
        }
        this.uotRelayOpening = (async () => {
            const relay = await RelayConnection.openPacketUDP();
            this.relay = relay;
            relay.pumpPacketUDP((endpoint, payload) => this.sendEncrypted(encodeUotV1Packet(endpoint, payload)), () => this.close());
            return relay;
        })();
        try {
            return await this.uotRelayOpening;
        }
        finally {
            this.uotRelayOpening = null;
        }
    }
    async ensureUotV2Relay() {
        if (this.relay && !this.relay.closed) {
            return this.relay;
        }
        if (this.uotRelayOpening) {
            return this.uotRelayOpening;
        }
        const h = this.uotDecoder.header;
        if (!h) {
            throw new Error('Shadowsocks UoT v2 request header is incomplete');
        }
        if (rejectUdpEndpoint(h.endpoint)) {
            throw new Error('UDP/443 is rejected for Shadowsocks UoT v2');
        }
        this.uotRelayOpening = (async () => {
            let relay;
            if (h.isConnect) {
                relay = await RelayConnection.openFixedUDP(h.endpoint);
                relay.pumpFixedUDP((payload) => this.sendEncrypted(encodeUotV2ConnectPacket(payload)), () => this.close());
            }
            else {
                relay = await RelayConnection.openPacketUDP();
                relay.pumpPacketUDP((endpoint, payload) => this.sendEncrypted(encodeUotV1Packet(endpoint, payload)), () => this.close());
            }
            this.relay = relay;
            return relay;
        })();
        try {
            return await this.uotRelayOpening;
        }
        finally {
            this.uotRelayOpening = null;
        }
    }
}

function isSsSpecialTarget(address) {
    const host = String(address || '').toLowerCase();
    return host === 'v1.mux.cool' || host === SS_UOT_V1 || host === SS_UOT_V2;
}

class VmessSession extends BaseSession {
    constructor(ws, proxyAddress) {
        super(ws, proxyAddress);
        this.pendingHeader = new Uint8Array(0);
        this.header = null;
        this.decoder = null;
        this.encoder = null;
    }
    async ingest(chunk) {
        if (this.closed || !chunk.byteLength) {
            return;
        }
        if (!this.header) {
            this.pendingHeader = concatBytes(this.pendingHeader, chunk);
            const parsed = tryParseVmessHeader(this.pendingHeader, UUID_BYTES, VMESS_REPLAY);
            if (!parsed) {
                if (this.pendingHeader.byteLength > CONFIG.MAX_PROTOCOL_HEADER) {
                    throw new Error('VMess request header is too large or incomplete');
                }
                return;
            }
            this.header = parsed;
            const remainder = this.pendingHeader.slice(parsed.headerLength);
            this.pendingHeader = new Uint8Array(0);
            this.decoder = new VmessBodyDecoder(parsed);
            this.encoder = new VmessBodyEncoder(parsed);
            await this.openOutbound();
            this.send(encodeVmessResponseHeader(parsed));
            if (remainder.byteLength) {
                await this.consumeBody(remainder, true);
            }
            return;
        }
        await this.consumeBody(chunk, true);
    }
    async openOutbound() {
        const h = this.header;
        const onPlain = (data) => {
            const encoded = this.encoder.encode(data);
            if (encoded.byteLength) {
                this.send(encoded);
            }
        };
        if (h.command === CMD_TCP) {
            this.tcp = new TcpBridge(this.proxyAddress, onPlain, () => this.close());
            await this.tcp.open(h.address, h.port);
            return;
        }
        if (h.command === CMD_UDP) {
            const endpoint = { address: h.address, port: h.port, addressType: h.addressType };
            assertUdpEndpointAllowed(endpoint);
            if (isDnsEndpoint(endpoint)) {
                this.dnsPacket = async (payload) => onPlain(await resolveDnsOverHttps(payload));
                return;
            }
            this.relay = await RelayConnection.openFixedUDP(endpoint);
            this.relay.pumpFixedUDP((payload) => onPlain(payload), () => this.close());
            return;
        }
        if (h.command === CMD_MUX) {
            this.muxRouter = new WorkerMuxRouter(this.proxyAddress, onPlain);
            return;
        }
        throw new Error(`unsupported VMess command ${h.command}`);
    }
    async consumeBody(bytes, messageBoundary) {
        const units = this.decoder.push(bytes, messageBoundary);
        for (const plain of units) {
            if (this.header.command === CMD_TCP) {
                await this.tcp.write(plain);
            }
            else if (this.header.command === CMD_UDP) {
                if (this.dnsPacket) {
                    await this.dnsPacket(plain);
                }
                else {
                    await this.relay.writeFixedPacket(plain);
                }
            }
            else {
                await this.muxRouter.ingest(plain);
            }
        }
    }
}

class WorkerMuxRouter {
    constructor(proxyAddress, onOutput) {
        this.proxyAddress = proxyAddress || '';
        this.onOutput = onOutput;
        this.decoder = new MuxFrameDecoder();
        this.relayDecoder = new MuxFrameDecoder();
        this.sessions = new Map();
        this.relay = null;
        this.relayOpening = null;
        this.closed = false;
    }
    emit(bytes) {
        if (this.closed) {
            return;
        }
        this.onOutput(toU8Sync(bytes));
    }
    async ingest(bytes) {
        if (this.closed) {
            throw new Error('Mux.Cool router is closed');
        }
        for (const frame of this.decoder.push(bytes)) {
            await this.handleFrame(frame);
        }
    }
    async handleFrame(frame) {
        if (frame.status === MUX_STATUS_KEEPALIVE) {
            return;
        }
        if (frame.status === MUX_STATUS_NEW) {
            return this.handleNew(frame);
        }
        if (frame.status === MUX_STATUS_KEEP) {
            return this.handleKeep(frame);
        }
        if (frame.status === MUX_STATUS_END) {
            return this.handleEnd(frame);
        }
        throw new Error(`unsupported Mux.Cool status ${frame.status}`);
    }
    async handleNew(frame) {
        if (frame.network === MUX_NETWORK_TCP) {
            return this.openTcp(frame);
        }
        if (frame.network === MUX_NETWORK_UDP) {
            return this.openUdp(frame);
        }
        this.emit(encodeMuxEnd(frame.id, true));
    }
    async closeExisting(id, nextNetwork = 0) {
        const existing = this.sessions.get(id);
        if (!existing) {
            return;
        }
        this.sessions.delete(id);
        if (existing.network === MUX_NETWORK_TCP) {
            existing.tcp.close();
            return;
        }
        if (existing.network === MUX_NETWORK_UDP && nextNetwork === MUX_NETWORK_TCP && this.relay && !this.relay.closed) {
            try {
                await this.relay.writeRaw(encodeMuxEnd(id, false));
            }
            catch { }
        }
    }
    async openTcp(frame) {
        if (!frame.target?.address || !frame.target?.port) {
            this.emit(encodeMuxEnd(frame.id, true));
            return;
        }
        await this.closeExisting(frame.id, MUX_NETWORK_TCP);
        const tcp = new TcpBridge(this.proxyAddress, (data) => this.sendTcpData(frame.id, data), () => this.handleTcpRemoteClose(frame.id, tcp));
        this.sessions.set(frame.id, { network: MUX_NETWORK_TCP, tcp });
        try {
            await tcp.open(frame.target.address, frame.target.port);
            if (frame.data.byteLength) {
                await tcp.write(frame.data);
            }
        }
        catch (error) {
            if (this.sessions.get(frame.id)?.tcp === tcp) {
                this.sessions.delete(frame.id);
            }
            tcp.close();
            console.error(`Mux.Cool TCP ${frame.target.address}:${frame.target.port} failed`, error?.stack || String(error));
            this.emit(encodeMuxEnd(frame.id, true));
        }
    }
    async openUdp(frame) {
        await this.closeExisting(frame.id, MUX_NETWORK_UDP);
        if (rejectUdpEndpoint(frame.target)) {
            console.warn(`rejecting Mux.Cool UDP/443 session ${frame.id} to ${frame.target?.address || '?'}:443`);
            this.emit(encodeMuxEnd(frame.id, true));
            return;
        }
        if (isDnsEndpoint(frame.target)) {
            this.sessions.set(frame.id, { network: MUX_NETWORK_UDP, localDns: true, target: frame.target });
            if (frame.data.byteLength) {
                try {
                    const answer = await resolveDnsOverHttps(frame.data);
                    this.emit(encodeMuxUdpData(frame.id, frame.target, answer));
                }
                catch (error) {
                    this.sessions.delete(frame.id);
                    console.error('Mux.Cool DNS-over-HTTPS failed', error?.stack || String(error));
                    this.emit(encodeMuxEnd(frame.id, true));
                }
            }
            return;
        }
        try {
            const relay = await this.ensureUdpRelay();
            this.sessions.set(frame.id, { network: MUX_NETWORK_UDP, localDns: false });
            await relay.writeRaw(frame.raw);
        }
        catch (error) {
            this.sessions.delete(frame.id);
            console.error('Mux.Cool UDP relay open/write failed', error?.stack || String(error));
            this.emit(encodeMuxEnd(frame.id, true));
        }
    }
    async handleKeep(frame) {
        const session = this.sessions.get(frame.id);
        if (!session) {
            this.emit(encodeMuxEnd(frame.id, false));
            return;
        }
        if (session.network === MUX_NETWORK_TCP) {
            if (frame.network === MUX_NETWORK_UDP) {
                session.tcp.close();
                this.sessions.delete(frame.id);
                this.emit(encodeMuxEnd(frame.id, true));
                return;
            }
            if (!frame.data.byteLength) {
                return;
            }
            try {
                await session.tcp.write(frame.data);
            }
            catch (error) {
                session.tcp.close();
                this.sessions.delete(frame.id);
                this.emit(encodeMuxEnd(frame.id, true));
            }
            return;
        }
        if (frame.network === MUX_NETWORK_UDP && rejectUdpEndpoint(frame.target)) {
            console.warn(`rejecting Mux.Cool UDP/443 packet on session ${frame.id}`);
            this.sessions.delete(frame.id);
            if (this.relay && !this.relay.closed) {
                try {
                    await this.relay.writeRaw(encodeMuxEnd(frame.id, false));
                }
                catch { }
            }
            this.emit(encodeMuxEnd(frame.id, true));
            return;
        }
        const target = frame.target || session.target || null;
        if (session.localDns) {
            if (!isDnsEndpoint(target)) {
                this.sessions.delete(frame.id);
                this.emit(encodeMuxEnd(frame.id, true));
                return;
            }
            session.target = target;
            if (!frame.data.byteLength) {
                return;
            }
            try {
                const answer = await resolveDnsOverHttps(frame.data);
                this.emit(encodeMuxUdpData(frame.id, target, answer));
            }
            catch (error) {
                this.sessions.delete(frame.id);
                console.error('Mux.Cool DNS-over-HTTPS failed', error?.stack || String(error));
                this.emit(encodeMuxEnd(frame.id, true));
            }
            return;
        }
        if (frame.network === MUX_NETWORK_UDP && isDnsEndpoint(frame.target)) {
            if (!frame.data.byteLength) {
                return;
            }
            try {
                const answer = await resolveDnsOverHttps(frame.data);
                this.emit(encodeMuxUdpData(frame.id, frame.target, answer));
            }
            catch (error) {
                console.error('Mux.Cool DNS-over-HTTPS failed', error?.stack || String(error));
            }
            return;
        }
        try {
            const relay = await this.ensureUdpRelay();
            await relay.writeRaw(frame.raw);
        }
        catch (error) {
            this.sessions.delete(frame.id);
            this.emit(encodeMuxEnd(frame.id, true));
        }
    }
    async handleEnd(frame) {
        const session = this.sessions.get(frame.id);
        if (!session) {
            return;
        }
        this.sessions.delete(frame.id);
        if (session.network === MUX_NETWORK_TCP) {
            if (frame.data.byteLength) {
                try {
                    await session.tcp.write(frame.data);
                }
                catch { }
            }
            session.tcp.close();
            return;
        }
        if (this.relay && !this.relay.closed) {
            try {
                await this.relay.writeRaw(frame.raw);
            }
            catch { }
        }
    }
    sendTcpData(id, bytes) {
        if (this.closed || this.sessions.get(id)?.network !== MUX_NETWORK_TCP) {
            return;
        }
        const data = toU8Sync(bytes);
        for (let offset = 0; offset < data.byteLength; offset += MAX_MUX_DATA_LEN) {
            this.emit(encodeMuxTcpData(id, data.subarray(offset, Math.min(data.byteLength, offset + MAX_MUX_DATA_LEN))));
        }
    }
    handleTcpRemoteClose(id, tcp) {
        if (this.closed) {
            return;
        }
        const session = this.sessions.get(id);
        if (!session || session.network !== MUX_NETWORK_TCP || session.tcp !== tcp) {
            return;
        }
        this.sessions.delete(id);
        this.emit(encodeMuxEnd(id, false));
    }
    async ensureUdpRelay() {
        if (this.closed) {
            throw new Error('Mux.Cool router is closed');
        }
        if (this.relay && !this.relay.closed) {
            return this.relay;
        }
        if (this.relayOpening) {
            return this.relayOpening;
        }
        this.relayOpening = (async () => {
            const relay = await RelayConnection.openMux();
            if (this.closed) {
                relay.close();
                throw new Error('Mux.Cool router closed while opening UDP relay');
            }
            this.relay = relay;
            relay.pumpRaw((data) => this.handleUdpRelayData(data), () => this.handleUdpRelayClose(relay));
            return relay;
        })();
        try {
            return await this.relayOpening;
        }
        finally {
            this.relayOpening = null;
        }
    }
    handleUdpRelayData(data) {
        try {
            for (const frame of this.relayDecoder.push(data)) {
                if (frame.status === MUX_STATUS_END && this.sessions.get(frame.id)?.network === MUX_NETWORK_UDP) {
                    this.sessions.delete(frame.id);
                }
            }
        }
        catch (error) {
            console.error('invalid Mux.Cool response from UDP relay', error?.stack || String(error));
            try {
                this.relay?.close();
            }
            catch { }
            return;
        }
        this.emit(data);
    }
    handleUdpRelayClose(relay) {
        if (this.relay !== relay) {
            return;
        }
        this.relay = null;
        if (this.closed) {
            return;
        }
        for (const [id, session] of [...this.sessions]) {
            if (session.network !== MUX_NETWORK_UDP) {
                continue;
            }
            this.sessions.delete(id);
            this.emit(encodeMuxEnd(id, true));
        }
    }
    close() {
        if (this.closed) {
            return;
        }
        this.closed = true;
        for (const session of this.sessions.values()) {
            if (session.network === MUX_NETWORK_TCP) {
                session.tcp.close();
            }
        }
        this.sessions.clear();
        try {
            this.relay?.close();
        }
        catch { }
        this.relay = null;
    }
}

class TcpBridge {
    constructor(proxyAddress, onData, onClose) {
        this.proxyAddress = proxyAddress || '';
        this.onData = onData;
        this.onClose = onClose;
        this.socket = null;
        this.writer = null;
        this.mode = null;
        this.received = false;
        this.replay = [];
        this.replayBytes = 0;
        this.fallbackPromise = null;
        this.closed = false;
    }
    async open(address, port) {
        try {
            await this.openSocket(address, port, 'primary');
        }
        catch (error) {
            if (!this.proxyAddress) {
                throw error;
            }
            const target = parseProxyAddress(this.proxyAddress);
            this.mode = 'switching';
            await this.openSocket(target.hostname, target.port, 'fallback');
        }
    }
    async openSocket(address, port, mode) {
        const socket = connect({ hostname: address, port }, { allowHalfOpen: true, secureTransport: 'off' });
        try {
            await socket.opened;
        }
        catch (error) {
            try {
                socket.close();
            }
            catch { }
            throw error;
        }
        this.socket = socket;
        this.writer = socket.writable.getWriter();
        this.mode = mode;
        void this.pump(socket, mode);
    }
    bufferReplay(bytes) {
        if (!this.proxyAddress || this.mode !== 'primary' || this.received) {
            return false;
        }
        if (this.replayBytes + bytes.byteLength > CONFIG.MAX_TCP_PROXY_REPLAY) {
            throw new Error('TCP proxy replay buffer limit exceeded');
        }
        this.replay.push(bytes.slice());
        this.replayBytes += bytes.byteLength;
        return true;
    }
    clearReplay() { this.replay = []; this.replayBytes = 0; }
    async fallback() {
        if (!this.proxyAddress) {
            throw new Error('TCP proxy fallback is not configured');
        }
        if (this.mode === 'fallback') {
            return;
        }
        if (this.fallbackPromise) {
            return this.fallbackPromise;
        }
        this.fallbackPromise = (async () => {
            const target = parseProxyAddress(this.proxyAddress);
            const replay = this.replayBytes ? concatBytes(...this.replay) : null;
            this.clearReplay();
            const oldWriter = this.writer;
            const oldSocket = this.socket;
            this.writer = null;
            this.socket = null;
            this.mode = 'switching';
            try {
                oldWriter?.releaseLock();
            }
            catch { }
            try {
                oldSocket?.close();
            }
            catch { }
            await this.openSocket(target.hostname, target.port, 'fallback');
            if (replay?.byteLength) {
                await this.writer.write(replay);
            }
        })();
        try {
            await this.fallbackPromise;
        }
        finally {
            this.fallbackPromise = null;
        }
    }
    async write(bytes) {
        if (this.closed) {
            throw new Error('TCP bridge is closed');
        }
        const b = toU8Sync(bytes);
        const buffered = this.bufferReplay(b);
        if (this.fallbackPromise) {
            await this.fallbackPromise;
            if (buffered) {
                return;
            }
        }
        if (!this.writer) {
            throw new Error('TCP writer unavailable');
        }
        try {
            await this.writer.write(b);
        }
        catch (error) {
            if (buffered && this.proxyAddress && this.mode !== 'fallback' && !this.received) {
                await this.fallback();
                return;
            }
            throw error;
        }
    }
    async pump(socket, mode) {
        const reader = socket.readable.getReader();
        let gotData = false;
        try {
            while (!this.closed && this.socket === socket) {
                const { value, done } = await reader.read();
                if (done) {
                    break;
                }
                if (!value?.byteLength) {
                    continue;
                }
                gotData = true;
                if (mode === 'primary') {
                    this.received = true;
                    this.clearReplay();
                }
                this.onData(toU8Sync(value));
            }
        }
        catch (error) {
            if (!this.closed && this.socket === socket) {
                console.error(`${mode} TCP read error`, error?.stack || String(error));
            }
        }
        finally {
            try {
                reader.releaseLock();
            }
            catch { }
        }
        if (this.closed || this.socket !== socket) {
            return;
        }
        if (mode === 'primary' && !gotData && this.proxyAddress) {
            try {
                await this.fallback();
                return;
            }
            catch (error) {
                console.error('TCP fallback failed', error?.stack || String(error));
            }
        }
        this.close();
        this.onClose();
    }
    close() {
        if (this.closed) {
            return;
        }
        this.closed = true;
        try {
            this.writer?.releaseLock();
        }
        catch { }
        try {
            this.socket?.close();
        }
        catch { }
        this.writer = null;
        this.socket = null;
    }
}


function normalizeUdpRelayConfig(value) {
    const cfg = value && typeof value === 'object' ? value : {};
    const host = String(cfg.host || '').trim();
    const port = Number(cfg.port);
    const hostConfigured = Boolean(host && host !== 'CHANGE_ME_TO_VPS_IP');
    const portConfigured = Number.isInteger(port) && port >= 1 && port <= 65535;
    if (hostConfigured && portConfigured) {
        return { transport: 'tcp', host, port };
    }
    const websocket = String(cfg.websocket || '').trim();
    if (websocket) {
        let url;
        try {
            url = new URL(websocket);
        }
        catch {
            throw new Error('CONFIG.UDP_RELAY.websocket must be a valid ws:// or wss:// URL');
        }
        if (url.protocol !== 'ws:' && url.protocol !== 'wss:') {
            throw new Error('CONFIG.UDP_RELAY.websocket must use ws:// or wss://');
        }
        return { transport: 'websocket', websocket: url.toString() };
    }
    if (hostConfigured || portConfigured) {
        throw new Error('CONFIG.UDP_RELAY host and port must both be valid');
    }
    throw new Error('set CONFIG.UDP_RELAY to { host, port } or { websocket: "wss://..." } before using UDP/XUDP');
}

async function openWebSocketRelay(url) {
    const relayUrl = new URL(url);
    relayUrl.protocol = relayUrl.protocol === 'wss:' ? 'https:' : 'http:';
    const response = await fetch(relayUrl, {
        headers: {
            Upgrade: 'websocket',
        },
    });
    const ws = response.webSocket;
    if (response.status !== 101 || !ws) {
        throw new Error(`UDP relay WebSocket upgrade failed (HTTP ${response.status})`);
    }
    try {
        ws.binaryType = 'arraybuffer';
    }
    catch { }
    ws.accept({ allowHalfOpen: true });
    let ended = false;
    let messageChain = Promise.resolve();
    const readable = new ReadableStream({
        start(c) {
            ws.addEventListener('message', (event) => {
                messageChain = messageChain.then(async () => {
                    if (ended) return;
                    const bytes = await toUint8Array(event.data);
                    if (bytes.byteLength) c.enqueue(bytes);
                }).catch((error) => {
                    if (ended) return;
                    ended = true;
                    try { c.error(error); } catch { }
                    safeCloseWebSocket(ws);
                });
            });
            ws.addEventListener('close', () => {
                messageChain.finally(() => {
                    if (ended) return;
                    ended = true;
                    try { c.close(); } catch { }
                });
            });
            ws.addEventListener('error', (event) => {
                messageChain.finally(() => {
                    if (ended) return;
                    ended = true;
                    try { c.error(new Error(`UDP relay WebSocket error${event?.message ? `: ${event.message}` : ''}`)); } catch { }
                });
            });
        },
        cancel() {
            ended = true;
            safeCloseWebSocket(ws);
        },
    });
    const writable = new WritableStream({
        write(chunk) {
            if (ws.readyState !== WS_OPEN) {
                throw new Error('UDP relay WebSocket is not open');
            }
            ws.send(toU8Sync(chunk));
        },
        close() {
            safeCloseWebSocket(ws);
        },
        abort() {
            safeCloseWebSocket(ws);
        },
    });
    return {
        socket: ws,
        writer: writable.getWriter(),
        reader: new BufferedStreamReader(readable.getReader()),
    };
}

class RelayConnection {
    constructor(socket, writer, reader, mode) {
        this.socket = socket;
        this.writer = writer;
        this.reader = reader;
        this.mode = mode;
        this.closed = false;
        this.writeChain = Promise.resolve();
    }
    static async open(mode, endpoint = null) {
        const relay = normalizeUdpRelayConfig(CONFIG.UDP_RELAY);
        let socket;
        let writer;
        let reader;
        if (relay.transport === 'tcp') {
            socket = connect({ hostname: relay.host, port: relay.port }, { allowHalfOpen: true, secureTransport: 'off' });
            await socket.opened;
            writer = socket.writable.getWriter();
            reader = new BufferedStreamReader(socket.readable.getReader());
        }
        else {
            ({ socket, writer, reader } = await openWebSocketRelay(relay.websocket));
        }
        const parts = [RELAY_MAGIC, new Uint8Array([mode])];
        if (mode === RELAY_MODE_FIXED_UDP) {
            parts.push(encodeRelayEndpoint(endpoint));
        }
        await writer.write(concatBytes(...parts));
        const status = await readRelayStatus(reader);
        if (!status.ok) {
            try {
                writer.releaseLock();
            }
            catch { }
            try {
                reader.releaseLock();
            }
            catch { }
            try {
                socket.close();
            }
            catch { }
            throw new Error(`UDP relay rejected connection: ${status.message}`);
        }
        return new RelayConnection(socket, writer, reader, mode);
    }
    static openFixedUDP(endpoint) { return RelayConnection.open(RELAY_MODE_FIXED_UDP, endpoint); }
    static openMux() { return RelayConnection.open(RELAY_MODE_MUX); }
    static openPacketUDP() { return RelayConnection.open(RELAY_MODE_PACKET_UDP); }
    queueWrite(data) {
        const bytes = toU8Sync(data).slice();
        const op = this.writeChain.then(() => {
            if (this.closed || !this.writer) {
                throw new Error('relay is closed');
            }
            return this.writer.write(bytes);
        });
        this.writeChain = op.catch(() => { });
        return op;
    }
    writeRaw(bytes) { return this.queueWrite(bytes); }
    writeFixedPacket(payload) { return this.queueWrite(concatBytes(uint16be(payload.byteLength), payload)); }
    writePacket(endpoint, payload) { return this.queueWrite(concatBytes(encodeRelayEndpoint(endpoint), uint16be(payload.byteLength), payload)); }
    pumpRaw(onData, onClose) {
        void (async () => {
            try {
                for (;;) {
                    const { value, done } = await this.reader.read();
                    if (done) {
                        break;
                    }
                    if (value?.byteLength) {
                        onData(toU8Sync(value));
                    }
                }
            }
            catch (error) {
                if (!this.closed) {
                    console.error('relay raw read error', error?.stack || String(error));
                }
            }
            finally {
                this.close();
                onClose();
            }
        })();
    }
    pumpFixedUDP(onPacket, onClose) {
        void (async () => {
            try {
                for (;;) {
                    const len = await this.reader.readUint16();
                    const payload = len ? await this.reader.readExactly(len) : new Uint8Array(0);
                    if (payload.byteLength) {
                        onPacket(payload);
                    }
                }
            }
            catch (error) {
                if (!this.closed && !isEof(error)) {
                    console.error('relay UDP read error', error?.stack || String(error));
                }
            }
            finally {
                this.close();
                onClose();
            }
        })();
    }
    pumpPacketUDP(onPacket, onClose) {
        void (async () => {
            try {
                for (;;) {
                    const endpoint = await readRelayEndpoint(this.reader);
                    const len = await this.reader.readUint16();
                    const payload = len ? await this.reader.readExactly(len) : new Uint8Array(0);
                    if (payload.byteLength) {
                        onPacket(endpoint, payload);
                    }
                }
            }
            catch (error) {
                if (!this.closed && !isEof(error)) {
                    console.error('relay packet UDP read error', error?.stack || String(error));
                }
            }
            finally {
                this.close();
                onClose();
            }
        })();
    }
    close() {
        if (this.closed) {
            return;
        }
        this.closed = true;
        try {
            this.writer?.releaseLock();
        }
        catch { }
        try {
            this.reader?.releaseLock();
        }
        catch { }
        try {
            this.socket?.close();
        }
        catch { }
        this.writer = null;
    }
}

class BufferedStreamReader {
    constructor(reader) { this.reader = reader; this.pending = new Uint8Array(0); }
    async readExactly(length) {
        const out = new Uint8Array(length);
        let off = 0;
        while (off < length) {
            if (!this.pending.byteLength) {
                const { value, done } = await this.reader.read();
                if (done) {
                    throw new Error('unexpected EOF');
                }
                if (!value?.byteLength) {
                    continue;
                }
                this.pending = toU8Sync(value);
            }
            const n = Math.min(this.pending.byteLength, length - off);
            out.set(this.pending.subarray(0, n), off);
            off += n;
            this.pending = this.pending.slice(n);
        }
        return out;
    }
    async readUint16() { const b = await this.readExactly(2); return (b[0] << 8) | b[1]; }
    async read() {
        if (this.pending.byteLength) {
            const value = this.pending;
            this.pending = new Uint8Array(0);
            return { value, done: false };
        }
        return this.reader.read();
    }
    releaseLock() { this.reader.releaseLock(); }
}

async function readRelayStatus(reader) {
    const status = (await reader.readExactly(1))[0];
    if (status === 0) {
        return { ok: true, message: '' };
    }
    const len = await reader.readUint16();
    const body = len ? await reader.readExactly(len) : new Uint8Array(0);
    return { ok: false, message: body.byteLength ? new TextDecoder().decode(body) : 'relay error' };
}

async function readRelayEndpoint(reader) {
    const head = await reader.readExactly(3);
    const port = (head[0] << 8) | head[1];
    const type = head[2];
    if (!port) {
        throw new Error('zero relay endpoint port');
    }
    if (type === ATYP_IPV4) {
        const b = await reader.readExactly(4);
        return { address: Array.from(b).join('.'), port, addressType: ATYP_IPV4 };
    }
    if (type === ATYP_DOMAIN) {
        const len = (await reader.readExactly(1))[0];
        if (!len) {
            throw new Error('empty relay endpoint domain');
        }
        const b = await reader.readExactly(len);
        return { address: new TextDecoder('utf-8', { fatal: true }).decode(b), port, addressType: ATYP_DOMAIN };
    }
    if (type === ATYP_IPV6) {
        const b = await reader.readExactly(16);
        const words = [];
        for (let i = 0; i < 16; i += 2) {
            words.push(((b[i] << 8) | b[i + 1]).toString(16));
        }
        return { address: words.join(':'), port, addressType: ATYP_IPV6 };
    }
    throw new Error(`invalid relay endpoint type ${type}`);
}

function parseEarlyDataLimit(url) {
    const raw = url?.searchParams?.get('ed');
    if (raw === null || raw === '') {
        return 0;
    }
    const n = Number(raw);
    return Number.isInteger(n) && n > 0 && n <= 8192 ? n : 0;
}

function decodeEarlyData(header, maxBytes = 8192) {
    if (!header || !Number.isInteger(maxBytes) || maxBytes <= 0) {
        return null;
    }
    try {
        let token = header.trim();
        if (token.includes(',')) {
            token = token.split(',')[0].trim();
        }
        if (!/^[A-Za-z0-9_-]+={0,2}$/.test(token)) {
            return null;
        }
        token = token.replace(/-/g, '+').replace(/_/g, '/');
        const rem = token.length % 4;
        if (rem) {
            token += '='.repeat(4 - rem);
        }
        const decoded = atob(token);
        if (!decoded || decoded.length > maxBytes) {
            return null;
        }
        return Uint8Array.from(decoded, (c) => c.charCodeAt(0));
    }
    catch {
        return null;
    }
}

async function toUint8Array(value) {
    if (value instanceof Uint8Array) {
        return value;
    }
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    if (typeof Blob !== 'undefined' && value instanceof Blob) {
        return new Uint8Array(await value.arrayBuffer());
    }
    if (typeof value === 'string') {
        throw new TypeError('text WebSocket frames are not supported');
    }
    throw new TypeError(`unsupported WebSocket message type: ${value?.constructor?.name || typeof value}`);
}

function uint16be(value) {
    if (!Number.isInteger(value) || value < 0 || value > 65535) {
        throw new Error(`invalid uint16 ${value}`);
    }
    return new Uint8Array([value >>> 8, value & 0xff]);
}

function isEof(error) { return String(error?.message || error).toLowerCase().includes('eof'); }
function safeCloseWebSocket(ws) {
    try {
        if (ws.readyState === WS_OPEN || ws.readyState === WS_CLOSING) {
            ws.close();
        }
    }
    catch { }
}