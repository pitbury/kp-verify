/*
 * kp-verify.js — independent JavaScript implementation of the KP-PROOF-1
 * verifier. Runs in a browser with no server, no network and no dependencies,
 * and in Node for testing.
 *
 * This is deliberately a SECOND implementation. The Python verifier in this
 * repository and this file were written against the specification in SPEC.md,
 * not against each other. Two independent implementations agreeing on the same
 * certificates is a stronger statement about a format than either one alone.
 *
 * Arithmetic uses native BigInt. Elliptic curve operations use homogeneous
 * projective coordinates so that no modular inverse is needed per operation,
 * which is what makes 4096-bit certificates practical in a browser.
 *
 * Copyright (c) 2026 RECHECK Piotr Burylo. MIT License.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.KPVerify = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const ZERO = 0n, ONE = 1n, TWO = 2n;
  const BPSW_DETERMINISTIC_LIMIT = ONE << 64n;

  /* ------------------------------ integer helpers ------------------------ */

  function mod(a, n) { const r = a % n; return r < ZERO ? r + n : r; }

  function powMod(base, exp, m) {
    base = mod(base, m);
    let result = ONE;
    while (exp > ZERO) {
      if (exp & ONE) result = (result * base) % m;
      base = (base * base) % m;
      exp >>= ONE;
    }
    return result;
  }

  function gcd(a, b) {
    a = a < ZERO ? -a : a; b = b < ZERO ? -b : b;
    while (b) { const t = a % b; a = b; b = t; }
    return a;
  }

  function isqrt(n) {
    if (n < ZERO) throw new Error("isqrt of negative");
    if (n < TWO) return n;
    let x = ONE << BigInt(((n.toString(2).length + 1) >> 1) + 1);
    let y = (x + n / x) >> ONE;
    while (y < x) { x = y; y = (x + n / x) >> ONE; }
    return x;
  }

  const SMALL_PRIMES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n];

  /* Miller-Rabin. With the first twelve prime bases the test is deterministic
     below 3.3 * 10^24, which covers every use here (final q < 2^64, and the
     factors of F in a Pocklington tail). Extra random bases are used above. */
  function isPrime(n, extraRounds) {
    if (n < TWO) return false;
    for (const p of SMALL_PRIMES) {
      if (n === p) return true;
      if (n % p === ZERO) return false;
    }
    let d = n - ONE, r = 0;
    while ((d & ONE) === ZERO) { d >>= ONE; r++; }
    const witness = (a) => {
      let x = powMod(a, d, n);
      if (x === ONE || x === n - ONE) return true;
      for (let i = 1; i < r; i++) {
        x = (x * x) % n;
        if (x === n - ONE) return true;
      }
      return false;
    };
    for (const a of SMALL_PRIMES) if (!witness(a)) return false;
    const rounds = extraRounds || 0;
    for (let i = 0; i < rounds; i++) {
      const a = TWO + BigInt(Math.floor(Math.random() * 1e15)) % (n - 4n);
      if (!witness(a)) return false;
    }
    return true;
  }

  /* ------------------- elliptic curve, projective (X:Y:Z) ----------------- */
  /* Curve Y^2 Z = X^3 + a X Z^2 + b Z^3 over Z/N. Infinity is Z == 0.        */

  function ecDouble(P, a, N) {
    const [X, Y, Z] = P;
    if (Y === ZERO || Z === ZERO) return [ZERO, ONE, ZERO];
    const W = mod(a * Z * Z + 3n * X * X, N);
    const S = mod(Y * Z, N);
    const B = mod(X * Y * S, N);
    const H = mod(W * W - 8n * B, N);
    const X3 = mod(2n * H * S, N);
    const Y3 = mod(W * (4n * B - H) - 8n * Y * Y * S * S, N);
    const Z3 = mod(8n * S * S * S, N);
    return [X3, Y3, Z3];
  }

  function ecAdd(P, Q, a, N) {
    if (P[2] === ZERO) return Q;
    if (Q[2] === ZERO) return P;
    const [X1, Y1, Z1] = P, [X2, Y2, Z2] = Q;
    const U1 = mod(Y2 * Z1, N), U2 = mod(Y1 * Z2, N);
    const V1 = mod(X2 * Z1, N), V2 = mod(X1 * Z2, N);
    if (V1 === V2) {
      if (U1 !== U2) return [ZERO, ONE, ZERO];
      return ecDouble(P, a, N);
    }
    const V = mod(V1 - V2, N);
    const U = mod(U1 - U2, N);
    const W = mod(Z1 * Z2, N);
    const V2sq = mod(V * V, N);
    const V3 = mod(V2sq * V, N);
    const A = mod(U * U * W - V3 - 2n * V2sq * V2, N);
    const X3 = mod(V * A, N);
    const Y3 = mod(U * (V2sq * V2 - A) - V3 * U2, N);
    const Z3 = mod(V3 * W, N);
    return [X3, Y3, Z3];
  }

  function ecMul(k, P, a, N) {
    let R = [ZERO, ONE, ZERO];
    let Q = P;
    while (k > ZERO) {
      if (k & ONE) R = ecAdd(R, Q, a, N);
      Q = ecDouble(Q, a, N);
      k >>= ONE;
    }
    return R;
  }

  function pointOnCurve(x, y, a, b, N) {
    return mod(y * y - (x * x * x + a * x + b), N) === ZERO;
  }

  /* --------------------------- ECPP chain ------------------------------- */

  function verifyLink(link) {
    const N = BigInt(link.N);
    const a = mod(BigInt(link.a), N);
    const b = mod(BigInt(link.b), N);
    const x = mod(BigInt(link.x), N);
    const y = mod(BigInt(link.y), N);
    const m = BigInt(link.m);
    const q = BigInt(link.q);

    if (N <= ONE) throw new Error("N <= 1");
    for (const sp of SMALL_PRIMES) {
      if (N % sp === ZERO && N !== sp) throw new Error("N is divisible by " + sp);
    }
    if (m <= ZERO || q <= ONE) throw new Error("m or q out of range");

    const d = m - (N + ONE);
    if (d * d > 4n * N) throw new Error("claimed order m violates the Hasse bound");
    if (!pointOnCurve(x, y, a, b, N)) throw new Error("point does not lie on the curve");
    if (m % q !== ZERO) throw new Error("q does not divide m");

    const r = isqrt(isqrt(N));
    if (!(q > (r + ONE) * (r + ONE))) {
      throw new Error("size condition fails: q <= (N^(1/4) + 1)^2");
    }

    const P = [x, y, ONE];
    const mP = ecMul(m, P, a, N);
    if (mod(mP[2], N) !== ZERO) throw new Error("m*P != O");

    const R = ecMul(m / q, P, a, N);
    if (mod(R[2], N) === ZERO) throw new Error("(m/q)*P == O, expected != O");
    if (gcd(mod(R[2], N), N) !== ONE) {
      throw new Error("non-invertible Z in (m/q)*P: N is composite");
    }
    return true;
  }

  function verifyPocklingtonTail(q, tail) {
    if (!tail || tail.F === undefined || !tail.factors_F || tail.witness_a === undefined) {
      throw new Error("tail: missing F / factors_F / witness_a");
    }
    const F = BigInt(tail.F);
    const a = BigInt(tail.witness_a);
    if (F * F <= q) throw new Error("tail: F^2 <= q, Pocklington proof incomplete");
    if ((q - ONE) % F !== ZERO) throw new Error("tail: F does not divide q-1");
    if (powMod(a, q - ONE, q) !== ONE) throw new Error("tail: witness fails a^(q-1) = 1");
    for (const fs of tail.factors_F) {
      const f = BigInt(fs);
      if (F % f !== ZERO) throw new Error("tail: " + f + " does not divide F");
      if (!isPrime(f, 20)) throw new Error("tail: claimed factor " + f + " is not prime");
      if (gcd(powMod(a, (q - ONE) / f, q) - ONE, q) !== ONE) {
        throw new Error("tail: Pocklington condition fails for f=" + f);
      }
    }
    return true;
  }

  /* onProgress(done, total) is optional and lets a UI stay responsive. */
  async function verifyChain(chain, claimedN, tail, onProgress) {
    if (!chain || chain.length === 0) throw new Error("empty chain: nothing is proven");
    if (claimedN !== undefined && claimedN !== null) {
      if (BigInt(chain[0].N) !== BigInt(claimedN)) {
        throw new Error("first link does not concern the claimed N");
      }
    }
    for (let i = 0; i < chain.length; i++) {
      verifyLink(chain[i]);
      const q = BigInt(chain[i].q);
      if (i + 1 < chain.length) {
        if (q !== BigInt(chain[i + 1].N)) {
          throw new Error("chain broken: q of link " + i + " != N of link " + (i + 1));
        }
        if (BigInt(chain[i + 1].N) >= BigInt(chain[i].N)) {
          throw new Error("chain does not decrease at link " + i);
        }
      } else {
        if (q < BPSW_DETERMINISTIC_LIMIT) {
          if (!isPrime(q, 0)) throw new Error("final q is not prime");
        } else if (tail) {
          verifyPocklingtonTail(q, tail);
        } else {
          throw new Error("chain is not closed: final q has " + q.toString(2).length +
            " bits (>= 2^64) and no Pocklington proof is present in 'tail'");
        }
      }
      if (onProgress) await onProgress(i + 1, chain.length);
    }
    return true;
  }

  /* ------------------------- canonical JSON + digest --------------------- */
  /* Must reproduce Python's json.dumps(obj, sort_keys=True) byte for byte:
     separators ", " and ": ", and non-ASCII escaped (ensure_ascii=True).     */

  function pyString(s) {
    let out = '"';
    for (const ch of s) {
      const c = ch.codePointAt(0);
      if (ch === '"') out += '\\"';
      else if (ch === "\\") out += "\\\\";
      else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else if (ch === "\b") out += "\\b";
      else if (ch === "\f") out += "\\f";
      else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
      else if (c < 0x7f) out += ch;
      else if (c <= 0xffff) out += "\\u" + c.toString(16).padStart(4, "0");
      else {
        const v = c - 0x10000;
        const hi = 0xd800 + (v >> 10), lo = 0xdc00 + (v & 0x3ff);
        out += "\\u" + hi.toString(16).padStart(4, "0") +
               "\\u" + lo.toString(16).padStart(4, "0");
      }
    }
    return out + '"';
  }

  function canonical(value) {
    if (value === null) return "null";
    if (value === true) return "true";
    if (value === false) return "false";
    if (typeof value === "string") return pyString(value);
    if (typeof value === "number") {
      if (Number.isInteger(value)) return String(value);
      return String(value);
    }
    if (typeof value === "bigint") return value.toString();
    if (Array.isArray(value)) return "[" + value.map(canonical).join(", ") + "]";
    if (typeof value === "object") {
      const keys = Object.keys(value).sort();
      return "{" + keys.map(k => pyString(k) + ": " + canonical(value[k])).join(", ") + "}";
    }
    throw new Error("cannot serialise " + typeof value);
  }

  async function sha256Hex(text) {
    const bytes = new TextEncoder().encode(text);
    if (typeof crypto !== "undefined" && crypto.subtle) {
      const buf = await crypto.subtle.digest("SHA-256", bytes);
      return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, "0")).join("");
    }
    // Node fallback
    const { createHash } = require("crypto");
    return createHash("sha256").update(Buffer.from(bytes)).digest("hex");
  }

  async function recomputeDigest(cert) {
    const body = {};
    for (const k of Object.keys(cert)) if (k !== "sha256") body[k] = cert[k];
    return sha256Hex(canonical(body));
  }

  /* --------------------------- JSON with BigInt -------------------------- */
  /*
   * JSON.parse turns a 512-bit integer into a float and silently loses it.
   * ECPP chains carry hundreds of such integers, so the built-in parser cannot
   * be used: the digest would never match and the curve arithmetic would be
   * nonsense. This is a minimal recursive-descent parser that yields BigInt for
   * every integer literal and leaves everything else to normal semantics.
   */
  function parseJSON(text) {
    let i = 0;

    function ws() { while (i < text.length && " \t\n\r".indexOf(text[i]) >= 0) i++; }
    function fail(msg) { throw new Error("JSON at " + i + ": " + msg); }

    function parseString() {
      if (text[i] !== '"') fail("expected string");
      i++;
      let out = "";
      while (i < text.length) {
        const ch = text[i];
        if (ch === '"') { i++; return out; }
        if (ch === "\\") {
          i++;
          const e = text[i++];
          if (e === "u") {
            out += String.fromCharCode(parseInt(text.substr(i, 4), 16));
            i += 4;
          } else {
            const map = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f",
                          n: "\n", r: "\r", t: "\t" };
            if (!(e in map)) fail("bad escape \\" + e);
            out += map[e];
          }
        } else { out += ch; i++; }
      }
      fail("unterminated string");
    }

    function parseNumber() {
      const start = i;
      if (text[i] === "-") i++;
      while (i < text.length && text[i] >= "0" && text[i] <= "9") i++;
      let isFloat = false;
      if (text[i] === "." || text[i] === "e" || text[i] === "E") {
        isFloat = true;
        while (i < text.length && "0123456789+-eE.".indexOf(text[i]) >= 0) i++;
      }
      const lit = text.slice(start, i);
      return isFloat ? Number(lit) : BigInt(lit);
    }

    function parseValue() {
      ws();
      const ch = text[i];
      if (ch === "{") {
        i++; const obj = {};
        ws();
        if (text[i] === "}") { i++; return obj; }
        for (;;) {
          ws();
          const k = parseString();
          ws();
          if (text[i] !== ":") fail("expected :");
          i++;
          obj[k] = parseValue();
          ws();
          if (text[i] === ",") { i++; continue; }
          if (text[i] === "}") { i++; return obj; }
          fail("expected , or }");
        }
      }
      if (ch === "[") {
        i++; const arr = [];
        ws();
        if (text[i] === "]") { i++; return arr; }
        for (;;) {
          arr.push(parseValue());
          ws();
          if (text[i] === ",") { i++; continue; }
          if (text[i] === "]") { i++; return arr; }
          fail("expected , or ]");
        }
      }
      if (ch === '"') return parseString();
      if (text.startsWith("true", i)) { i += 4; return true; }
      if (text.startsWith("false", i)) { i += 5; return false; }
      if (text.startsWith("null", i)) { i += 4; return null; }
      if (ch === "-" || (ch >= "0" && ch <= "9")) return parseNumber();
      fail("unexpected " + JSON.stringify(ch));
    }

    const v = parseValue();
    ws();
    if (i !== text.length) fail("trailing data");
    return v;
  }

  /* ------------------------------ claims -------------------------------- */

  function checkPocklington(N, cert) {
    const a = BigInt(cert.witness_a);
    const F = BigInt(cert.F);
    if (F * F <= N) return [false, "F is too small (F^2 <= N): proof incomplete"];
    if ((N - ONE) % F !== ZERO) return [false, "F does not divide N-1"];
    if (powMod(a, N - ONE, N) !== ONE) return [false, "witness fails a^(N-1) = 1"];
    for (const qs of cert.factors_F) {
      const q = BigInt(qs);
      if (F % q !== ZERO) return [false, "claimed factor " + q + " does not divide F"];
      if (!isPrime(q, 20)) return [false, "claimed factor " + q + " is not itself prime"];
      if (gcd(powMod(a, (N - ONE) / q, N) - ONE, N) !== ONE) {
        return [false, "Pocklington condition fails for q=" + q];
      }
    }
    return [true, "PROVEN: N is prime (Pocklington, F > sqrt(N), witness a=" + a + ")"];
  }

  async function checkPrimeClaim(cert, strict, onProgress) {
    const N = BigInt(cert.N);
    if (cert.verdict === "NOT_PRIME") {
      if (isPrime(N, 20)) {
        return [false, "certificate claims NOT_PRIME but N passes Miller-Rabin: contradiction"];
      }
      return [true, "CONFIRMED: N is composite"];
    }
    const method = cert.method;
    if (method === "Pocklington") {
      try { return checkPocklington(N, cert); }
      catch (e) { return [false, "incomplete Pocklington certificate: " + e.message]; }
    }
    if (method === "ECPP") {
      const chain = cert.ecpp_chain;
      if (!chain || chain.length === 0) {
        return [false, "method is ECPP but the certificate carries no 'ecpp_chain'"];
      }
      try {
        await verifyChain(chain, N, cert.tail, onProgress);
      } catch (e) {
        return [false, "ECPP chain rejected: " + e.message];
      }
      const qLast = BigInt(chain[chain.length - 1].q);
      const closure = qLast < BPSW_DETERMINISTIC_LIMIT
        ? "deterministic Miller-Rabin (q < 2^64)" : "Pocklington tail";
      return [true, "PROVEN: N is prime (ECPP, " + chain.length +
        " links checked here, closure: " + closure + ")"];
    }
    return [false, "method '" + method + "' carries no proof of primality. N may pass " +
      "a probabilistic test, but that is a probability, not a proof: rejected " +
      "(use ECPP or Pocklington)"];
  }

  async function verifyKpProof(cert, strict, onProgress) {
    const claim = cert.claim;

    if (claim === "CLAIM_WEAK") {
      if (cert.verdict !== "WEAK") return [true, "certificate is intact (no weakness found)"];
      if (!cert.recovered_factor) {
        return [true, "weakness reported without a recovered factor " +
          "(e.g. a ROCA fingerprint): intact, but carries no proof"];
      }
      const n = BigInt(cert.modulus_n), f = BigInt(cert.recovered_factor);
      if (!(f > ONE && f < n) || n % f !== ZERO) {
        return [false, "the recovered factor does NOT divide n: false positive"];
      }
      return [true, "PROVEN: " + f + " x " + (n / f) + " = n (checked here)"];
    }

    if (claim === "CLAIM_PRIME") return checkPrimeClaim(cert, strict, onProgress);

    if (claim === "CLAIM_HARDENED") {
      const report = cert.attacks_repelled || {};
      const names = Object.keys(report);
      if (names.length === 0) return [false, "no attack report present: nothing to check"];
      const broken = names.filter(k => {
        const v = report[k];
        return v !== true && v !== "repelled" && v !== "odbity";
      });
      if (broken.length) return [false, "claims resistance but attacks succeeded: " + broken];
      if (cert.verdict !== "HARDENED") return [false, "verdict inconsistent with the attack report"];
      if (strict) {
        return [false, "HARDENED attests report consistency, not a mathematical proof: " +
          "rejected under strict mode. Run the attack suite yourself against n"];
      }
      return [true, "report is consistent: " + names.length + " attacks repelled. NOTE: " +
        "this is not a proof — run the suite yourself for certainty"];
    }

    if (claim === "CLAIM_PARAMS") {
      const p = BigInt(cert.p), q = BigInt(cert.q);
      if (p !== TWO * q + ONE) return [false, "p != 2q+1: not a safe prime"];
      const levels = {};
      for (const [name, value, key] of [["p", p, "proof_p"], ["q", q, "proof_q"]]) {
        const sub = cert[key];
        if (sub) {
          if (BigInt(sub.N || 0) !== value) {
            return [false, key + " concerns a different number than " + name];
          }
          const [ok, why] = await checkPrimeClaim(sub, false, onProgress);
          if (!ok) return [false, "primality proof for " + name + " rejected: " + why];
          levels[name] = why.split(":")[0];
        } else {
          if (!isPrime(value, 20)) return [false, name + " is not prime"];
          levels[name] = "Miller-Rabin (probabilistic)";
        }
      }
      const full = Object.values(levels).every(v => v.indexOf("PROVEN") === 0);
      if (strict && !full) {
        return [false, "no primality proofs attached for p and q: rejected under strict mode"];
      }
      const level = full ? "PROVEN" : "CONFIRMED probabilistically";
      return [true, level + ": p = 2q+1, both prime (" + p.toString(2).length +
        "-bit); p: " + levels.p + ", q: " + levels.q];
    }

    return [false, "unknown claim: " + claim];
  }

  function verifyAuditCert(cert) {
    if (cert.verdict === "WEAK") {
      if (!cert.recovered_factor) {
        return [true, "weakness reported without a recovered factor: intact, but carries no proof"];
      }
      const n = BigInt(cert.modulus_n), f = BigInt(cert.recovered_factor);
      if (!(f > ONE && f < n)) return [false, "recovered factor out of range"];
      if (n % f !== ZERO) return [false, "the recovered factor does NOT divide n: false positive"];
      return [true, "PROVEN: " + f + " x " + (n / f) + " = n (checked here)"];
    }
    if (cert.verdict === "STRONG") return [true, "certificate is intact; the audit found no weakness"];
    return [false, "unknown verdict '" + cert.verdict + "': rejected"];
  }

  async function verify(cert, options) {
    const opts = options || {};
    const fmt = cert.format;
    if (fmt !== "KP-PROOF-1" && fmt !== "KP-AUDIT-CERT-1") {
      return [false, "unknown certificate format: " + JSON.stringify(fmt)];
    }
    const digest = await recomputeDigest(cert);
    if (digest !== cert.sha256) {
      return [false, "digest mismatch: the certificate has been altered"];
    }
    if (fmt === "KP-PROOF-1") return verifyKpProof(cert, !!opts.strict, opts.onProgress);
    return verifyAuditCert(cert);
  }

  return {
    verify, verifyChain, verifyLink, recomputeDigest, canonical, parseJSON,
    isPrime, powMod, gcd, isqrt, ecMul, ecAdd, ecDouble,
    BPSW_DETERMINISTIC_LIMIT
  };
});
