/*
 * Cross-check: does the JavaScript verifier agree with the Python one?
 *
 * Two implementations written from the same specification, not from each
 * other. If they disagree on any certificate, one of them is wrong and the
 * format has a hole. This script runs the JS side; compare-with-python.sh runs
 * both and diffs the verdicts.
 *
 *     node test-node.js
 *
 * Exit code 0 means every check passed.
 */
const fs = require("fs");
const path = require("path");
const KP = require("./kp-verify.js");

const EX = path.join(__dirname, "examples");
let passed = 0, failed = [];

function check(name, cond, detail) {
  if (cond) { passed++; console.log("  [PASS] " + name + (detail ? " -- " + detail : "")); }
  else { failed.push(name); console.log("  [FAIL] " + name + (detail ? " -- " + detail : "")); }
}

function load(f) { return KP.parseJSON(fs.readFileSync(path.join(EX, f), "utf8")); }

async function reseal(cert) {
  const out = KP.parseJSON(KP.canonical(cert));
  delete out.sha256;
  out.sha256 = await KP.recomputeDigest(out);
  return out;
}

(async () => {
  const t0 = Date.now();
  const files = fs.readdirSync(EX).filter(f => f.endsWith(".json")).sort();

  console.log("\n== 1. genuine certificates are accepted (strict) ==");
  for (const f of files) {
    const cert = load(f);
    const t = Date.now();
    const [ok, why] = await KP.verify(cert, { strict: true });
    check(f + "  [" + ((Date.now() - t) / 1000).toFixed(1) + "s]", ok, why);
  }

  console.log("\n== 2. digest is byte-compatible with the Python canonical form ==");
  for (const f of files) {
    const cert = load(f);
    const d = await KP.recomputeDigest(cert);
    check("digest " + f, d === cert.sha256,
      d === cert.sha256 ? d.slice(0, 16) + "..." : "got " + d.slice(0, 16) + " want " + cert.sha256.slice(0, 16));
  }

  const base = load("prime_512bit_ecpp.json");

  console.log("\n== 3. forgeries are rejected ==");

  let c = KP.parseJSON(KP.canonical(base));
  c.N = (BigInt(c.N) + 2n).toString();
  check("altered field with stale digest", !(await KP.verify(c))[0], (await KP.verify(c))[1]);

  c = KP.parseJSON(KP.canonical(base));
  c.ecpp_chain[0].y = (BigInt(c.ecpp_chain[0].y) + 1n) % BigInt(c.ecpp_chain[0].N);
  let r = await KP.verify(await reseal(c));
  check("point moved off the curve", !r[0], r[1]);

  c = KP.parseJSON(KP.canonical(base));
  c.ecpp_chain[0].m = BigInt(c.ecpp_chain[0].m) * 7n;
  r = await KP.verify(await reseal(c));
  check("order violating the Hasse bound", !r[0], r[1]);

  c = KP.parseJSON(KP.canonical(base));
  {
    const m = BigInt(c.ecpp_chain[0].m);
    let small = null;
    for (let d = 2n; d < 500n; d++) if (m % d === 0n && KP.isPrime(d, 0)) { small = d; break; }
    if (small) {
      c.ecpp_chain[0].q = small;
      r = await KP.verify(await reseal(c));
      check("q below the size condition", !r[0], r[1]);
    }
  }

  c = KP.parseJSON(KP.canonical(base));
  c.ecpp_chain[1].N = BigInt(c.ecpp_chain[1].N) + 2n;
  r = await KP.verify(await reseal(c));
  check("broken link in the chain", !r[0], r[1]);

  c = KP.parseJSON(KP.canonical(base));
  c.N = (BigInt(c.N) + 30n).toString();
  r = await KP.verify(await reseal(c));
  check("claimed N swapped", !r[0], r[1]);

  c = KP.parseJSON(KP.canonical(base));
  c.ecpp_chain = [];
  r = await KP.verify(await reseal(c));
  check("empty chain", !r[0], r[1]);

  c = KP.parseJSON(KP.canonical(base));
  c.ecpp_chain = [c.ecpp_chain[0]];
  delete c.tail;
  if (BigInt(c.ecpp_chain[0].q) >= KP.BPSW_DETERMINISTIC_LIMIT) {
    r = await KP.verify(await reseal(c));
    check("truncated chain, unclosed tail", !r[0], r[1]);
  }

  c = await reseal({ format: "KP-PROOF-1", claim: "CLAIM_PRIME", N: base.N,
                     verdict: "PRIME_PROBABLE", method: "ECPP_REQUIRED" });
  r = await KP.verify(c);
  check("claim without a proof", !r[0], r[1]);

  c = await reseal({ format: "SOMETHING-ELSE-1", claim: "CLAIM_PRIME" });
  r = await KP.verify(c);
  check("unknown certificate format", !r[0], r[1]);

  console.log("\n== 4. proven vs probable ==");
  const params = files.map(load).find(x => x.claim === "CLAIM_PARAMS");
  if (params) {
    const stripped = KP.parseJSON(KP.canonical(params));
    delete stripped.proof_p; delete stripped.proof_q;
    const s = await reseal(stripped);
    r = await KP.verify(s);
    check("parameters without proofs: valid, marked probabilistic",
      r[0] && /probabilistic/.test(r[1]), r[1]);
    r = await KP.verify(s, { strict: true });
    check("parameters without proofs: rejected in strict mode", !r[0], r[1]);
  }

  console.log("\n" + "=".repeat(68));
  console.log("PASSED: " + passed + "   FAILED: " + failed.length +
    "   (" + ((Date.now() - t0) / 1000).toFixed(1) + "s)");
  if (failed.length) console.log("failing: " + failed.join(", "));
  console.log("=".repeat(68));
  process.exit(failed.length ? 1 : 0);
})();
