#!/usr/bin/env python3
"""
Self-test for kp-verify. Runs offline: no network, no PARI, no issuer.

It answers the only two questions that matter about a verifier:

    1. does it accept a genuine proof?     (without this the tool is useless)
    2. does it reject a forged one?        (without this the tool is a lie)

Every certificate in examples/ is verified, then deliberately corrupted in
several independent ways, and each corruption must be caught.

    python3 selftest.py

Exit code 0 means every check passed.

Copyright (c) 2026 IDEALPLACE algorithms. MIT License.
"""
import copy
import glob
import hashlib
import json
import os
import sys
import time

import gmpy2
from gmpy2 import mpz

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kp_verify
from kp_verify import verify, recompute_digest

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    mark = "PASS" if condition else "FAIL"
    print(f"  [{mark}] {name}" + (f" -- {detail}" if detail else ""))


def reseal(cert):
    """Recompute the digest, i.e. forge as competently as possible."""
    out = copy.deepcopy(cert)
    out.pop("sha256", None)
    out["sha256"] = hashlib.sha256(
        json.dumps(out, sort_keys=True).encode()).hexdigest()
    return out


def load_examples():
    here = os.path.dirname(os.path.abspath(__file__))
    paths = sorted(glob.glob(os.path.join(here, "examples", "*.json")))
    return [(os.path.basename(p), json.load(open(p))) for p in paths]


def main():
    t0 = time.perf_counter()
    examples = load_examples()
    if not examples:
        print("no example certificates found in examples/")
        return 2

    print("\n== 1. genuine certificates are accepted (--strict) ==")
    ecpp_certs = []
    for name, cert in examples:
        ok, why = verify(cert, strict=True)
        check(f"{name}", ok, why)
        if cert.get("method") == "ECPP" or cert.get("claim") == "CLAIM_PARAMS":
            ecpp_certs.append((name, cert))

    if not ecpp_certs:
        print("\nno ECPP certificate among the examples; forgery tests skipped")
        return 1

    # Use the smallest ECPP certificate for the forgery tests: same code path,
    # faster to run.
    name, base = min(
        (c for c in ecpp_certs if c[1].get("method") == "ECPP"),
        key=lambda c: len(json.dumps(c[1])))
    print(f"\n== 2. forgeries are rejected (base: {name}) ==")

    # a) altered field, digest left stale
    c = copy.deepcopy(base)
    c["N"] = str(mpz(c["N"]) + 2)
    ok, why = verify(c)
    check("altered field with stale digest", not ok, why)

    # b) point moved off the curve, digest recomputed
    c = copy.deepcopy(base)
    link = c["ecpp_chain"][0]
    link["y"] = int((mpz(link["y"]) + 1) % mpz(link["N"]))
    ok, why = verify(reseal(c))
    check("point moved off the curve", not ok, why)

    # c) order outside the Hasse interval
    c = copy.deepcopy(base)
    c["ecpp_chain"][0]["m"] = int(mpz(c["ecpp_chain"][0]["m"]) * 7)
    ok, why = verify(reseal(c))
    check("order violating the Hasse bound", not ok, why)

    # d) q below the size condition
    c = copy.deepcopy(base)
    link = c["ecpp_chain"][0]
    m = mpz(link["m"])
    small = next((d for d in range(2, 500)
                  if m % d == 0 and gmpy2.is_prime(mpz(d))), None)
    if small:
        link["q"] = small
        ok, why = verify(reseal(c))
        check("q below (N^(1/4)+1)^2", not ok, why)

    # e) chain broken between links
    if len(base["ecpp_chain"]) > 1:
        c = copy.deepcopy(base)
        c["ecpp_chain"][1]["N"] = int(mpz(c["ecpp_chain"][1]["N"]) + 2)
        ok, why = verify(reseal(c))
        check("broken link in the chain", not ok, why)

    # f) certificate re-pointed at a different number
    c = copy.deepcopy(base)
    c["N"] = str(gmpy2.next_prime(mpz(c["N"])))
    ok, why = verify(reseal(c))
    check("claimed N swapped", not ok, why)

    # g) empty chain
    c = copy.deepcopy(base)
    c["ecpp_chain"] = []
    ok, why = verify(reseal(c))
    check("empty chain", not ok, why)

    # h) truncated chain: final q >= 2^64 with no Pocklington tail
    long_chain = next((cc for _, cc in ecpp_certs
                       if cc.get("method") == "ECPP" and len(cc["ecpp_chain"]) > 2), None)
    if long_chain:
        c = copy.deepcopy(long_chain)
        c["ecpp_chain"] = c["ecpp_chain"][:1]
        c.pop("tail", None)
        if mpz(c["ecpp_chain"][0]["q"]) >= kp_verify.BPSW_DETERMINISTIC_LIMIT:
            ok, why = verify(reseal(c))
            check("truncated chain, unclosed tail", not ok, why)

    # i) a claim with no proof behind it must not be stamped valid
    c = reseal({"format": "KP-PROOF-1", "claim": "CLAIM_PRIME",
                "N": base["N"], "verdict": "PRIME_PROBABLE",
                "method": "ECPP_REQUIRED"})
    ok, why = verify(c)
    check("claim without a proof", not ok, why)

    # j) unknown format
    c = reseal({"format": "SOMETHING-ELSE-1", "claim": "CLAIM_PRIME"})
    ok, why = verify(c)
    check("unknown certificate format", not ok, why)

    print("\n== 3. proven vs probable is reported honestly ==")
    params = next((cc for _, cc in examples if cc.get("claim") == "CLAIM_PARAMS"), None)
    if params:
        stripped = copy.deepcopy(params)
        stripped.pop("proof_p", None)
        stripped.pop("proof_q", None)
        stripped = reseal(stripped)
        ok, why = verify(stripped)
        check("parameters without proofs: valid but marked probabilistic",
              ok and "probabilistic" in why, why)
        ok, why = verify(stripped, strict=True)
        check("parameters without proofs: rejected under --strict", not ok, why)

    elapsed = time.perf_counter() - t0
    print("\n" + "=" * 68)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}   ({elapsed:.1f}s)")
    if FAILED:
        print("failing checks: " + ", ".join(FAILED))
    print("=" * 68)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
