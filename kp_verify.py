#!/usr/bin/env python3
"""
kp-verify — open verifier for KP-PROOF-1 and KP-AUDIT-CERT-1 certificates.

You run this. Not the issuer. The point of the certificate format is that its
validity is decidable from the certificate alone, with no network access, no
issuer, and no shared secret.

Usage
    python3 kp_verify.py CERTIFICATE.json [--strict]

Exit codes
    0  valid
    1  invalid
    2  usage error

--strict rejects anything that is not a complete mathematical proof. Use it
when the distinction between "proven" and "probable" matters to you. It does
matter more often than people assume.

DESIGN RULE: FAIL CLOSED
    An unknown format, an unknown claim, an unknown proof method or a missing
    proof all yield "invalid". A verifier that returns "valid" for something it
    did not check is worse than no verifier at all, because it converts an open
    question into a false answer. Earlier versions of this file did exactly
    that for one branch; the bug is described in SPEC.md under "History".

Copyright (c) 2026 RECHECK Piotr Burylo. MIT License.
"""
import sys
import json
import hashlib

import gmpy2
from gmpy2 import mpz, is_prime, gcd

try:
    from ecpp import verify_chain, ECPPError, BPSW_DETERMINISTIC_LIMIT
    _HAVE_ECPP = True
except ImportError:
    _HAVE_ECPP = False
    BPSW_DETERMINISTIC_LIMIT = mpz(1) << 64

    class ECPPError(Exception):
        pass


__all__ = ["verify", "recompute_digest"]


def recompute_digest(cert):
    """SHA-256 over the certificate with the `sha256` field removed,
    JSON-serialised with sorted keys and no whitespace variation."""
    body = {k: v for k, v in cert.items() if k != "sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


# ------------------------------ primality claims ------------------------------

def _check_pocklington(N, cert):
    a = mpz(cert["witness_a"])
    factors = [mpz(x) for x in cert["factors_F"]]
    F = mpz(cert["F"])
    if F * F <= N:
        return False, "F is too small (F^2 <= N): proof incomplete"
    if (N - 1) % F != 0:
        return False, "F does not divide N-1"
    if pow(a, N - 1, N) != 1:
        return False, "witness fails a^(N-1) = 1"
    for q in factors:
        if F % q != 0:
            return False, f"claimed factor {q} does not divide F"
        if not is_prime(q, 40):
            return False, f"claimed factor {q} is not itself prime"
        if gcd(pow(a, (N - 1) // q, N) - 1, N) != 1:
            return False, f"Pocklington condition fails for q={q}"
    return True, f"PROVEN: N is prime (Pocklington, F > sqrt(N), witness a={a})"


def _check_prime_claim(cert, strict):
    N = mpz(cert["N"])

    if cert.get("verdict") == "NOT_PRIME":
        if is_prime(N):
            return False, "certificate claims NOT_PRIME but N passes BPSW: contradiction"
        return True, "CONFIRMED: N is composite"

    method = cert.get("method")

    if method == "Pocklington":
        try:
            return _check_pocklington(N, cert)
        except (KeyError, ValueError) as exc:
            return False, f"incomplete Pocklington certificate: {exc}"

    if method == "ECPP":
        if not _HAVE_ECPP:
            return False, "ecpp.py is missing: cannot check the chain, refusing to guess"
        chain = cert.get("ecpp_chain")
        if not chain:
            return False, "method is ECPP but the certificate carries no 'ecpp_chain'"
        try:
            verify_chain(chain, claimed_N=N, tail=cert.get("tail"))
        except ECPPError as exc:
            return False, f"ECPP chain rejected: {exc}"
        q_last = mpz(chain[-1]["q"])
        closure = ("deterministic BPSW (q < 2^64)"
                   if q_last < BPSW_DETERMINISTIC_LIMIT else "Pocklington tail")
        return True, (f"PROVEN: N is prime (ECPP, {len(chain)} links checked here, "
                      f"closure: {closure})")

    return False, (f"method '{method}' carries no proof of primality. N may pass "
                   f"BPSW, but that is a probability, not a proof: rejected "
                   f"(use ECPP or Pocklington)")


# --------------------------------- dispatcher ---------------------------------

def _verify_kp_proof(cert, strict):
    claim = cert.get("claim")

    # 1. "this RSA key is weak" — check that the recovered factor really divides n
    if claim == "CLAIM_WEAK":
        if cert.get("verdict") != "WEAK":
            return True, "certificate is intact (no weakness found)"
        f = cert.get("recovered_factor")
        if not f:
            return True, ("weakness reported without a recovered factor "
                          "(e.g. a ROCA fingerprint): intact, but carries no proof")
        n = mpz(cert["modulus_n"])
        f = mpz(f)
        if not 1 < f < n or n % f != 0:
            return False, "the recovered factor does NOT divide n: false positive"
        return True, f"PROVEN: {f} x {n // f} = n (checked here)"

    # 2. "this number is prime"
    if claim == "CLAIM_PRIME":
        return _check_prime_claim(cert, strict)

    # 3. "this key resists structural attacks"
    if claim == "CLAIM_HARDENED":
        report = cert.get("attacks_repelled", {})
        if not report:
            return False, "no attack report present: nothing to check"
        # each entry must state that the attack was repelled: `true`, or the
        # legacy string form emitted by older issuers
        broken = [a for a, v in report.items()
                  if v is not True and v not in ("repelled", "odbity")]
        if broken:
            return False, f"claims resistance but attacks succeeded: {broken}"
        if cert.get("verdict") != "HARDENED":
            return False, "verdict inconsistent with the attack report"
        if strict:
            return False, ("HARDENED attests report consistency, not a mathematical "
                           "proof: rejected under --strict. Run the attack suite "
                           "yourself against n from the certificate")
        return True, (f"report is consistent: {len(report)} attacks repelled. NOTE: "
                      f"this is not a proof — run the suite yourself for certainty")

    # 4. "these domain parameters are safe"
    if claim == "CLAIM_PARAMS":
        p = mpz(cert["p"])
        q = mpz(cert["q"])
        if p != 2 * q + 1:
            return False, "p != 2q+1: not a safe prime"
        levels = {}
        for name, value, key in (("p", p, "proof_p"), ("q", q, "proof_q")):
            sub = cert.get(key)
            if sub:
                if mpz(sub.get("N", 0)) != value:
                    return False, f"{key} concerns a different number than {name}"
                ok, why = _check_prime_claim(sub, strict=False)
                if not ok:
                    return False, f"primality proof for {name} rejected: {why}"
                levels[name] = why.split(":")[0]
            else:
                if not is_prime(value, 40):
                    return False, f"{name} is not prime"
                levels[name] = "BPSW (probabilistic)"
        full = all(v.startswith("PROVEN") for v in levels.values())
        if strict and not full:
            return False, ("no primality proofs attached for p and q: "
                           "rejected under --strict")
        level = "PROVEN" if full else "CONFIRMED probabilistically"
        return True, (f"{level}: p = 2q+1, both prime ({p.bit_length()}-bit); "
                      f"p: {levels['p']}, q: {levels['q']}")

    return False, f"unknown claim: {claim}"


def _verify_audit_cert(cert):
    """KP-AUDIT-CERT-1 — the verdict of an RSA key audit."""
    verdict = cert.get("verdict")

    if verdict == "WEAK":
        f = cert.get("recovered_factor")
        if not f:
            return True, ("weakness reported without a recovered factor: intact, "
                          "but carries no proof")
        n = mpz(cert["modulus_n"])
        f = mpz(f)
        if not 1 < f < n:
            return False, "recovered factor out of range"
        if n % f != 0:
            return False, "the recovered factor does NOT divide n: false positive"
        return True, f"PROVEN: {f} x {n // f} = n (checked here)"

    if verdict == "STRONG":
        return True, "certificate is intact; the audit found no weakness"

    return False, f"unknown verdict '{verdict}': rejected"


def verify(cert, strict=False):
    """Verify a certificate. Returns (ok: bool, reason: str)."""
    fmt = cert.get("format")
    if fmt not in ("KP-PROOF-1", "KP-AUDIT-CERT-1"):
        return False, f"unknown certificate format: {fmt!r}"
    if recompute_digest(cert) != cert.get("sha256"):
        return False, "digest mismatch: the certificate has been altered"
    if fmt == "KP-PROOF-1":
        return _verify_kp_proof(cert, strict)
    return _verify_audit_cert(cert)


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    strict = "--strict" in argv
    if not args:
        print(__doc__.strip().splitlines()[0])
        print("usage: python3 kp_verify.py CERTIFICATE.json [--strict]")
        return 2
    with open(args[0]) as fh:
        cert = json.load(fh)
    ok, reason = verify(cert, strict=strict)
    print(("VALID: " if ok else "INVALID: ") + reason)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
