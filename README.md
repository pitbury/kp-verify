# KP-verify

An open verifier for portable cryptographic evidence.

A KP certificate is a small JSON file that states a mathematical fact about a
key or a parameter set, and carries everything needed to check that fact. You
check it yourself, offline, with the code in this repository. No issuer, no
service, no network, no shared secret. If the issuer disappears tomorrow, the
certificate still decides.

That is the entire idea. The engine that produces these certificates is closed;
the verifier is not, and it is the verifier that matters.

## Try it in thirty seconds

```
pip install gmpy2
python3 kp_verify.py examples/prime_4096bit_ecpp.json --strict
```

```
VALID: PROVEN: N is prime (ECPP, 137 links checked here, closure: deterministic BPSW (q < 2^64))
```

That certificate was produced on a machine you have never seen, by software you
cannot read. The line above was decided on your machine, by code you can read in
an afternoon. Nothing was trusted in between.

```
python3 selftest.py
```

verifies every bundled certificate, then forges each one in ten different ways
and requires every forgery to be caught.

### Or without installing anything

Open `verify.html` and drop a certificate onto the page. Verification runs in
the tab, in plain `BigInt`, with no network requests — disconnect and it still
works. Certificates up to 2048 bits verify in seconds; 4096 bits takes about a
minute in a browser.

This is a **second, independent implementation**. `kp_verify.py` and
`kp-verify.js` were written from `SPEC.md`, not from each other, and are tested
to agree on every certificate here — down to byte-identical digests. Two
implementations agreeing is a stronger statement about a format than either one
alone.

## What is actually proven

| claim | statement | what the verifier checks | strength |
|---|---|---|---|
| `CLAIM_PRIME` | this number is prime | full ECPP chain (Atkin-Morain) or a Pocklington proof, link by link | **proof** |
| `CLAIM_PARAMS` | these are safe domain parameters | p = 2q+1 and attached primality proofs for both | **proof** when proofs are attached |
| `CLAIM_WEAK` | this RSA key is defective | that the recovered factor really divides n | **proof** |
| `CLAIM_HARDENED` | this key resists structural attacks | internal consistency of the attack report only | **not a proof** |

The last row is deliberate. `CLAIM_HARDENED` attests that a report is
self-consistent; it does not establish that the attacks were run honestly. Run
them yourself against the modulus in the certificate. `--strict` rejects this
claim for exactly that reason.

## What this does not do

Being clear about the boundary is more useful than a longer feature list.

- It does **not** prove how a key was generated. Keys born inside an HSM never
  expose p and q, so only the public modulus can be examined.
- It does **not** discover keys. It says nothing about assets you have not
  handed to it.
- It does **not** replace a probabilistic primality test in a hot path. A
  Baillie-PSW test on a 4096-bit number takes milliseconds; producing the proof
  below took forty seconds. The value here is the artefact, not the speed.
- `CLAIM_PARAMS` without attached proofs falls back to Baillie-PSW and says so
  in its own output. Probable is not proven, and the verifier will not blur that.

## Measured

Certificate generation on one cloud instance (PARI/GP 2.17.4 produces the ECPP
chain; this verifier checks it independently, single-threaded):

| size | chain links | generation | verification | certificate |
|---|---|---|---|---|
| 512-bit | 16 | 0.2 s | 0.05 s | 11 kB |
| 1024-bit | 35 | 0.7 s | 0.39 s | 45 kB |
| 2048-bit | 95 | 4.9 s | 3.54 s | 208 kB |
| 4096-bit | 137 | 40.4 s | 19.6 s | 544 kB |

Verification is cheaper than production, which is the right asymmetry for
evidence that many parties will check and one party will issue.

## Trust model

The verifier assumes the certificate is hostile. Every quantity in it is
recomputed or checked against a condition that a forger cannot satisfy without
solving the underlying problem. A tampered digest, a point off the curve, an
order outside the Hasse interval, a divisor below the size bound, a broken link,
a chain that never terminates in something proven — all are rejected with a
stated reason.

The design rule is **fail closed**: an unknown format, an unknown claim, an
unknown proof method or a missing proof yields `INVALID`. A verifier that
returns `VALID` for something it did not check is worse than no verifier,
because it converts an open question into a false answer.

## History, including the part that is unflattering

An earlier version of this verifier contained this line in the primality branch:

```python
return True, "probabilistic primality certificate (full ECPP proof on a PARI host)"
```

For any certificate whose method was not Pocklington, it returned **valid
without checking anything**. The issuing engine emitted exactly such
certificates whenever N-1 was not smooth. The bug was found by testing the
verifier against deliberately forged input rather than against expected input.

It is documented here because a verifier is only worth what its failure modes
are worth, and because anyone auditing this code would find it in five minutes
anyway. The current version fails closed in three places where it previously
rubber-stamped, and `selftest.py` contains a regression test for this exact case.

## Files

```
kp_verify.py     verifier and CLI, both certificate formats
ecpp.py          ECPP chain verification, elliptic curve arithmetic from scratch
selftest.py      genuine certificates accepted, ten forgery classes rejected
kp-verify.js     independent JavaScript implementation, browser and Node
verify.html      drop a certificate on the page, verified in your tab
test-node.js     the same test matrix against the JavaScript implementation
SPEC.md          KP-PROOF-1 certificate format
examples/        real certificates, 512 to 4096 bits
```

The Python side needs Python 3.8+ and `gmpy2`. The JavaScript side needs
nothing at all.

## Reimplementing this

You are encouraged to — there are two implementations here precisely because a
format is only as trustworthy as the number of people who can check it
independently. The `CLAIM_WEAK` check is ten lines in any language:
read `modulus_n` and `recovered_factor`, confirm the factor lies strictly
between 1 and n, confirm `n % factor == 0`. The ECPP check is longer but has no
hidden parts; `SPEC.md` states every condition. A second independent
implementation is the strongest thing that can happen to a format like this.

## License

MIT. See `LICENSE`.

## Contact
Piotr Burylo — pitbury222@gmail.com
