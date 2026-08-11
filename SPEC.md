# KP-PROOF-1 — certificate format

A certificate is a single JSON object. Its validity is decidable from the object
alone. Every condition below is checked by `kp_verify.py`; nothing is checked
elsewhere.

## Common fields

| field | type | meaning |
|---|---|---|
| `format` | string | `"KP-PROOF-1"` |
| `claim` | string | one of the four claims below |
| `verdict` | string | outcome, claim-specific |
| `sha256` | hex string | integrity digest, see below |

Large integers are carried as **decimal strings**, not JSON numbers, to avoid
precision loss in parsers that use doubles. Integers inside an ECPP chain are
JSON integers.

> **Implementers, read this.** The chain integers are ordinary JSON numbers and
> routinely exceed 2^53. A parser that maps them to IEEE doubles — which is what
> `JSON.parse`, and many other stock parsers, do — silently destroys them: the
> digest will never match and the curve arithmetic becomes meaningless. Use a
> parser that yields arbitrary-precision integers. The JavaScript
> implementation in this repository ships a small one for exactly this reason.
>
> This is a wart in version 1 of the format. Carrying chain integers as strings,
> like every other integer field, would have avoided it. Changing it now would
> invalidate certificates already issued, so version 1 keeps the behaviour and
> states it plainly instead.

### Digest

```
sha256 = SHA-256( JSON( certificate without the "sha256" key,
                        keys sorted, compact separators ) )
```

Reference implementation:

```python
body = {k: v for k, v in cert.items() if k != "sha256"}
hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
```

The digest detects accidental corruption and naive tampering. It is **not** a
signature and proves nothing about origin. A competent forger recomputes it —
which is why every substantive check below is independent of the digest.

## CLAIM_PRIME

Statement: *N is prime.*

| field | meaning |
|---|---|
| `N` | the number, decimal string |
| `verdict` | `PRIME`, or `NOT_PRIME` |
| `method` | `ECPP` or `Pocklington` |

Any other value of `method` is rejected. There is no fallback to a
probabilistic test.

### method = Pocklington

| field | meaning |
|---|---|
| `F` | fully factored part of N-1, decimal string |
| `factors_F` | prime factors of F, decimal strings |
| `witness_a` | witness a |

Conditions, all required:

1. `F^2 > N`
2. `F` divides `N-1`
3. `a^(N-1) = 1 (mod N)`
4. every `q` in `factors_F` divides `F` and is itself prime
5. `gcd(a^((N-1)/q) - 1, N) = 1` for every such `q`

### method = ECPP

| field | meaning |
|---|---|
| `ecpp_chain` | array of links, descending in N |
| `tail` | optional Pocklington proof of the final q |

Each link is an object:

```json
{"N": ..., "a": ..., "b": ..., "x": ..., "y": ..., "m": ..., "q": ...}
```

defining the curve `E: y^2 = x^3 + a*x + b (mod N)` and a point `P = (x, y)`.

Conditions per link:

1. `N > 1`, not divisible by any prime below 50
2. `P` lies on `E`
3. `|m - (N+1)| <= 2*sqrt(N)` — Hasse bound
4. `q` divides `m`
5. `q > (N^(1/4) + 1)^2` — size condition
6. `m*P = O`
7. `(m/q)*P != O`

Conditions on the chain:

8. if `claimed_N` is supplied, link 0 concerns exactly that N
9. `q` of link *i* equals `N` of link *i+1*
10. `N` strictly decreases along the chain
11. the chain is **closed**: either the final `q < 2^64` and passes Baillie-PSW
    (deterministic in that range), or `tail` carries a Pocklington proof of the
    final `q`, verified by the rules above

An empty chain is rejected. An unclosed chain is rejected. Condition 11 is the
one most often omitted by implementations, and omitting it means the artefact is
not a proof.

## CLAIM_PARAMS

Statement: *p is a safe prime, p = 2q+1, and both p and q are prime.*

| field | meaning |
|---|---|
| `p`, `q` | decimal strings |
| `proof_p`, `proof_q` | optional nested `CLAIM_PRIME` certificates |

Conditions:

1. `p = 2q + 1`
2. if `proof_p` / `proof_q` are present, each must concern the matching number
   and verify as a `CLAIM_PRIME` certificate
3. if absent, primality falls back to Baillie-PSW and the result is reported as
   **probabilistic**; `--strict` rejects it

## CLAIM_WEAK

Statement: *this RSA modulus is defective.*

| field | meaning |
|---|---|
| `modulus_n` | decimal string |
| `verdict` | `WEAK` or `STRONG` |
| `recovered_factor` | decimal string, when a factor was recovered |

Conditions: `1 < factor < n` and `n % factor == 0`.

If `verdict` is `WEAK` but no factor is present — a fingerprint match such as
ROCA, where the defect is recognised but not exploited — the certificate is
reported as intact and explicitly **carrying no proof**.

## CLAIM_HARDENED

Statement: *this key resisted a suite of structural attacks.*

| field | meaning |
|---|---|
| `attacks_repelled` | object: attack name to `true` |
| `verdict` | `HARDENED` |

Only internal consistency is checked. This claim is **not a proof** and is
rejected under `--strict`. Legacy issuers emit the string `"repelled"` instead
of `true`; both are accepted.

## KP-AUDIT-CERT-1

A narrower, older format carrying only an RSA audit verdict: `modulus_n`,
`verdict` (`WEAK` / `STRONG`), optional `recovered_factor`, `sha256`. The same
factor check applies. An unrecognised verdict is rejected.

## History

Version 1 of the verifier returned *valid* for `CLAIM_PRIME` whenever `method`
was neither `Pocklington` nor recognised, with a message describing the result
as "probabilistic". No condition was checked in that branch. Certificates with
`method: "ECPP_REQUIRED"` — emitted whenever N-1 was not smooth — were therefore
stamped valid without evidence.

A second defect, found while writing the JavaScript implementation: chain
integers are JSON numbers and any parser using doubles corrupts them. Documented
above rather than silently patched.

Current behaviour: any unrecognised `method` is rejected. `selftest.py` carries
a regression test for this case. Certificates issued by older tooling with
`method: "ECPP_REQUIRED"` now read as `INVALID`, which is the correct reading.
