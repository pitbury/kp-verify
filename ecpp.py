"""
Independent verification of ECPP (Atkin-Goldwasser-Kilian / Atkin-Morain)
primality certificate chains.

This module verifies a chain WITHOUT trusting whoever produced it. Elliptic
curve arithmetic is implemented here from scratch; no cryptographic library is
consulted for the decision.

Each link proves N prime, given that a smaller q is prime:

    given:  N, a, b   defining E: y^2 = x^3 + a*x + b  (mod N)
            P = (x, y) a point claimed to be on E
            m           the claimed order of E
            q           a large divisor of m

    checks: 1. N > 1 and has no small factors
            2. P lies on E
            3. |m - (N+1)| <= 2*sqrt(N)          (Hasse bound)
            4. q divides m
            5. q > (N^(1/4) + 1)^2               (size condition)
            6. m*P = O
            7. (m/q)*P != O
            8. q is prime — recursively, via the next link

CHAIN CLOSURE
    A chain is only a proof if it terminates in something proven. This module
    accepts termination in exactly two ways:

        (a) the final q < 2^64, where the Baillie-PSW test is deterministic
            (exhaustively verified below 2^64, no counterexample known), or
        (b) the certificate carries a `tail` field holding a Pocklington proof
            of the final q, which is checked here as well.

    Anything else is rejected. A chain that merely ends in a probable prime is
    not a proof and this module will not say that it is.

Copyright (c) 2026 RECHECK Piotr Burylo. MIT License.
"""
import gmpy2
from gmpy2 import mpz, gcd, isqrt, invert

__all__ = ["verify_chain", "verify_link", "ECPPError", "BPSW_DETERMINISTIC_LIMIT"]


class ECPPError(Exception):
    """Raised when a certificate fails verification. The message states why."""


# Below this bound Baillie-PSW is a proof, not a probabilistic test.
BPSW_DETERMINISTIC_LIMIT = mpz(1) << 64

INF = None  # point at infinity


# --------------------------- elliptic curve over Z/N ---------------------------

def point_on_curve(N, a, b, P):
    if P is INF:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % N == 0


def ec_add(N, a, P, Q):
    """Affine addition on y^2 = x^3 + a*x + b over Z/N.

    A non-invertible denominator means N is composite and yields a factor;
    that is reported as a verification failure rather than silently ignored.
    """
    if P is INF:
        return Q
    if Q is INF:
        return P
    x1, y1 = P
    x2, y2 = Q
    if (x1 - x2) % N == 0 and (y1 + y2) % N == 0:
        return INF
    if (x1 - x2) % N == 0 and (y1 - y2) % N == 0:
        den = (2 * y1) % N
        g = gcd(den, N)
        if g != 1:
            raise ECPPError(f"non-invertible {g} while doubling: N is composite")
        lam = ((3 * x1 * x1 + a) * invert(den, N)) % N
    else:
        den = (x2 - x1) % N
        g = gcd(den, N)
        if g != 1:
            raise ECPPError(f"non-invertible {g} while adding: N is composite")
        lam = ((y2 - y1) * invert(den, N)) % N
    x3 = (lam * lam - x1 - x2) % N
    y3 = (lam * (x1 - x3) - y1) % N
    return (x3, y3)


def ec_mul(N, a, k, P):
    R = INF
    Q = P
    k = int(k)
    if k < 0:
        raise ECPPError("negative scalar")
    while k > 0:
        if k & 1:
            R = ec_add(N, a, R, Q)
        Q = ec_add(N, a, Q, Q)
        k >>= 1
    return R


# --------------------------------- one link ---------------------------------

def verify_link(N, a, b, x, y, m, q):
    """Verify a single link. Returns True or raises ECPPError explaining why not."""
    N = mpz(N)
    a = mpz(a) % N
    b = mpz(b) % N
    x = mpz(x) % N
    y = mpz(y) % N
    m = mpz(m)
    q = mpz(q)

    if N <= 1:
        raise ECPPError("N <= 1")
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
        if N % sp == 0 and N != sp:
            raise ECPPError(f"N is divisible by {sp}")
    if m <= 0 or q <= 1:
        raise ECPPError("m or q out of range")

    d = m - (N + 1)
    if d * d > 4 * N:
        raise ECPPError("claimed order m violates the Hasse bound")

    P = (x, y)
    if not point_on_curve(N, a, b, P):
        raise ECPPError("point does not lie on the curve")
    if m % q != 0:
        raise ECPPError("q does not divide m")

    r = isqrt(isqrt(N))
    if not q > (r + 1) * (r + 1):
        raise ECPPError("size condition fails: q <= (N^(1/4) + 1)^2")

    if ec_mul(N, a, m, P) is not INF:
        raise ECPPError("m*P != O")
    if ec_mul(N, a, m // q, P) is INF:
        raise ECPPError("(m/q)*P == O, expected != O")
    return True


# ------------------------------- chain closure -------------------------------

def verify_pocklington_tail(q, tail):
    """Verify a Pocklington proof closing the chain at a final q >= 2^64.

    tail = {"F": str, "factors_F": [str, ...], "witness_a": str}
    """
    q = mpz(q)
    try:
        F = mpz(tail["F"])
        factors = [mpz(f) for f in tail["factors_F"]]
        a = mpz(tail["witness_a"])
    except (KeyError, TypeError, ValueError):
        raise ECPPError("tail: missing F / factors_F / witness_a")

    if F * F <= q:
        raise ECPPError("tail: F^2 <= q, Pocklington proof incomplete")
    if (q - 1) % F != 0:
        raise ECPPError("tail: F does not divide q-1")
    if pow(a, q - 1, q) != 1:
        raise ECPPError("tail: witness fails a^(q-1) = 1")
    for f in factors:
        if F % f != 0:
            raise ECPPError(f"tail: {f} does not divide F")
        if not gmpy2.is_prime(f, 40):
            raise ECPPError(f"tail: claimed factor {f} is not prime")
        if gcd(pow(a, (q - 1) // f, q) - 1, q) != 1:
            raise ECPPError(f"tail: Pocklington condition fails for f={f}")
    return True


def verify_chain(chain, claimed_N=None, tail=None):
    """Verify a full ECPP chain.

    chain      list of links, each {"N","a","b","x","y","m","q"}, descending
    claimed_N  if given, the first link must concern exactly this number
    tail       optional Pocklington proof closing a final q >= 2^64

    Fails closed: an empty chain or an unclosed tail is rejected.
    """
    if not chain:
        raise ECPPError("empty chain: nothing is proven")
    if claimed_N is not None and mpz(chain[0]["N"]) != mpz(claimed_N):
        raise ECPPError("first link does not concern the claimed N")

    for i, link in enumerate(chain):
        verify_link(link["N"], link["a"], link["b"], link["x"], link["y"],
                    link["m"], link["q"])
        q = mpz(link["q"])
        if i + 1 < len(chain):
            if q != mpz(chain[i + 1]["N"]):
                raise ECPPError(f"chain broken: q of link {i} != N of link {i+1}")
            if mpz(chain[i + 1]["N"]) >= mpz(link["N"]):
                raise ECPPError(f"chain does not decrease at link {i}")
        else:
            if q < BPSW_DETERMINISTIC_LIMIT:
                if not gmpy2.is_prime(q, 40):
                    raise ECPPError("final q is not prime")
            elif tail is not None:
                verify_pocklington_tail(q, tail)
            else:
                raise ECPPError(
                    f"chain is not closed: final q has {q.bit_length()} bits "
                    f"(>= 2^64) and no Pocklington proof is present in 'tail'")
    return True
