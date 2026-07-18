#!/usr/bin/env python3
"""
RFC 6979 nonce-compliance check for Bitcoin ECDSA signatures
------------------------------------------------------------
A sanitized, self-contained sample from my Bitcoin puzzle forensic study.

Forensic question it answers:
    "Given a signature and a KNOWN private key, was the nonce (k) generated
     deterministically per RFC 6979, or with an external RNG?"

Why it matters:
    A signer using a weak/reused/biased RNG for k leaks the private key.
    A signer that is RFC 6979-compliant does not. Establishing which one you
    are looking at is the first gate of any ECDSA key-recovery investigation.

This file implements secp256k1 and RFC 6979 from scratch (no ECDSA library),
so the method is fully auditable. Run it directly:  python sample_rfc6979_verify.py

Author: M. Fadel  |  self-contained demo, safe to share
"""

import hashlib
import hmac

# ── secp256k1 domain parameters ───────────────────────────────────────────────
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)


# ── minimal elliptic-curve arithmetic over secp256k1 ──────────────────────────
def inv(a, m):
    return pow(a, -1, m)

def ec_add(pt_a, pt_b):
    if pt_a is None:
        return pt_b
    if pt_b is None:
        return pt_a
    (x1, y1), (x2, y2) = pt_a, pt_b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if pt_a == pt_b:
        lam = (3 * x1 * x1) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def ec_mul(k, pt):
    result, addend = None, pt
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result


# ── RFC 6979 deterministic nonce (HMAC-SHA256) ────────────────────────────────
def rfc6979_k(priv, z):
    """Return the deterministic nonce k that RFC 6979 mandates for (priv, z)."""
    x = priv.to_bytes(32, "big")
    z_oct = (z % N).to_bytes(32, "big")          # bits2octets(hash)
    k_mac = b"\x00" * 32
    v_mac = b"\x01" * 32
    mac = lambda key, data: hmac.new(key, data, hashlib.sha256).digest()
    k_mac = mac(k_mac, v_mac + b"\x00" + x + z_oct)
    v_mac = mac(k_mac, v_mac)
    k_mac = mac(k_mac, v_mac + b"\x01" + x + z_oct)
    v_mac = mac(k_mac, v_mac)
    while True:
        v_mac = mac(k_mac, v_mac)
        cand = int.from_bytes(v_mac, "big")
        if 1 <= cand < N:
            return cand
        k_mac = mac(k_mac, v_mac + b"\x00")
        v_mac = mac(k_mac, v_mac)


# ── ECDSA sign + the forensic nonce-recovery / compliance check ───────────────
def sign(priv, z, k):
    """Produce (r, s) for message hash z under private key priv using nonce k."""
    r = ec_mul(k, G)[0] % N
    s = inv(k, N) * (z + r * priv) % N
    return r, min(s, N - s)                        # low-s (BIP 62), like Bitcoin Core

def recover_nonce(r, s, z, priv):
    """With the private key known, back out the nonce k used to sign."""
    k = inv(s, N) * (z + r * priv) % N
    return min_k_for_r(r, k, z, priv)

def min_k_for_r(r, k, z, priv):
    # low-s normalisation means the on-chain s may correspond to k or N-k;
    # return whichever nonce actually reproduces r.
    if ec_mul(k, G)[0] % N == r:
        return k
    return (N - k) % N

def is_rfc6979_compliant(r, s, z, priv):
    """The core check: does the recovered nonce equal the RFC 6979 nonce?"""
    recovered = recover_nonce(r, s, z, priv)
    mandated  = rfc6979_k(priv, z)
    return recovered == mandated, recovered, mandated


# ── demonstration ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    priv = 0x1a838b13505b26867            # a sample key (secp256k1 scalar)
    z    = int.from_bytes(hashlib.sha256(b"forensics demo message").digest(), "big")

    print("=" * 62)
    print(" RFC 6979 compliance check — worked example")
    print("=" * 62)

    # Case A: a well-behaved (deterministic) signer, as in the puzzle TXs.
    k_good = rfc6979_k(priv, z)
    r, s = sign(priv, z, k_good)
    ok, rec, mand = is_rfc6979_compliant(r, s, z, priv)
    print(f"\n[A] Deterministic signer")
    print(f"    recovered k : {rec:#066x}")
    print(f"    RFC6979  k  : {mand:#066x}")
    print(f"    verdict     : {'RFC 6979 COMPLIANT — nonce is safe' if ok else 'NON-COMPLIANT'}")

    # Case B: a reckless signer that picked k with an external RNG.
    k_bad = 0xC0FFEE0000000000000000000000000000000000000000000000000000000001
    r2, s2 = sign(priv, z, k_bad)
    ok2, rec2, mand2 = is_rfc6979_compliant(r2, s2, z, priv)
    print(f"\n[B] External-RNG signer")
    print(f"    recovered k : {rec2:#066x}")
    print(f"    RFC6979  k  : {mand2:#066x}")
    print(f"    verdict     : {'compliant' if ok2 else 'NON-COMPLIANT — investigate for RNG weakness / reuse'}")
    print()
