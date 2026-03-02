"""data_signer.py

BLS12-381 signing utilities using py_ecc.

Keys live on G1 (128-byte uncompressed points); signatures live on G2
(256-byte uncompressed points).  The domain separation tag matches the
standard BLS signature scheme: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import List

from py_ecc.optimized_bls12_381 import G1, multiply, add, curve_order, normalize, FQ2, neg
from py_ecc.optimized_bls12_381.optimized_pairing import pairing, final_exponentiate
from py_ecc.bls.hash_to_curve import hash_to_G2

DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _pack(n: int) -> bytes:
    """Encode an Fp integer as a 64-byte big-endian EIP-2537 field element."""
    return n.to_bytes(48, "big").rjust(64, b"\x00")


def _g2_from_bytes(sig_bytes: bytes):
    """Deserialise a 256-byte uncompressed G2 point into Jacobian form."""
    x = FQ2((int.from_bytes(sig_bytes[  0: 64], "big"),
             int.from_bytes(sig_bytes[ 64:128], "big")))
    y = FQ2((int.from_bytes(sig_bytes[128:192], "big"),
             int.from_bytes(sig_bytes[192:256], "big")))
    return (x, y, FQ2((1, 0)))


def _g2_to_bytes(pt) -> bytes:
    """Serialise a G2 point to 256 bytes (normalised affine, EIP-2537 layout)."""
    x, y = normalize(pt)
    x_re, x_im = x.coeffs
    y_re, y_im = y.coeffs
    return _pack(int(x_re)) + _pack(int(x_im)) + _pack(int(y_re)) + _pack(int(y_im))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_signature(pub_pt, msg: bytes, sig_bytes: bytes) -> bool:
    """Verify a single BLS signature.

    Args:
        pub_pt:    G1 public key point (Jacobian, from ``multiply(G1, sk)``).
        msg:       Original message bytes.
        sig_bytes: 256-byte uncompressed G2 signature.

    Returns True iff the signature is valid.
    """
    if len(sig_bytes) != 256:
        raise ValueError("signature must be 256 bytes")
    sig_pt  = _g2_from_bytes(sig_bytes)
    msg_pt  = hash_to_G2(msg, DST, hashlib.sha256)
    lhs = final_exponentiate(pairing(sig_pt, G1))
    rhs = final_exponentiate(pairing(msg_pt, pub_pt))
    return lhs == rhs


def verify_pop(pub_pt, pop_sig: bytes) -> bool:
    """Verify a proof-of-possession signature over b"BLS_POP"."""
    return verify_signature(pub_pt, b"BLS_POP", pop_sig)


def aggregate_signatures(sigs: List[bytes]) -> bytes:
    """Point-sum a list of G2 signatures into one aggregate signature.

    Args:
        sigs: List of 256-byte signatures from :meth:`Signer.sign`.

    Returns:
        256-byte aggregate signature.
    """
    if not sigs:
        raise ValueError("no signatures to aggregate")
    agg = _g2_from_bytes(sigs[0])
    for sig in sigs[1:]:
        agg = add(agg, _g2_from_bytes(sig))
    return _g2_to_bytes(agg)


@dataclass
class Signer:
    """A BLS12-381 key pair (secret scalar + derived G1 public key)."""

    secret: int

    @classmethod
    def generate(cls) -> Signer:
        """Generate a fresh key pair with a cryptographically random scalar."""
        return cls(secret=secrets.randbelow(curve_order - 1) + 1)

    def sign(self, msg: bytes) -> bytes:
        """Sign *msg* and return a 256-byte uncompressed G2 point."""
        msg_pt = hash_to_G2(msg, DST, hashlib.sha256)
        return _g2_to_bytes(multiply(msg_pt, self.secret))

    def make_pop(self) -> bytes:
        """Return a proof-of-possession (signature over b"BLS_POP")."""
        return self.sign(b"BLS_POP")

    def public_bytes(self) -> bytes:
        """Return the 128-byte uncompressed G1 public key."""
        x, y = normalize(multiply(G1, self.secret))
        return _pack(x.n) + _pack(y.n)


# ---------------------------------------------------------------------------
# Example / smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    signers = [Signer.generate() for _ in range(3)]
    msgs    = [b"hello", b"world", b"bls"]
    sigs    = [s.sign(m) for s, m in zip(signers, msgs)]
    pops    = [s.make_pop() for s in signers]
    agg     = aggregate_signatures(sigs)

    print(f"Aggregate signature: {agg.hex()}")
    for s, m, sig, pop in zip(signers, msgs, sigs, pops):
        pub_pt = multiply(G1, s.secret)
        print(f"  msg={m!r}  sig_valid={verify_signature(pub_pt, m, sig)}"
              f"  pop_valid={verify_pop(pub_pt, pop)}")
