"""test_data_signer.py — Unit tests for data_signer.py.

Tests BLS12-381 key generation, signing, verification, proof-of-possession,
and aggregate signatures.
"""

import os

import pytest
from py_ecc.optimized_bls12_381 import G1, multiply, curve_order, normalize

from data_signer import (
    Signer,
    verify_signature,
    verify_pop,
    aggregate_signatures,
    _pack,
    _g2_from_bytes,
    _g2_to_bytes,
    DST,
)


# ===========================================================================
# Signer generation
# ===========================================================================

class TestSignerGeneration:
    def test_generate_returns_signer(self):
        s = Signer.generate()
        assert isinstance(s, Signer)

    def test_secret_in_valid_range(self):
        s = Signer.generate()
        assert 1 <= s.secret < curve_order

    def test_different_signers_have_different_secrets(self):
        s1 = Signer.generate()
        s2 = Signer.generate()
        assert s1.secret != s2.secret

    def test_public_bytes_length(self):
        s = Signer.generate()
        assert len(s.public_bytes()) == 128

    def test_public_bytes_deterministic(self):
        s = Signer.generate()
        assert s.public_bytes() == s.public_bytes()

    def test_different_signers_have_different_pubkeys(self):
        s1 = Signer.generate()
        s2 = Signer.generate()
        assert s1.public_bytes() != s2.public_bytes()


# ===========================================================================
# Signing
# ===========================================================================

class TestSigning:
    def test_sign_returns_256_bytes(self):
        s = Signer.generate()
        sig = s.sign(b"hello")
        assert len(sig) == 256

    def test_sign_deterministic(self):
        s = Signer.generate()
        sig1 = s.sign(b"hello")
        sig2 = s.sign(b"hello")
        assert sig1 == sig2

    def test_different_messages_different_sigs(self):
        s = Signer.generate()
        sig1 = s.sign(b"hello")
        sig2 = s.sign(b"world")
        assert sig1 != sig2

    def test_different_signers_different_sigs(self):
        s1 = Signer.generate()
        s2 = Signer.generate()
        sig1 = s1.sign(b"hello")
        sig2 = s2.sign(b"hello")
        assert sig1 != sig2

    def test_sign_empty_message(self):
        s = Signer.generate()
        sig = s.sign(b"")
        assert len(sig) == 256

    def test_sign_large_message(self):
        s = Signer.generate()
        sig = s.sign(os.urandom(1024))
        assert len(sig) == 256


# ===========================================================================
# Verification
# ===========================================================================

class TestVerification:
    def test_valid_signature_verifies(self):
        s = Signer.generate()
        msg = b"hello world"
        sig = s.sign(msg)
        pub_pt = multiply(G1, s.secret)
        assert verify_signature(pub_pt, msg, sig) is True

    def test_wrong_message_rejects(self):
        s = Signer.generate()
        sig = s.sign(b"hello")
        pub_pt = multiply(G1, s.secret)
        assert verify_signature(pub_pt, b"wrong", sig) is False

    def test_wrong_key_rejects(self):
        s1 = Signer.generate()
        s2 = Signer.generate()
        sig = s1.sign(b"hello")
        pub_pt2 = multiply(G1, s2.secret)
        assert verify_signature(pub_pt2, b"hello", sig) is False

    def test_invalid_sig_length_raises(self):
        s = Signer.generate()
        pub_pt = multiply(G1, s.secret)
        with pytest.raises(ValueError, match="256 bytes"):
            verify_signature(pub_pt, b"hello", b"\x00" * 128)

    def test_empty_message_verifies(self):
        s = Signer.generate()
        sig = s.sign(b"")
        pub_pt = multiply(G1, s.secret)
        assert verify_signature(pub_pt, b"", sig) is True


# ===========================================================================
# Proof of possession
# ===========================================================================

class TestProofOfPossession:
    def test_valid_pop_verifies(self):
        s = Signer.generate()
        pop = s.make_pop()
        pub_pt = multiply(G1, s.secret)
        assert verify_pop(pub_pt, pop) is True

    def test_pop_is_signature_over_bls_pop(self):
        s = Signer.generate()
        pop = s.make_pop()
        sig = s.sign(b"BLS_POP")
        assert pop == sig

    def test_pop_wrong_key_rejects(self):
        s1 = Signer.generate()
        s2 = Signer.generate()
        pop = s1.make_pop()
        pub_pt2 = multiply(G1, s2.secret)
        assert verify_pop(pub_pt2, pop) is False

    def test_pop_length(self):
        s = Signer.generate()
        pop = s.make_pop()
        assert len(pop) == 256


# ===========================================================================
# Aggregate signatures
# ===========================================================================

class TestAggregateSignatures:
    def test_aggregate_single(self):
        s = Signer.generate()
        sig = s.sign(b"hello")
        agg = aggregate_signatures([sig])
        assert len(agg) == 256

    def test_aggregate_multiple(self):
        signers = [Signer.generate() for _ in range(3)]
        msgs = [b"hello", b"world", b"test"]
        sigs = [s.sign(m) for s, m in zip(signers, msgs)]
        agg = aggregate_signatures(sigs)
        assert len(agg) == 256

    def test_aggregate_empty_raises(self):
        with pytest.raises(ValueError, match="no signatures"):
            aggregate_signatures([])

    def test_aggregate_order_matters(self):
        """Aggregation is commutative for G2 addition, but test for consistency."""
        signers = [Signer.generate() for _ in range(2)]
        msgs = [b"a", b"b"]
        sigs = [s.sign(m) for s, m in zip(signers, msgs)]
        agg1 = aggregate_signatures(sigs)
        agg2 = aggregate_signatures(list(reversed(sigs)))
        # G2 addition is commutative
        assert agg1 == agg2

    def test_aggregate_deterministic(self):
        s = Signer.generate()
        sigs = [s.sign(b"hello"), s.sign(b"world")]
        agg1 = aggregate_signatures(sigs)
        agg2 = aggregate_signatures(sigs)
        assert agg1 == agg2


# ===========================================================================
# Internal helpers
# ===========================================================================

class TestInternalHelpers:
    def test_pack_field_element(self):
        result = _pack(42)
        assert len(result) == 64
        assert result[:16] == b"\x00" * 16
        assert int.from_bytes(result, "big") == 42

    def test_g2_roundtrip(self):
        """Serialize then deserialize a G2 point."""
        s = Signer.generate()
        sig = s.sign(b"test")
        pt = _g2_from_bytes(sig)
        roundtrip = _g2_to_bytes(pt)
        assert roundtrip == sig
