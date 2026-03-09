"""test_data_signer.py — Tests for BLS12-381 signing utilities.

Tests Signer class, signature verification, proof-of-possession,
and aggregate signature operations.
"""

import pytest
from py_ecc.optimized_bls12_381 import G1, multiply, curve_order

from data_signer import (
    Signer,
    verify_signature,
    verify_pop,
    aggregate_signatures,
    _g2_to_bytes,
    _g2_from_bytes,
)


class TestSignerGeneration:
    def test_generate_creates_valid_key(self):
        signer = Signer.generate()
        assert 1 <= signer.secret < curve_order

    def test_generate_unique_keys(self):
        s1 = Signer.generate()
        s2 = Signer.generate()
        assert s1.secret != s2.secret

    def test_public_bytes_length(self):
        signer = Signer.generate()
        pub = signer.public_bytes()
        assert len(pub) == 128

    def test_public_bytes_deterministic(self):
        signer = Signer.generate()
        assert signer.public_bytes() == signer.public_bytes()


class TestSigning:
    def test_sign_produces_256_bytes(self):
        signer = Signer.generate()
        sig = signer.sign(b"test")
        assert len(sig) == 256

    def test_sign_deterministic(self):
        signer = Signer.generate()
        assert signer.sign(b"msg") == signer.sign(b"msg")

    def test_different_messages_different_sigs(self):
        signer = Signer.generate()
        s1 = signer.sign(b"hello")
        s2 = signer.sign(b"world")
        assert s1 != s2

    def test_different_signers_different_sigs(self):
        s1 = Signer.generate()
        s2 = Signer.generate()
        sig1 = s1.sign(b"same message")
        sig2 = s2.sign(b"same message")
        assert sig1 != sig2


class TestVerification:
    def test_valid_signature_verifies(self):
        signer = Signer.generate()
        msg = b"hello world"
        sig = signer.sign(msg)
        pub_pt = multiply(G1, signer.secret)
        assert verify_signature(pub_pt, msg, sig) is True

    def test_wrong_message_fails(self):
        signer = Signer.generate()
        sig = signer.sign(b"hello")
        pub_pt = multiply(G1, signer.secret)
        assert verify_signature(pub_pt, b"wrong", sig) is False

    def test_wrong_key_fails(self):
        s1 = Signer.generate()
        s2 = Signer.generate()
        sig = s1.sign(b"hello")
        pub_pt = multiply(G1, s2.secret)
        assert verify_signature(pub_pt, b"hello", sig) is False

    def test_invalid_sig_length_raises(self):
        signer = Signer.generate()
        pub_pt = multiply(G1, signer.secret)
        with pytest.raises(ValueError, match="256 bytes"):
            verify_signature(pub_pt, b"test", b"\x00" * 128)

    def test_empty_message(self):
        signer = Signer.generate()
        sig = signer.sign(b"")
        pub_pt = multiply(G1, signer.secret)
        assert verify_signature(pub_pt, b"", sig) is True

    def test_binary_message(self):
        import os
        signer = Signer.generate()
        msg = os.urandom(100)
        sig = signer.sign(msg)
        pub_pt = multiply(G1, signer.secret)
        assert verify_signature(pub_pt, msg, sig) is True


class TestProofOfPossession:
    def test_valid_pop(self):
        signer = Signer.generate()
        pop = signer.make_pop()
        pub_pt = multiply(G1, signer.secret)
        assert verify_pop(pub_pt, pop) is True

    def test_pop_is_sig_over_bls_pop(self):
        signer = Signer.generate()
        pop = signer.make_pop()
        sig = signer.sign(b"BLS_POP")
        assert pop == sig

    def test_wrong_key_pop_fails(self):
        s1 = Signer.generate()
        s2 = Signer.generate()
        pop = s1.make_pop()
        pub_pt = multiply(G1, s2.secret)
        assert verify_pop(pub_pt, pop) is False

    def test_pop_length(self):
        signer = Signer.generate()
        pop = signer.make_pop()
        assert len(pop) == 256


class TestAggregateSignatures:
    def test_aggregate_single(self):
        signer = Signer.generate()
        sig = signer.sign(b"msg")
        agg = aggregate_signatures([sig])
        assert len(agg) == 256

    def test_aggregate_multiple(self):
        signers = [Signer.generate() for _ in range(3)]
        msgs = [b"msg1", b"msg2", b"msg3"]
        sigs = [s.sign(m) for s, m in zip(signers, msgs)]
        agg = aggregate_signatures(sigs)
        assert len(agg) == 256

    def test_aggregate_empty_raises(self):
        with pytest.raises(ValueError, match="no signatures"):
            aggregate_signatures([])

    def test_aggregate_deterministic(self):
        signers = [Signer.generate() for _ in range(2)]
        msgs = [b"a", b"b"]
        sigs = [s.sign(m) for s, m in zip(signers, msgs)]
        assert aggregate_signatures(sigs) == aggregate_signatures(sigs)


class TestG2RoundTrip:
    def test_serialize_deserialize_identity(self):
        """G2 point should survive round-trip through bytes."""
        signer = Signer.generate()
        sig = signer.sign(b"test")
        pt = _g2_from_bytes(sig)
        roundtripped = _g2_to_bytes(pt)
        assert roundtripped == sig

    def test_multiple_points(self):
        for _ in range(3):
            signer = Signer.generate()
            sig = signer.sign(b"round-trip test")
            pt = _g2_from_bytes(sig)
            assert _g2_to_bytes(pt) == sig
