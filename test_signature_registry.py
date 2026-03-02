"""test_signature_registry.py — Unit tests for signature_registry.vy.

Tests BLS key registration, single/aggregate signature verification,
proof-of-possession, and scheme metadata queries.
"""

import os

import pytest
from web3 import Web3

from data_signer import Signer, aggregate_signatures


# ===========================================================================
# Scheme metadata
# ===========================================================================

class TestSchemeMetadata:
    def test_scheme_id(self, registry):
        assert registry.functions.schemeId().call() == 2

    def test_scheme_name(self, registry):
        assert registry.functions.schemeName().call() == "BLS12-381"

    def test_pub_key_size(self, registry):
        assert registry.functions.pubKeySize().call() == 128

    def test_signature_size(self, registry):
        assert registry.functions.signatureSize().call() == 256

    def test_supports_aggregation(self, registry):
        assert registry.functions.supportsAggregation().call() is True


# ===========================================================================
# Key registration
# ===========================================================================

class TestKeyRegistration:
    def test_register_and_get_key(self, w3, registry, accounts):
        """Register a key and retrieve it."""
        signer = Signer.generate()
        acct = accounts[5]
        pub = signer.public_bytes()
        pop = signer.make_pop()

        registry.functions.register(pub, pop).transact({"from": acct})
        stored = registry.functions.getKey(acct).call()
        assert stored == pub

    def test_is_registered(self, w3, registry, accounts):
        """isRegistered returns True after registration."""
        signer = Signer.generate()
        acct = accounts[6]

        assert registry.functions.isRegistered(acct).call() is False
        registry.functions.register(
            signer.public_bytes(), signer.make_pop()
        ).transact({"from": acct})
        assert registry.functions.isRegistered(acct).call() is True

    def test_register_emits_event(self, w3, registry, accounts):
        """Registration emits KeyRegistered event."""
        signer = Signer.generate()
        acct = accounts[7]
        pub = signer.public_bytes()
        pop = signer.make_pop()

        receipt = w3.eth.wait_for_transaction_receipt(
            registry.functions.register(pub, pop).transact({"from": acct})
        )
        logs = registry.events.KeyRegistered().process_receipt(receipt)
        assert len(logs) == 1
        assert logs[0].args.owner == acct
        assert logs[0].args.pubKey == pub

    def test_invalid_pop_reverts(self, w3, registry, accounts):
        """Registration with wrong PoP should revert."""
        s1 = Signer.generate()
        s2 = Signer.generate()
        acct = accounts[8]

        with pytest.raises(Exception):
            registry.functions.register(
                s1.public_bytes(), s2.make_pop()
            ).transact({"from": acct})

    def test_invalid_key_length_reverts(self, w3, registry, accounts):
        """Key that isn't 128 bytes should revert."""
        signer = Signer.generate()
        acct = accounts[9]

        with pytest.raises(Exception):
            registry.functions.register(
                b"\x00" * 64, signer.make_pop()
            ).transact({"from": acct})

    def test_unregistered_key_is_empty(self, registry):
        """Unregistered address returns empty bytes."""
        addr = Web3.to_checksum_address("0x" + "00" * 20)
        key = registry.functions.getKey(addr).call()
        assert key == b""


# ===========================================================================
# Single signature verification
# ===========================================================================

class TestSingleVerification:
    def test_verify_valid_signature(self, registry, registered_signers):
        """Verify a valid BLS signature with an explicit key."""
        signers_list, _ = registered_signers
        signer = signers_list[0]
        msg = b"verify me"
        sig = signer.sign(msg)
        pub = signer.public_bytes()

        result = registry.functions.verify(pub, msg, sig).call()
        assert result is True

    def test_verify_wrong_message_rejects(self, registry, registered_signers):
        """Wrong message should fail verification."""
        signers_list, _ = registered_signers
        signer = signers_list[0]
        sig = signer.sign(b"correct")
        pub = signer.public_bytes()

        result = registry.functions.verify(pub, b"wrong", sig).call()
        assert result is False

    def test_verify_with_registered_key(self, registry, registered_signers):
        """Verify using the registered key via verifyWithRegisteredKey."""
        signers_list, accts = registered_signers
        signer = signers_list[0]
        msg = b"registered key test"
        sig = signer.sign(msg)

        result = registry.functions.verifyWithRegisteredKey(
            accts[0], msg, sig
        ).call()
        assert result is True

    def test_verify_unregistered_owner_reverts(self, registry):
        """Verifying with unregistered owner should revert."""
        fake_addr = Web3.to_checksum_address("0x" + "ab" * 20)
        with pytest.raises(Exception):
            registry.functions.verifyWithRegisteredKey(
                fake_addr, b"test", b"\x00" * 256
            ).call()


# ===========================================================================
# Aggregate signature verification
# ===========================================================================

class TestAggregateVerification:
    def test_verify_aggregated_valid(self, registry, registered_signers):
        """Valid aggregate signature should pass."""
        signers_list, accts = registered_signers
        messages = [b"msg0", b"msg1", b"msg2"]
        sigs = [s.sign(m) for s, m in zip(signers_list, messages)]
        agg = aggregate_signatures(sigs)

        result = registry.functions.verifyAggregated(
            list(accts), messages, agg
        ).call()
        assert result is True

    def test_verify_aggregated_wrong_sig(self, registry, registered_signers):
        """Bit-flipped aggregate signature should fail."""
        signers_list, accts = registered_signers
        messages = [b"msg0", b"msg1", b"msg2"]
        sigs = [s.sign(m) for s, m in zip(signers_list, messages)]
        agg = aggregate_signatures(sigs)

        bad_sig = bytes([agg[0] ^ 0xFF]) + agg[1:]
        try:
            result = registry.functions.verifyAggregated(
                list(accts), messages, bad_sig
            ).call()
        except Exception:
            result = False
        assert result is False

    def test_verify_aggregated_wrong_messages(self, registry, registered_signers):
        """Wrong messages should fail verification."""
        signers_list, accts = registered_signers
        messages = [b"msg0", b"msg1", b"msg2"]
        sigs = [s.sign(m) for s, m in zip(signers_list, messages)]
        agg = aggregate_signatures(sigs)

        wrong = [b"wrong"] + messages[1:]
        try:
            result = registry.functions.verifyAggregated(
                list(accts), wrong, agg
            ).call()
        except Exception:
            result = False
        assert result is False

    def test_verify_aggregated_empty_reverts(self, registry):
        """Empty owner list should revert."""
        with pytest.raises(Exception):
            registry.functions.verifyAggregated(
                [], [], b"\x00" * 256
            ).call()

    def test_verify_aggregated_length_mismatch_reverts(
        self, registry, registered_signers
    ):
        """Mismatched owner/message lengths should revert."""
        _, accts = registered_signers
        with pytest.raises(Exception):
            registry.functions.verifyAggregated(
                list(accts), [b"only one"], b"\x00" * 256
            ).call()


# ===========================================================================
# hash_to_g2 public accessor
# ===========================================================================

class TestHashToG2:
    def test_hash_to_g2_returns_256_bytes(self, registry):
        """Public hash_to_g2 should return a 256-byte G2 point."""
        result = registry.functions.hash_to_g2(
            b"test message",
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
        ).call()
        assert len(result) == 256

    def test_hash_to_g2_deterministic(self, registry):
        """Same input should produce same output."""
        msg = b"deterministic test"
        dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
        r1 = registry.functions.hash_to_g2(msg, dst).call()
        r2 = registry.functions.hash_to_g2(msg, dst).call()
        assert r1 == r2

    def test_hash_to_g2_different_inputs(self, registry):
        """Different messages should produce different G2 points."""
        dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
        r1 = registry.functions.hash_to_g2(b"msg1", dst).call()
        r2 = registry.functions.hash_to_g2(b"msg2", dst).call()
        assert r1 != r2
