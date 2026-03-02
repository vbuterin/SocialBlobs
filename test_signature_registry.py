"""test_signature_registry.py — Tests for BLS12-381 signature registry.

Tests registration, proof-of-possession, single/aggregate verification,
key rotation, and scheme metadata.
"""

import pytest
from web3 import Web3

from data_signer import Signer, aggregate_signatures


# ── Scheme metadata ─────────────────────────────────────────────────────────


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


# ── Registration ────────────────────────────────────────────────────────────


class TestRegistration:
    def test_register_new_key(self, w3, registry, accounts):
        signer = Signer.generate()
        acct = accounts[1]
        tx = registry.functions.register(
            signer.public_bytes(), signer.make_pop()
        ).transact({"from": acct})
        w3.eth.wait_for_transaction_receipt(tx)

        assert registry.functions.isRegistered(acct).call() is True
        assert registry.functions.getKey(acct).call() == signer.public_bytes()

    def test_register_emits_event(self, w3, registry, accounts):
        signer = Signer.generate()
        acct = accounts[2]
        tx = registry.functions.register(
            signer.public_bytes(), signer.make_pop()
        ).transact({"from": acct})
        receipt = w3.eth.wait_for_transaction_receipt(tx)
        logs = registry.events.KeyRegistered().process_receipt(receipt)
        assert len(logs) == 1
        assert logs[0].args.owner == acct
        assert logs[0].args.pubKey == signer.public_bytes()

    def test_invalid_pop_reverts(self, w3, registry, accounts):
        s1 = Signer.generate()
        s2 = Signer.generate()
        with pytest.raises(Exception):
            registry.functions.register(
                s1.public_bytes(), s2.make_pop()  # wrong PoP
            ).transact({"from": accounts[3]})

    def test_invalid_key_length_reverts(self, w3, registry, accounts):
        signer = Signer.generate()
        with pytest.raises(Exception):
            registry.functions.register(
                b"\x00" * 64,  # wrong length
                signer.make_pop(),
            ).transact({"from": accounts[3]})

    def test_key_rotation(self, w3, registry, accounts):
        """Re-registering should update the key without overcounting."""
        acct = accounts[4]
        s1 = Signer.generate()
        s2 = Signer.generate()

        # Register first key
        tx = registry.functions.register(
            s1.public_bytes(), s1.make_pop()
        ).transact({"from": acct})
        w3.eth.wait_for_transaction_receipt(tx)
        assert registry.functions.getKey(acct).call() == s1.public_bytes()

        # Rotate to second key
        tx = registry.functions.register(
            s2.public_bytes(), s2.make_pop()
        ).transact({"from": acct})
        w3.eth.wait_for_transaction_receipt(tx)
        assert registry.functions.getKey(acct).call() == s2.public_bytes()

    def test_unregistered_returns_empty(self, registry, accounts):
        assert registry.functions.isRegistered(accounts[9]).call() is False
        assert registry.functions.getKey(accounts[9]).call() == b""


# ── Single verification ────────────────────────────────────────────────────


class TestVerifySingle:
    def test_verify_valid_sig(self, w3, registry, accounts):
        signer = Signer.generate()
        acct = accounts[5]
        tx = registry.functions.register(
            signer.public_bytes(), signer.make_pop()
        ).transact({"from": acct})
        w3.eth.wait_for_transaction_receipt(tx)

        msg = b"hello world"
        sig = signer.sign(msg)
        result = registry.functions.verify(
            signer.public_bytes(), msg, sig
        ).call()
        assert result is True

    def test_verify_wrong_message_fails(self, registry):
        signer = Signer.generate()
        msg = b"hello"
        sig = signer.sign(msg)
        result = registry.functions.verify(
            signer.public_bytes(), b"wrong", sig
        ).call()
        assert result is False

    def test_verify_with_registered_key(self, w3, registry, accounts):
        signer = Signer.generate()
        acct = accounts[6]
        tx = registry.functions.register(
            signer.public_bytes(), signer.make_pop()
        ).transact({"from": acct})
        w3.eth.wait_for_transaction_receipt(tx)

        msg = b"test message"
        sig = signer.sign(msg)
        result = registry.functions.verifyWithRegisteredKey(
            acct, msg, sig
        ).call()
        assert result is True

    def test_verify_unregistered_owner_reverts(self, registry, accounts):
        signer = Signer.generate()
        sig = signer.sign(b"test")
        with pytest.raises(Exception):
            registry.functions.verifyWithRegisteredKey(
                accounts[9], b"test", sig
            ).call()


# ── Aggregate verification ──────────────────────────────────────────────────


class TestVerifyAggregated:
    @pytest.fixture(autouse=True)
    def setup(self, w3, registry, accounts):
        """Register 3 signers for aggregate tests."""
        self.w3 = w3
        self.registry = registry
        self.signers = [Signer.generate() for _ in range(3)]
        self.accts = accounts[7:10]
        self.msgs = [b"message one", b"message two", b"message three"]

        for signer, acct in zip(self.signers, self.accts):
            try:
                tx = registry.functions.register(
                    signer.public_bytes(), signer.make_pop()
                ).transact({"from": acct})
                w3.eth.wait_for_transaction_receipt(tx)
            except Exception:
                pass  # May already be registered from previous test run

        sigs = [s.sign(m) for s, m in zip(self.signers, self.msgs)]
        self.agg_sig = aggregate_signatures(sigs)

    def test_valid_aggregate_verifies(self):
        result = self.registry.functions.verifyAggregated(
            list(self.accts), list(self.msgs), self.agg_sig
        ).call()
        assert result is True

    def test_tampered_sig_fails(self):
        bad_sig = bytes([self.agg_sig[0] ^ 0xFF]) + self.agg_sig[1:]
        try:
            result = self.registry.functions.verifyAggregated(
                list(self.accts), list(self.msgs), bad_sig
            ).call()
        except Exception:
            result = False
        assert result is False

    def test_wrong_message_fails(self):
        wrong_msgs = [b"wrong"] + list(self.msgs[1:])
        try:
            result = self.registry.functions.verifyAggregated(
                list(self.accts), wrong_msgs, self.agg_sig
            ).call()
        except Exception:
            result = False
        assert result is False

    def test_empty_owners_reverts(self):
        with pytest.raises(Exception):
            self.registry.functions.verifyAggregated(
                [], [], self.agg_sig
            ).call()

    def test_mismatched_lengths_reverts(self):
        with pytest.raises(Exception):
            self.registry.functions.verifyAggregated(
                list(self.accts[:2]),
                list(self.msgs),
                self.agg_sig,
            ).call()
