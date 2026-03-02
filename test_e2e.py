"""test_e2e.py — End-to-end integration tests for SocialBlobs.

Tests the full flow: generate BLS keys -> sign messages -> encode blob ->
register on-chain -> decode -> verify signatures -> expose messages.
"""

import os

import pytest
from web3 import Web3

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob


# ===========================================================================
# Full pipeline: sign -> encode -> register -> decode -> verify
# ===========================================================================

class TestFullPipeline:
    def test_sign_encode_register_decode_verify(
        self, w3, core, decoder, registry, exposer, deployer,
        signers, signer_accounts, registered_signers,
    ):
        """Complete flow matching Vitalik's test.py."""
        msgs_content = [b"hello world", b"test message", b"data blobs rock"]
        sigs = [s.sign(m) for s, m in zip(signers, msgs_content)]
        agg_sig = aggregate_signatures(sigs)

        nonces = list(range(3))
        message_tuples = list(zip(signer_accounts, nonces, msgs_content))
        blob = encode_blob(message_tuples, sigs)

        # Register on-chain via BAM Core.
        receipt = w3.eth.wait_for_transaction_receipt(
            core.functions.registerCalldataBatch(
                blob, decoder.address, registry.address
            ).transact({"from": deployer})
        )

        # Verify CalldataBatchRegistered event.
        logs = core.events.CalldataBatchRegistered().process_receipt(receipt)
        assert len(logs) == 1
        assert logs[0].args.submitter == deployer
        assert logs[0].args.contentHash == Web3.keccak(blob)
        assert logs[0].args.decoder == decoder.address
        assert logs[0].args.signatureRegistry == registry.address

        # Decode the blob.
        decoded_messages, decoded_sig = decoder.functions.decode(blob).call()
        assert len(decoded_messages) == 3
        assert decoded_sig == agg_sig

        # Verify decoded message fields.
        for i, (sender, nonce, content) in enumerate(message_tuples):
            assert decoded_messages[i][0] == sender
            assert decoded_messages[i][1] == nonce
            assert decoded_messages[i][2] == content

        # Verify aggregate BLS signature on-chain.
        assert registry.functions.verifyAggregated(
            list(signer_accounts), list(msgs_content), agg_sig
        ).call()

    def test_negative_tampered_signature(
        self, w3, registry, signers, signer_accounts, registered_signers,
    ):
        """Tampered aggregate signature must be rejected."""
        msgs = [b"neg1", b"neg2", b"neg3"]
        sigs = [s.sign(m) for s, m in zip(signers, msgs)]
        agg = aggregate_signatures(sigs)

        bad_sig = bytes([agg[0] ^ 0xFF]) + agg[1:]
        try:
            result = registry.functions.verifyAggregated(
                list(signer_accounts), msgs, bad_sig
            ).call()
        except Exception:
            result = False
        assert not result

    def test_negative_wrong_messages(
        self, w3, registry, signers, signer_accounts, registered_signers,
    ):
        """Wrong messages must be rejected."""
        msgs = [b"wrong1", b"wrong2", b"wrong3"]
        sigs = [s.sign(m) for s, m in zip(signers, [b"right1", b"right2", b"right3"])]
        agg = aggregate_signatures(sigs)

        try:
            result = registry.functions.verifyAggregated(
                list(signer_accounts), msgs, agg
            ).call()
        except Exception:
            result = False
        assert not result


# ===========================================================================
# BAM Core events
# ===========================================================================

class TestBAMCoreEvents:
    def test_calldata_batch_registered_event(
        self, w3, core, decoder, registry, deployer,
    ):
        """CalldataBatchRegistered event contains correct fields."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        msgs = [(sender, 0, b"event test")]
        sigs = [signer.sign(b"event test")]
        blob = encode_blob(msgs, sigs)

        receipt = w3.eth.wait_for_transaction_receipt(
            core.functions.registerCalldataBatch(
                blob, decoder.address, registry.address
            ).transact({"from": deployer})
        )
        logs = core.events.CalldataBatchRegistered().process_receipt(receipt)
        assert len(logs) == 1
        assert logs[0].args.contentHash == Web3.keccak(blob)
        assert logs[0].args.decoder == decoder.address
        assert logs[0].args.signatureRegistry == registry.address

    def test_zero_address_registry(self, w3, core, decoder, deployer):
        """Can register with zero address as signatureRegistry."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        msgs = [(sender, 0, b"zero reg")]
        sigs = [signer.sign(b"zero reg")]
        blob = encode_blob(msgs, sigs)

        zero = Web3.to_checksum_address("0x" + "00" * 20)
        receipt = w3.eth.wait_for_transaction_receipt(
            core.functions.registerCalldataBatch(
                blob, decoder.address, zero
            ).transact({"from": deployer})
        )
        logs = core.events.CalldataBatchRegistered().process_receipt(receipt)
        assert logs[0].args.signatureRegistry == zero


# ===========================================================================
# Message exposure (IERC_BAM_Exposer)
# ===========================================================================

class TestMessageExposure:
    def _register_blob(self, w3, core, decoder, registry, exposer, deployer):
        """Helper: encode blob, register, register batch in exposer."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        msgs = [(sender, 0, b"expose me")]
        sigs = [signer.sign(b"expose me")]
        blob = encode_blob(msgs, sigs)

        receipt = w3.eth.wait_for_transaction_receipt(
            core.functions.registerCalldataBatch(
                blob, decoder.address, registry.address
            ).transact({"from": deployer})
        )
        logs = core.events.CalldataBatchRegistered().process_receipt(receipt)
        content_hash = logs[0].args.contentHash

        exposer.functions.registerBatch(content_hash).transact({"from": deployer})
        return content_hash, sender

    def test_expose_message(
        self, w3, core, decoder, registry, exposer, deployer,
    ):
        """Expose a message and verify the event."""
        content_hash, sender = self._register_blob(
            w3, core, decoder, registry, exposer, deployer
        )
        author = Web3.to_checksum_address(sender)
        nonce = 0
        content = b"expose me"

        msg_id = exposer.functions.computeMessageId(
            author, nonce, content_hash
        ).call()

        assert not exposer.functions.isExposed(msg_id).call()

        receipt = w3.eth.wait_for_transaction_receipt(
            exposer.functions.exposeMessage(
                content_hash, author, nonce, content
            ).transact({"from": deployer})
        )
        logs = exposer.events.MessageExposed().process_receipt(receipt)
        assert len(logs) == 1
        assert logs[0].args.contentHash == content_hash
        assert logs[0].args.messageId == msg_id
        assert logs[0].args.author == author

        assert exposer.functions.isExposed(msg_id).call()

    def test_double_exposure_reverts(
        self, w3, core, decoder, registry, exposer, deployer,
    ):
        """Exposing the same message twice should revert."""
        content_hash, sender = self._register_blob(
            w3, core, decoder, registry, exposer, deployer
        )
        author = Web3.to_checksum_address(sender)

        exposer.functions.exposeMessage(
            content_hash, author, 0, b"expose me"
        ).transact({"from": deployer})

        with pytest.raises(Exception):
            exposer.functions.exposeMessage(
                content_hash, author, 0, b"expose me"
            ).transact({"from": deployer})

    def test_unregistered_batch_reverts(self, w3, exposer, deployer):
        """Exposing from an unregistered batch should revert."""
        fake_hash = Web3.keccak(b"not registered")
        with pytest.raises(Exception):
            exposer.functions.exposeMessage(
                fake_hash, deployer, 0, b"fake"
            ).transact({"from": deployer})

    def test_message_id_formula(self, w3, exposer, deployer):
        """Message ID matches keccak256(author || nonce || contentHash)."""
        author = deployer
        nonce = 42
        content_hash = Web3.keccak(b"test content hash")

        computed = exposer.functions.computeMessageId(
            author, nonce, content_hash
        ).call()

        expected = Web3.keccak(
            Web3.to_bytes(hexstr=author)
            + nonce.to_bytes(8, "big")
            + content_hash
        )
        assert computed == expected

    def test_different_nonces_different_ids(self, w3, exposer, deployer):
        """Different nonces produce different message IDs."""
        content_hash = Web3.keccak(b"same hash")
        id1 = exposer.functions.computeMessageId(deployer, 0, content_hash).call()
        id2 = exposer.functions.computeMessageId(deployer, 1, content_hash).call()
        assert id1 != id2

    def test_different_authors_different_ids(self, w3, exposer, accounts):
        """Different authors produce different message IDs."""
        content_hash = Web3.keccak(b"same hash")
        id1 = exposer.functions.computeMessageId(accounts[0], 0, content_hash).call()
        id2 = exposer.functions.computeMessageId(accounts[1], 0, content_hash).call()
        assert id1 != id2

    def test_expose_different_messages_independently(
        self, w3, core, decoder, registry, exposer, deployer,
    ):
        """Multiple messages from same batch can be exposed independently."""
        content_hash, sender = self._register_blob(
            w3, core, decoder, registry, exposer, deployer
        )
        author = Web3.to_checksum_address(sender)

        # Expose message with nonce=0
        exposer.functions.exposeMessage(
            content_hash, author, 0, b"expose me"
        ).transact({"from": deployer})

        # Expose different message (different nonce) should work
        id_nonce1 = exposer.functions.computeMessageId(
            author, 1, content_hash
        ).call()
        assert not exposer.functions.isExposed(id_nonce1).call()

        exposer.functions.exposeMessage(
            content_hash, author, 1, b"second msg"
        ).transact({"from": deployer})
        assert exposer.functions.isExposed(id_nonce1).call()


# ===========================================================================
# BSS — declareBlobSegment
# ===========================================================================

class TestBlobSegmentDeclared:
    def test_invalid_segment_start_ge_end(self, w3, core, deployer):
        """startFE >= endFE should revert."""
        with pytest.raises(Exception):
            core.functions.declareBlobSegment(0, 10, 10, b"\x00" * 32).transact(
                {"from": deployer}
            )

    def test_invalid_segment_end_exceeds_max(self, w3, core, deployer):
        """endFE > 4096 should revert."""
        with pytest.raises(Exception):
            core.functions.declareBlobSegment(0, 0, 4097, b"\x00" * 32).transact(
                {"from": deployer}
            )
