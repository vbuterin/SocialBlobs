"""test_e2e.py — End-to-end integration tests for SocialBlobs.

Tests the full pipeline:
  Sign → Compress → Encode → Register → Decode → Decompress → Verify
"""

import pytest
from web3 import Web3

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob
from bpe_encode import encode_msg


# ── Full pipeline ───────────────────────────────────────────────────────────


class TestFullPipeline:
    """Sign → compress → encode → on-chain decode → verify."""

    def test_three_message_pipeline(
        self, w3, decoder, registry, core_contract,
        deployer, accounts, token_to_code,
    ):
        """Full 3-message pipeline with compression."""
        signer_accounts = accounts[1:4]
        contents = [
            b"hello world",
            b"the quick brown fox jumps over the yellow dog",
            b"A purely peer-to-peer version of electronic cash would allow "
            b"online payments to be sent directly from one party to another "
            b"without going through a financial institution",
        ]
        n = len(contents)
        signers = [Signer.generate() for _ in range(n)]
        sigs = [s.sign(c) for s, c in zip(signers, contents)]
        agg_sig = aggregate_signatures(sigs)
        nonces = list(range(n))

        # Compress + encode
        compressor = lambda msg: encode_msg(msg, token_to_code)
        message_tuples = list(zip(signer_accounts, nonces, contents))
        blob = encode_blob(message_tuples, sigs, compressor)

        # Register BLS keys
        for signer, acct in zip(signers, signer_accounts):
            try:
                tx = registry.functions.register(
                    signer.public_bytes(), signer.make_pop()
                ).transact({"from": acct})
                w3.eth.wait_for_transaction_receipt(tx)
            except Exception:
                pass

        # Register blob on-chain
        receipt = w3.eth.wait_for_transaction_receipt(
            core_contract.functions.registerCalldataBatch(
                blob, decoder.address, registry.address
            ).transact({"from": deployer})
        )
        logs = core_contract.events.BlobBatchRegistered().process_receipt(receipt)
        assert len(logs) == 1
        assert logs[0].args.submitter == deployer
        assert logs[0].args.versionedHash == Web3.keccak(blob)
        assert logs[0].args.decoder == decoder.address
        assert logs[0].args.signatureRegistry == registry.address

        # Decode on-chain
        decoded_msgs, decoded_sig = decoder.functions.decode(blob).call()
        assert decoded_msgs == message_tuples
        assert decoded_sig == agg_sig

        # Verify aggregate signature
        owners = list(signer_accounts)
        messages = list(contents)
        assert registry.functions.verifyAggregated(
            owners, messages, agg_sig
        ).call() is True

    def test_single_message_pipeline(
        self, w3, decoder, registry, core_contract,
        deployer, accounts, token_to_code,
    ):
        """Pipeline with a single message."""
        acct = accounts[4]
        content = b"single message test"
        signer = Signer.generate()
        sig = signer.sign(content)
        agg_sig = aggregate_signatures([sig])
        compressor = lambda msg: encode_msg(msg, token_to_code)

        blob = encode_blob([(acct, 0, content)], [sig], compressor)

        try:
            tx = registry.functions.register(
                signer.public_bytes(), signer.make_pop()
            ).transact({"from": acct})
            w3.eth.wait_for_transaction_receipt(tx)
        except Exception:
            pass

        decoded_msgs, decoded_sig = decoder.functions.decode(blob).call()
        assert len(decoded_msgs) == 1
        assert decoded_msgs[0][0] == acct
        assert decoded_msgs[0][2] == content
        assert decoded_sig == agg_sig


# ── Compression integration ─────────────────────────────────────────────────


class TestCompressionIntegration:
    """Verify compression actually saves space in the blob."""

    def test_compressed_blob_smaller(self, token_to_code, accounts):
        """Compressed blob should be smaller than uncompressed for English text."""
        acct = accounts[1]
        content = b"the quick brown fox jumps over the lazy dog " * 3
        signer = Signer.generate()
        sig = signer.sign(content)

        compressor = lambda msg: encode_msg(msg, token_to_code)
        blob_comp = encode_blob([(acct, 0, content)], [sig], compressor)
        blob_raw = encode_blob([(acct, 0, content)], [sig], lambda x: x)

        # Compressed should be meaningfully smaller
        assert len(blob_comp) < len(blob_raw)

    def test_compression_ratio_reported(self, token_to_code):
        """Check compression achieves reasonable ratio for common text."""
        contents = [
            b"hello world",
            b"the quick brown fox jumps over the yellow dog",
            b"ethereum is a decentralized platform",
        ]
        for content in contents:
            compressed = encode_msg(content, token_to_code)
            ratio = len(compressed) / len(content)
            # Compression should not expand text more than 2x
            assert ratio < 2.0, f"Bad ratio {ratio} for {content!r}"


# ── Negative tests ──────────────────────────────────────────────────────────


class TestNegativeCases:
    def test_tampered_sig_rejected(
        self, w3, decoder, registry, accounts, token_to_code,
    ):
        """Bit-flipped aggregate signature must be rejected."""
        accts = accounts[5:7]
        contents = [b"msg1", b"msg2"]
        signers = [Signer.generate() for _ in range(2)]
        sigs = [s.sign(c) for s, c in zip(signers, contents)]
        agg_sig = aggregate_signatures(sigs)

        for signer, acct in zip(signers, accts):
            try:
                tx = registry.functions.register(
                    signer.public_bytes(), signer.make_pop()
                ).transact({"from": acct})
                w3.eth.wait_for_transaction_receipt(tx)
            except Exception:
                pass

        bad_sig = bytes([agg_sig[0] ^ 0xFF]) + agg_sig[1:]
        try:
            result = registry.functions.verifyAggregated(
                list(accts), list(contents), bad_sig
            ).call()
        except Exception:
            result = False
        assert result is False

    def test_wrong_message_rejected(
        self, w3, decoder, registry, accounts, token_to_code,
    ):
        """Wrong message content must cause verification failure."""
        accts = accounts[5:7]
        contents = [b"msg1", b"msg2"]
        signers = [Signer.generate() for _ in range(2)]
        sigs = [s.sign(c) for s, c in zip(signers, contents)]
        agg_sig = aggregate_signatures(sigs)

        for signer, acct in zip(signers, accts):
            try:
                tx = registry.functions.register(
                    signer.public_bytes(), signer.make_pop()
                ).transact({"from": acct})
                w3.eth.wait_for_transaction_receipt(tx)
            except Exception:
                pass

        wrong = [b"wrong"] + list(contents[1:])
        try:
            result = registry.functions.verifyAggregated(
                list(accts), wrong, agg_sig
            ).call()
        except Exception:
            result = False
        assert result is False

    def test_decode_verify_roundtrip_matches(
        self, decoder, registry, accounts, token_to_code,
    ):
        """Decoded messages should verify against the decoded signature."""
        accts = accounts[5:7]
        contents = [b"verify me", b"and me too"]
        signers = [Signer.generate() for _ in range(2)]
        sigs = [s.sign(c) for s, c in zip(signers, contents)]
        compressor = lambda msg: encode_msg(msg, token_to_code)

        for signer, acct in zip(signers, accts):
            try:
                tx = registry.functions.register(
                    signer.public_bytes(), signer.make_pop()
                ).transact({"from": acct})
                registry.w3.eth.wait_for_transaction_receipt(tx)
            except Exception:
                pass

        blob = encode_blob(list(zip(accts, [0, 1], contents)), sigs, compressor)
        decoded_msgs, decoded_sig = decoder.functions.decode(blob).call()

        # Extract just the contents from decoded messages
        decoded_contents = [m[2] for m in decoded_msgs]
        decoded_owners = [m[0] for m in decoded_msgs]

        result = registry.functions.verifyAggregated(
            decoded_owners, decoded_contents, decoded_sig
        ).call()
        assert result is True
