"""test_decoder.py — Unit tests for decoder.vy.

Tests the on-chain blob decoder contract against various blob inputs.
"""

import os
import struct

import pytest
from web3 import Web3

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob


# ===========================================================================
# Basic decoding
# ===========================================================================

class TestDecoderBasic:
    def test_decode_three_messages(self, w3, decoder, signers, signer_accounts):
        """Decode a 3-message blob and verify all fields."""
        msgs_content = [b"hello world", b"test message", b"data blobs rock"]
        sigs = [s.sign(m) for s, m in zip(signers, msgs_content)]
        message_tuples = list(zip(signer_accounts, [0, 1, 2], msgs_content))
        blob = encode_blob(message_tuples, sigs)

        decoded_messages, decoded_sig = decoder.functions.decode(blob).call()
        assert len(decoded_messages) == 3
        agg = aggregate_signatures(sigs)
        assert decoded_sig == agg

    def test_decode_single_message(self, w3, decoder):
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        msg = [(sender, 0, b"single")]
        sig = [signer.sign(b"single")]
        blob = encode_blob(msg, sig)

        decoded_messages, decoded_sig = decoder.functions.decode(blob).call()
        assert len(decoded_messages) == 1
        assert decoded_messages[0][2] == b"single"

    def test_decode_sender_address(self, w3, decoder, signer_accounts):
        """Verify decoded sender matches the encoded address."""
        signer = Signer.generate()
        msg = [(signer_accounts[0], 0, b"test")]
        sig = [signer.sign(b"test")]
        blob = encode_blob(msg, sig)

        decoded_messages, _ = decoder.functions.decode(blob).call()
        assert decoded_messages[0][0] == signer_accounts[0]

    def test_decode_nonce_values(self, w3, decoder):
        """Verify nonces are decoded correctly."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        nonces = [0, 42, 1000]
        msgs = [(sender, n, b"msg") for n in nonces]
        sigs = [signer.sign(b"msg") for _ in nonces]
        blob = encode_blob(msgs, sigs)

        decoded_messages, _ = decoder.functions.decode(blob).call()
        for i, n in enumerate(nonces):
            assert decoded_messages[i][1] == n

    def test_decode_preserves_contents(self, w3, decoder):
        """Verify message contents are decoded exactly."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        contents = [b"hello", b"world!", b"\x00\xff\x80"]
        msgs = [(sender, i, c) for i, c in enumerate(contents)]
        sigs = [signer.sign(c) for c in contents]
        blob = encode_blob(msgs, sigs)

        decoded_messages, _ = decoder.functions.decode(blob).call()
        for i, c in enumerate(contents):
            assert decoded_messages[i][2] == c

    def test_decode_signature_matches_aggregate(self, w3, decoder):
        """Verify the decoded signature equals the aggregate."""
        signers_list = [Signer.generate() for _ in range(3)]
        sender = "0x" + os.urandom(20).hex()
        contents = [b"a", b"b", b"c"]
        msgs = [(sender, i, c) for i, c in enumerate(contents)]
        sigs = [s.sign(c) for s, c in zip(signers_list, contents)]
        blob = encode_blob(msgs, sigs)

        _, decoded_sig = decoder.functions.decode(blob).call()
        expected_agg = aggregate_signatures(sigs)
        assert decoded_sig == expected_agg


# ===========================================================================
# Edge cases
# ===========================================================================

class TestDecoderEdgeCases:
    def test_decode_empty_contents(self, w3, decoder):
        """Messages with empty contents should decode correctly."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        msgs = [(sender, 0, b"")]
        sigs = [signer.sign(b"")]
        blob = encode_blob(msgs, sigs)

        decoded_messages, _ = decoder.functions.decode(blob).call()
        assert len(decoded_messages) == 1
        assert decoded_messages[0][2] == b""

    def test_decode_max_nonce(self, w3, decoder):
        """Maximum uint64 nonce should decode correctly."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        max_nonce = (1 << 64) - 1
        msgs = [(sender, max_nonce, b"max")]
        sigs = [signer.sign(b"max")]
        blob = encode_blob(msgs, sigs)

        decoded_messages, _ = decoder.functions.decode(blob).call()
        assert decoded_messages[0][1] == max_nonce

    def test_decode_binary_contents(self, w3, decoder):
        """Binary content (all byte values) should roundtrip."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        content = bytes(range(256))
        msgs = [(sender, 0, content)]
        sigs = [signer.sign(content)]
        blob = encode_blob(msgs, sigs)

        decoded_messages, _ = decoder.functions.decode(blob).call()
        assert decoded_messages[0][2] == content


# ===========================================================================
# Error cases
# ===========================================================================

class TestDecoderErrors:
    def test_decode_payload_too_small(self, w3, decoder):
        """Payload smaller than signature size should revert."""
        with pytest.raises(Exception):
            decoder.functions.decode(b"\x00" * 100).call()

    def test_decode_too_many_messages(self, w3, decoder):
        """Message count > MAX_MESSAGES (64) should revert."""
        # Craft a payload with N=65 in the header
        n = 65
        header = struct.pack("!H", n)
        # Add dummy offsets and pad to signature size
        payload = header + b"\x00" * (2 * n + 256 + 100)
        with pytest.raises(Exception):
            decoder.functions.decode(payload).call()
