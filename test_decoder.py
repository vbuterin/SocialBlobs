"""test_decoder.py — Tests for on-chain blob decoder with decompression.

Tests decoder.vy:
  - decode(): Parse blob → messages[] + aggregated signature
  - decompress(): Decompress encoded data using dictionary
  - Full round-trip: encode (with compression) → decode → verify
"""

import os
import struct

import pytest
from web3 import Web3

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob, signing_payload
from bpe_encode import encode_msg


# ── Helpers ──────────────────────────────────────────────────────────────────


def make_blob(senders, nonces, contents, compressor):
    """Build a blob from senders (hex), nonces, contents, and BLS sigs."""
    signers = [Signer.generate() for _ in range(len(contents))]
    sigs = [s.sign(signing_payload(n, c)) for s, n, c in zip(signers, nonces, contents)]
    messages = list(zip(senders, nonces, contents))
    blob = encode_blob(messages, sigs, compressor)
    return blob, signers, sigs


# ── decode() tests ──────────────────────────────────────────────────────────


class TestDecode:
    """Tests for the decode() external function."""

    def test_decode_three_messages(self, decoder, token_to_code, accounts):
        """Decode a 3-message blob and verify sender/nonce/contents."""
        senders = accounts[1:4]
        nonces = [0, 1, 2]
        contents = [
            b"hello world",
            b"the quick brown fox jumps over the yellow dog",
            b"A purely peer-to-peer version of electronic cash would allow "
            b"online payments to be sent directly from one party to another "
            b"without going through a financial institution",
        ]
        compressor = lambda msg: encode_msg(msg, token_to_code)
        blob, signers, sigs = make_blob(senders, nonces, contents, compressor)

        decoded_msgs, decoded_sig = decoder.functions.decode(blob).call()
        expected_tuples = list(zip(senders, nonces, contents))

        assert decoded_msgs == expected_tuples
        assert decoded_sig == aggregate_signatures(sigs)

    def test_decode_single_message(self, decoder, token_to_code, accounts):
        sender = accounts[1]
        content = b"hello"
        compressor = lambda msg: encode_msg(msg, token_to_code)
        blob, signers, sigs = make_blob([sender], [0], [content], compressor)

        decoded_msgs, decoded_sig = decoder.functions.decode(blob).call()
        assert len(decoded_msgs) == 1
        assert decoded_msgs[0][0] == sender
        assert decoded_msgs[0][1] == 0
        assert decoded_msgs[0][2] == content

    def test_decode_preserves_sender_address(self, decoder, token_to_code, accounts):
        senders = accounts[1:3]
        compressor = lambda msg: encode_msg(msg, token_to_code)
        blob, _, _ = make_blob(senders, [0, 1], [b"a", b"b"], compressor)

        decoded_msgs, _ = decoder.functions.decode(blob).call()
        assert decoded_msgs[0][0] == senders[0]
        assert decoded_msgs[1][0] == senders[1]

    def test_decode_preserves_nonce(self, decoder, token_to_code, accounts):
        compressor = lambda msg: encode_msg(msg, token_to_code)
        blob, _, _ = make_blob(
            [accounts[1], accounts[2]],
            [42, 99],
            [b"a", b"b"],
            compressor,
        )

        decoded_msgs, _ = decoder.functions.decode(blob).call()
        assert decoded_msgs[0][1] == 42
        assert decoded_msgs[1][1] == 99

    def test_decode_extracts_aggregate_sig(self, decoder, token_to_code, accounts):
        compressor = lambda msg: encode_msg(msg, token_to_code)
        blob, _, sigs = make_blob(
            [accounts[1]], [0], [b"test"], compressor
        )

        _, decoded_sig = decoder.functions.decode(blob).call()
        assert decoded_sig == aggregate_signatures(sigs)

    def test_decode_two_messages(self, decoder, token_to_code, accounts):
        senders = accounts[1:3]
        contents = [b"first", b"second"]
        compressor = lambda msg: encode_msg(msg, token_to_code)
        blob, _, sigs = make_blob(senders, [0, 1], contents, compressor)

        decoded_msgs, decoded_sig = decoder.functions.decode(blob).call()
        assert len(decoded_msgs) == 2
        for i, (sender, nonce, content) in enumerate(zip(senders, [0, 1], contents)):
            assert decoded_msgs[i][0] == sender
            assert decoded_msgs[i][1] == nonce
            assert decoded_msgs[i][2] == content


# ── decompress() tests ──────────────────────────────────────────────────────


class TestDecompress:
    """Tests for the decompress() external function."""

    def test_roundtrip_short(self, decoder, token_to_code):
        msg = b"hello"
        compressed = encode_msg(msg, token_to_code)
        result = decoder.functions.decompress(compressed).call()
        assert result[:len(msg)] == msg

    def test_roundtrip_medium(self, decoder, token_to_code):
        msg = b"the quick brown fox jumps over the yellow dog"
        compressed = encode_msg(msg, token_to_code)
        result = decoder.functions.decompress(compressed).call()
        assert result == msg

    def test_empty_input_returns_empty(self, decoder):
        result = decoder.functions.decompress(b"").call()
        assert result == b""

    def test_not_aligned_reverts(self, decoder):
        with pytest.raises(Exception):
            decoder.functions.decompress(b"\x00\x01\x02\x03").call()

    def test_multiple_words(self, decoder, token_to_code):
        """Message requiring multiple 5-byte words should decode correctly."""
        msg = b"this is a longer test message for multi-word encoding"
        compressed = encode_msg(msg, token_to_code)
        assert len(compressed) > 5  # needs multiple words
        result = decoder.functions.decompress(compressed).call()
        assert result == msg


# ── Error cases ─────────────────────────────────────────────────────────────


class TestDecodeErrors:
    def test_too_small_payload_reverts(self, decoder):
        """Payload smaller than SIG_SIZE (256) should revert."""
        with pytest.raises(Exception):
            decoder.functions.decode(b"\x00" * 100).call()

    def test_too_many_messages_reverts(self, decoder, token_to_code):
        """More than MAX_MESSAGES (64) should revert."""
        # Construct a payload with N > 64 in the header
        n = 65
        header = struct.pack("!H", n)
        # Pad enough to pass the size check
        payload = header + b"\x00" * (2 * n + 256 + 100)
        with pytest.raises(Exception):
            decoder.functions.decode(payload).call()
