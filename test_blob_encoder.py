"""test_blob_encoder.py — Unit tests for blob_encoder.py.

Tests the binary blob encoding format:
  [0:2]       N                 — number of messages (uint16, big-endian)
  [2:2+2N]    offsets[0..N-1]   — per-message start offset (uint16, big-endian)
  [2+2N:-256] message bodies    — each: sender (20 B) | nonce (8 B) | contents
  [-256:]     aggregate BLS signature (256 bytes)
"""

import os
import struct

import pytest

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob, _parse_sender


# ═══════════════════════════════════════════════════════════════════════════════
# _parse_sender
# ═══════════════════════════════════════════════════════════════════════════════

class TestParseSender:
    def test_valid_bytes_20(self):
        addr = os.urandom(20)
        assert _parse_sender(addr) == addr

    def test_valid_hex_string(self):
        addr = "0x" + "ab" * 20
        result = _parse_sender(addr)
        assert len(result) == 20
        assert result == bytes.fromhex("ab" * 20)

    def test_bytes_wrong_length_short(self):
        with pytest.raises(ValueError, match="20 bytes"):
            _parse_sender(b"\x00" * 10)

    def test_bytes_wrong_length_long(self):
        with pytest.raises(ValueError, match="20 bytes"):
            _parse_sender(b"\x00" * 32)

    def test_hex_string_no_prefix(self):
        with pytest.raises(ValueError, match="0x-prefixed"):
            _parse_sender("ab" * 20)

    def test_hex_string_wrong_length(self):
        """Hex string producing != 20 bytes should be rejected."""
        with pytest.raises(ValueError, match="20 bytes"):
            _parse_sender("0xABCD")

    def test_hex_string_too_long(self):
        with pytest.raises(ValueError, match="20 bytes"):
            _parse_sender("0x" + "ab" * 32)

    def test_checksummed_address(self):
        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        result = _parse_sender(addr)
        assert len(result) == 20


# ═══════════════════════════════════════════════════════════════════════════════
# encode_blob — basic encoding
# ═══════════════════════════════════════════════════════════════════════════════

class TestEncodeBlob:
    @pytest.fixture
    def three_signers(self):
        return [Signer.generate() for _ in range(3)]

    @pytest.fixture
    def three_messages(self):
        senders = ["0x" + os.urandom(20).hex() for _ in range(3)]
        nonces = [0, 1, 2]
        contents = [b"hello", b"world", b"test"]
        return list(zip(senders, nonces, contents))

    def test_basic_encoding(self, three_signers, three_messages):
        sigs = [s.sign(c) for s, (_, _, c) in zip(three_signers, three_messages)]
        blob = encode_blob(three_messages, sigs)
        assert isinstance(blob, bytes)
        assert len(blob) > 256  # at least signature

    def test_message_count_header(self, three_signers, three_messages):
        sigs = [s.sign(c) for s, (_, _, c) in zip(three_signers, three_messages)]
        blob = encode_blob(three_messages, sigs)
        n = struct.unpack("!H", blob[0:2])[0]
        assert n == 3

    def test_signature_at_end(self, three_signers, three_messages):
        sigs = [s.sign(c) for s, (_, _, c) in zip(three_signers, three_messages)]
        blob = encode_blob(three_messages, sigs)
        agg = aggregate_signatures(sigs)
        assert blob[-256:] == agg

    def test_offsets_are_valid(self, three_signers, three_messages):
        sigs = [s.sign(c) for s, (_, _, c) in zip(three_signers, three_messages)]
        blob = encode_blob(three_messages, sigs)
        n = struct.unpack("!H", blob[0:2])[0]
        for i in range(n):
            offset = struct.unpack("!H", blob[2 + 2 * i : 4 + 2 * i])[0]
            assert offset < len(blob) - 256  # within body region

    def test_sender_nonce_contents_roundtrip(self, three_signers, three_messages):
        sigs = [s.sign(c) for s, (_, _, c) in zip(three_signers, three_messages)]
        blob = encode_blob(three_messages, sigs)
        n = struct.unpack("!H", blob[0:2])[0]
        sig_start = len(blob) - 256
        for i in range(n):
            start = struct.unpack("!H", blob[2 + 2 * i : 4 + 2 * i])[0]
            end = struct.unpack("!H", blob[2 + 2 * (i + 1) : 4 + 2 * (i + 1)])[0] \
                if i + 1 < n else sig_start
            body = blob[start:end]
            sender_bytes = body[:20]
            nonce = int.from_bytes(body[20:28], "big")
            contents = body[28:]
            expected_sender = bytes.fromhex(three_messages[i][0][2:])
            assert sender_bytes == expected_sender
            assert nonce == three_messages[i][1]
            assert contents == three_messages[i][2]

    def test_single_message(self):
        signer = Signer.generate()
        msgs = [("0x" + os.urandom(20).hex(), 0, b"single message")]
        sigs = [signer.sign(msgs[0][2])]
        blob = encode_blob(msgs, sigs)
        n = struct.unpack("!H", blob[0:2])[0]
        assert n == 1

    def test_empty_contents(self):
        signer = Signer.generate()
        msgs = [("0x" + os.urandom(20).hex(), 0, b"")]
        sigs = [signer.sign(b"")]
        blob = encode_blob(msgs, sigs)
        n = struct.unpack("!H", blob[0:2])[0]
        assert n == 1

    def test_large_nonce(self):
        signer = Signer.generate()
        max_nonce = (1 << 64) - 1
        msgs = [("0x" + os.urandom(20).hex(), max_nonce, b"max nonce")]
        sigs = [signer.sign(msgs[0][2])]
        blob = encode_blob(msgs, sigs)
        # Verify nonce is correctly encoded
        offset = struct.unpack("!H", blob[2:4])[0]
        nonce = int.from_bytes(blob[offset + 20 : offset + 28], "big")
        assert nonce == max_nonce


# ═══════════════════════════════════════════════════════════════════════════════
# encode_blob — error cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestEncodeBlobErrors:
    def test_mismatched_lengths(self):
        msgs = [("0x" + os.urandom(20).hex(), 0, b"hello")]
        with pytest.raises(ValueError, match="same length"):
            encode_blob(msgs, [])

    def test_negative_nonce(self):
        signer = Signer.generate()
        msgs = [("0x" + os.urandom(20).hex(), -1, b"hello")]
        sigs = [signer.sign(b"hello")]
        with pytest.raises(ValueError, match="nonce"):
            encode_blob(msgs, sigs)

    def test_nonce_overflow(self):
        signer = Signer.generate()
        msgs = [("0x" + os.urandom(20).hex(), 1 << 64, b"hello")]
        sigs = [signer.sign(b"hello")]
        with pytest.raises(ValueError, match="nonce"):
            encode_blob(msgs, sigs)
