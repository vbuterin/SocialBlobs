"""test_blob_encoder.py -- Tests for blob encoding with compression.

Tests the binary blob format:
  [0:2]       N           -- number of messages (uint16, big-endian)
  [2:2+2N]    offsets     -- per-message start offset (uint16, big-endian)
  [2+2N:-256] bodies      -- sender (20 B) | nonce (8 B) | compressed contents
  [-256:]     agg sig     -- aggregate BLS signature (256 bytes)
"""

import os
import struct

import pytest

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob, signing_payload, _parse_sender
from bpe_encode import build_12bit_dict_from_corpus, encode_msg


@pytest.fixture(scope="module")
def compression():
    token_to_code, _, _, _ = build_12bit_dict_from_corpus("corpus.txt")
    return token_to_code


@pytest.fixture(scope="module")
def compressor(compression):
    return lambda msg: encode_msg(msg, compression)


@pytest.fixture(scope="module")
def identity_compressor():
    """No-op compressor for testing raw (uncompressed) blobs."""
    return lambda x: x


# -- Sender parsing --


class TestParseSender:
    def test_hex_string_20_bytes(self):
        sender = "0x" + "ab" * 20
        result = _parse_sender(sender)
        assert len(result) == 20
        assert result == bytes.fromhex("ab" * 20)

    def test_bytes_20(self):
        sender = b"\x01" * 20
        result = _parse_sender(sender)
        assert result == sender

    def test_hex_no_prefix_raises(self):
        with pytest.raises(ValueError, match="0x-prefixed"):
            _parse_sender("ab" * 20)

    def test_wrong_length_hex_raises(self):
        with pytest.raises(ValueError, match="20 bytes"):
            _parse_sender("0x" + "ab" * 19)

    def test_wrong_length_bytes_raises(self):
        with pytest.raises(ValueError, match="20 bytes"):
            _parse_sender(b"\x01" * 19)

    def test_checksum_address(self):
        addr = "0x" + "aB" * 20
        result = _parse_sender(addr)
        assert len(result) == 20


# -- Blob structure --


class TestBlobStructure:
    def test_message_count_header(self, compressor):
        signers = [Signer.generate() for _ in range(3)]
        senders = ["0x" + os.urandom(20).hex() for _ in range(3)]
        nonces = [0, 1, 2]
        contents = [b"hello", b"world", b"test"]
        sigs = [s.sign(signing_payload(n, c)) for s, n, c in zip(signers, nonces, contents)]
        messages = list(zip(senders, nonces, contents))
        blob = encode_blob(messages, sigs, compressor)

        n = struct.unpack("!H", blob[:2])[0]
        assert n == 3

    def test_trailing_signature_256_bytes(self, compressor):
        signers = [Signer.generate() for _ in range(2)]
        senders = ["0x" + os.urandom(20).hex() for _ in range(2)]
        nonces = [0, 1]
        contents = [b"hello", b"world"]
        sigs = [s.sign(signing_payload(n, c)) for s, n, c in zip(signers, nonces, contents)]
        messages = list(zip(senders, nonces, contents))
        blob = encode_blob(messages, sigs, compressor)

        agg_sig = aggregate_signatures(sigs)
        assert blob[-256:] == agg_sig

    def test_offsets_are_valid(self, compressor):
        signers = [Signer.generate() for _ in range(3)]
        senders = ["0x" + os.urandom(20).hex() for _ in range(3)]
        nonces = [0, 1, 2]
        contents = [b"hello", b"world", b"test"]
        sigs = [s.sign(signing_payload(n, c)) for s, n, c in zip(signers, nonces, contents)]
        messages = list(zip(senders, nonces, contents))
        blob = encode_blob(messages, sigs, compressor)

        n = struct.unpack("!H", blob[:2])[0]
        offsets = []
        for i in range(n):
            off = struct.unpack("!H", blob[2 + i * 2:4 + i * 2])[0]
            offsets.append(off)

        # Offsets should be monotonically increasing
        for i in range(len(offsets) - 1):
            assert offsets[i] < offsets[i + 1]

        # First offset should be right after the header
        assert offsets[0] == 2 + 2 * n

    def test_sender_embedded_in_body(self, compressor):
        sender_bytes = os.urandom(20)
        sender_hex = "0x" + sender_bytes.hex()
        signer = Signer.generate()
        content = b"hello"
        sig = signer.sign(signing_payload(0, content))
        blob = encode_blob([(sender_hex, 0, content)], [sig], compressor)

        # First message starts at offset 4 (2 bytes N + 2 bytes offset)
        offset = struct.unpack("!H", blob[2:4])[0]
        assert blob[offset:offset + 20] == sender_bytes

    def test_nonce_embedded_in_body(self, compressor):
        sender = "0x" + os.urandom(20).hex()
        signer = Signer.generate()
        nonce = 42
        content = b"test"
        sig = signer.sign(signing_payload(nonce, content))
        blob = encode_blob([(sender, nonce, content)], [sig], compressor)

        offset = struct.unpack("!H", blob[2:4])[0]
        nonce_bytes = blob[offset + 20:offset + 28]
        assert int.from_bytes(nonce_bytes, "big") == nonce


# -- Edge cases --


class TestBlobEdgeCases:
    def test_single_message(self, compressor):
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        content = b"single"
        sig = signer.sign(signing_payload(0, content))
        blob = encode_blob([(sender, 0, content)], [sig], compressor)

        n = struct.unpack("!H", blob[:2])[0]
        assert n == 1
        assert len(blob) > 256  # at least sig + header + body

    def test_empty_content(self, compressor):
        """Empty message content should encode without error."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        sig = signer.sign(signing_payload(0, b""))
        blob = encode_blob([(sender, 0, b"")], [sig], compressor)
        assert len(blob) >= 256 + 4 + 28  # sig + header + sender+nonce

    def test_nonce_max_uint64(self, compressor):
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        nonce = (1 << 64) - 1
        sig = signer.sign(signing_payload(nonce, b"test"))
        blob = encode_blob([(sender, nonce, b"test")], [sig], compressor)
        assert len(blob) > 256

    def test_nonce_negative_raises(self, compressor):
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        sig = signer.sign(signing_payload(0, b"test"))
        with pytest.raises(ValueError, match="nonce"):
            encode_blob([(sender, -1, b"test")], [sig], compressor)

    def test_nonce_too_large_raises(self, compressor):
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        sig = signer.sign(signing_payload(0, b"test"))
        with pytest.raises(ValueError, match="nonce"):
            encode_blob([(sender, 1 << 64, b"test")], [sig], compressor)

    def test_mismatched_lengths_raises(self, compressor):
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        with pytest.raises(ValueError, match="same length"):
            encode_blob([(sender, 0, b"test")], [], compressor)

    def test_identity_compressor(self, identity_compressor):
        """Encoding with identity compressor stores raw contents."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        content = b"hello"
        sig = signer.sign(signing_payload(0, content))
        blob = encode_blob([(sender, 0, content)], [sig], identity_compressor)

        offset = struct.unpack("!H", blob[2:4])[0]
        # Raw content should appear directly after sender+nonce
        assert blob[offset + 28:offset + 28 + len(content)] == content

    def test_compressed_content_different(self, compressor, identity_compressor):
        """Compressed blob should differ from uncompressed blob."""
        signer = Signer.generate()
        sender = "0x" + os.urandom(20).hex()
        content = b"the quick brown fox jumps over the lazy dog"
        sig = signer.sign(signing_payload(0, content))
        blob_comp = encode_blob([(sender, 0, content)], [sig], compressor)
        blob_raw = encode_blob([(sender, 0, content)], [sig], identity_compressor)
        # Compressed and raw blobs should differ (different body sizes)
        assert blob_comp != blob_raw
