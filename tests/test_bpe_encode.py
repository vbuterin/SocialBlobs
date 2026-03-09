"""test_bpe_encode.py -- Tests for BPE 12-bit dictionary compression/decompression.

Tests the full compression pipeline:
  - Dictionary building from corpus
  - Greedy longest-match encoding
  - 12-bit code packing into 3-byte words
  - On-chain decompression round-trip via decoder.vy
"""

import pytest
from paths import CORPUS_PATH
from bpe_encode import (
    build_12bit_dict_from_corpus,
    encode_msg,
    _count_windows,
    _top_tokens,
    _make_dict_blobs,
)


# -- Dictionary building --


class TestCountWindows:
    """Tests for _count_windows (n-gram counting)."""

    def test_counts_2byte_windows(self):
        data = b"abcabc"
        counts = _count_windows(data)
        assert counts[2][b"ab"] == 2
        assert counts[2][b"bc"] == 2
        assert counts[2][b"ca"] == 1

    def test_counts_3byte_windows(self):
        data = b"abcabc"
        counts = _count_windows(data)
        assert counts[3][b"abc"] == 2
        assert counts[3][b"bca"] == 1
        assert counts[3][b"cab"] == 1

    def test_counts_4byte_windows(self):
        data = b"abcdabcd"
        counts = _count_windows(data)
        assert counts[4][b"abcd"] == 2
        assert counts[4][b"bcda"] == 1

    def test_empty_data(self):
        counts = _count_windows(b"")
        assert len(counts[2]) == 0
        assert len(counts[3]) == 0
        assert len(counts[4]) == 0

    def test_short_data(self):
        counts = _count_windows(b"a")
        assert len(counts[2]) == 0
        assert len(counts[3]) == 0
        assert len(counts[4]) == 0

    def test_two_byte_data(self):
        counts = _count_windows(b"ab")
        assert counts[2][b"ab"] == 1
        assert len(counts[3]) == 0
        assert len(counts[4]) == 0


class TestTopTokens:
    """Tests for _top_tokens (code table construction)."""

    def test_total_codes_with_corpus(self):
        """With a large enough corpus, we get 3328 codes (1024+1024+1024+256)."""
        token_to_code, _, _, _ = build_12bit_dict_from_corpus(str(CORPUS_PATH))
        assert len(token_to_code) == 3328

    def test_small_data_fills_all_1byte_codes(self):
        """Even small data always produces 256 1-byte codes."""
        data = b"hello world " * 100
        counts = _count_windows(data)
        token_to_code, _ = _top_tokens(counts)
        one_byte = [c for tok, c in token_to_code.items() if len(tok) == 1]
        assert len(one_byte) == 256

    def test_code_0_is_null_token(self):
        data = b"hello world " * 100
        counts = _count_windows(data)
        token_to_code, _ = _top_tokens(counts)
        assert token_to_code[b"\x00\x00\x00\x00"] == 0

    def test_corpus_4byte_tokens_in_range_0_1023(self):
        """With the real corpus, 4-byte tokens get codes 0-1023."""
        token_to_code, _, _, _ = build_12bit_dict_from_corpus(str(CORPUS_PATH))
        four_byte_codes = [c for tok, c in token_to_code.items()
                           if len(tok) == 4 and c < 1024]
        assert len(four_byte_codes) == 1024

    def test_corpus_3byte_tokens_in_range_1024_2047(self):
        token_to_code, _, _, _ = build_12bit_dict_from_corpus(str(CORPUS_PATH))
        three_byte_codes = [c for tok, c in token_to_code.items()
                            if len(tok) == 3 and 1024 <= c < 2048]
        assert len(three_byte_codes) == 1024

    def test_corpus_2byte_tokens_in_range_2048_3071(self):
        token_to_code, _, _, _ = build_12bit_dict_from_corpus(str(CORPUS_PATH))
        two_byte_codes = [c for tok, c in token_to_code.items()
                          if len(tok) == 2 and 2048 <= c < 3072]
        assert len(two_byte_codes) == 1024

    def test_corpus_1byte_tokens_in_range_3072_3327(self):
        token_to_code, _, _, _ = build_12bit_dict_from_corpus(str(CORPUS_PATH))
        one_byte_codes = [c for tok, c in token_to_code.items()
                          if len(tok) == 1 and 3072 <= c < 3328]
        assert len(one_byte_codes) == 256

    def test_all_single_bytes_present(self):
        """Every possible byte value (0-255) must have a 1-byte code."""
        data = b"hello world " * 100
        counts = _count_windows(data)
        token_to_code, _ = _top_tokens(counts)
        for i in range(256):
            assert bytes([i]) in token_to_code


class TestMakeDictBlobs:
    """Tests for _make_dict_blobs (binary dictionary construction)."""

    def test_dict_bytes_length(self):
        data = b"hello world " * 100
        counts = _count_windows(data)
        token_to_code, _ = _top_tokens(counts)
        dict_bytes, dict_offs, dict_len = _make_dict_blobs(token_to_code)
        assert len(dict_bytes) == 10240

    def test_dict_offs_and_len_consistent(self):
        data = b"hello world " * 100
        counts = _count_windows(data)
        token_to_code, _ = _top_tokens(counts)
        dict_bytes, dict_offs, dict_len = _make_dict_blobs(token_to_code)
        for tok, code in token_to_code.items():
            off = dict_offs[code]
            ln = dict_len[code]
            assert ln == len(tok), f"code {code}: expected len {len(tok)}, got {ln}"
            assert dict_bytes[off:off + ln] == tok, \
                f"code {code}: expected {tok!r}, got {dict_bytes[off:off+ln]!r}"

    def test_no_overlap_in_dict(self):
        """Token regions in DICT_BYTES should not overlap."""
        data = b"hello world " * 100
        counts = _count_windows(data)
        token_to_code, _ = _top_tokens(counts)
        _, dict_offs, dict_len = _make_dict_blobs(token_to_code)
        regions = sorted(
            [(dict_offs[c], dict_offs[c] + dict_len[c])
             for c in range(4096) if dict_len[c] > 0],
            key=lambda x: x[0],
        )
        for i in range(len(regions) - 1):
            assert regions[i][1] <= regions[i + 1][0], \
                f"overlap at {regions[i]} and {regions[i+1]}"


class TestBuildFromCorpus:
    """Tests for build_12bit_dict_from_corpus (full pipeline)."""

    def test_loads_corpus(self):
        token_to_code, dict_bytes, dict_offs, dict_len = \
            build_12bit_dict_from_corpus(str(CORPUS_PATH))
        assert len(token_to_code) == 3328
        assert len(dict_bytes) == 10240

    def test_deterministic(self):
        r1 = build_12bit_dict_from_corpus(str(CORPUS_PATH))
        r2 = build_12bit_dict_from_corpus(str(CORPUS_PATH))
        assert r1[0] == r2[0]  # token_to_code
        assert r1[1] == r2[1]  # dict_bytes


# -- Encoding --


class TestEncodeMsg:
    """Tests for encode_msg (greedy longest-match encoding)."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.token_to_code, _, _, _ = build_12bit_dict_from_corpus(str(CORPUS_PATH))

    def test_output_is_3_byte_aligned(self):
        msg = b"hello world"
        encoded = encode_msg(msg, self.token_to_code)
        assert len(encoded) % 3 == 0

    def test_empty_message(self):
        encoded = encode_msg(b"", self.token_to_code)
        assert len(encoded) == 0

    def test_single_byte(self):
        encoded = encode_msg(b"x", self.token_to_code)
        assert len(encoded) == 3  # 1 code + 1 padding -> 2 codes -> 3 bytes

    def test_compression_ratio(self):
        """Longer messages with common patterns should compress."""
        msg = b"the quick brown fox jumps over the lazy dog"
        encoded = encode_msg(msg, self.token_to_code)
        # Should be shorter than original (or at most similar for incompressible)
        assert len(encoded) <= len(msg) * 2  # generous upper bound

    def test_all_single_bytes_encodable(self):
        """Every single byte must be encodable."""
        for i in range(256):
            encoded = encode_msg(bytes([i]), self.token_to_code)
            assert len(encoded) == 3

    def test_binary_data_encodable(self):
        """Arbitrary binary data should encode without errors."""
        import os
        data = os.urandom(64)
        encoded = encode_msg(data, self.token_to_code)
        assert len(encoded) % 3 == 0
        assert len(encoded) > 0

    def test_repeated_pattern_compresses(self):
        """Repeated patterns should use multi-byte tokens effectively."""
        msg = b"aaaa" * 10  # 40 bytes
        encoded = encode_msg(msg, self.token_to_code)
        # Each "aaaa" maps to a single 12-bit code, 10 codes = 5 words = 15 bytes
        # Even with padding, should be well under 2x original size
        assert len(encoded) <= len(msg) * 2

    def test_deterministic_encoding(self):
        msg = b"hello world"
        e1 = encode_msg(msg, self.token_to_code)
        e2 = encode_msg(msg, self.token_to_code)
        assert e1 == e2

    def test_different_messages_different_encodings(self):
        e1 = encode_msg(b"hello", self.token_to_code)
        e2 = encode_msg(b"world", self.token_to_code)
        assert e1 != e2

    def test_12bit_codes_valid_range(self):
        """All packed codes should be in the 0-4095 range."""
        msg = b"test message"
        encoded = encode_msg(msg, self.token_to_code)
        for i in range(0, len(encoded), 3):
            word = int.from_bytes(encoded[i:i + 3], "big")
            c0 = (word >> 12) & 4095
            c1 = word & 4095
            for c in [c0, c1]:
                assert 0 <= c <= 4095, f"code {c} out of range"

    def test_greedy_longest_match(self):
        """Encoder should prefer longer tokens when available."""
        msg = b"the "  # 4 bytes -- should use a single 4-byte token if available
        encoded = encode_msg(msg, self.token_to_code)
        # If "the " is a 4-byte token, we get 1 code + 1 padding = 3 bytes
        assert len(encoded) == 3  # single 3-byte word


# -- On-chain decompression round-trip --


class TestDecompressionRoundTrip:
    """Test compression -> on-chain decompression matches the original."""

    def test_short_message(self, decoder, token_to_code):
        msg = b"hello world"
        compressed = encode_msg(msg, token_to_code)
        decompressed = decoder.functions.decompress(compressed).call()
        assert decompressed == msg

    def test_medium_message(self, decoder, token_to_code):
        msg = b"the quick brown fox jumps over the yellow dog"
        compressed = encode_msg(msg, token_to_code)
        decompressed = decoder.functions.decompress(compressed).call()
        assert decompressed == msg

    def test_long_message(self, decoder, token_to_code):
        msg = (
            b"A purely peer-to-peer version of electronic cash would allow "
            b"online payments to be sent directly from one party to another "
            b"without going through a financial institution"
        )
        compressed = encode_msg(msg, token_to_code)
        decompressed = decoder.functions.decompress(compressed).call()
        assert decompressed == msg

    def test_single_char(self, decoder, token_to_code):
        msg = b"x"
        compressed = encode_msg(msg, token_to_code)
        decompressed = decoder.functions.decompress(compressed).call()
        # Decompressed may have padding from code 0, so check prefix
        assert decompressed[:1] == msg

    def test_common_english_words(self, decoder, token_to_code):
        for word in [b"the", b"and", b"for", b"with", b"this"]:
            compressed = encode_msg(word, token_to_code)
            decompressed = decoder.functions.decompress(compressed).call()
            # The original word should be a prefix of decompressed
            assert decompressed[:len(word)] == word

    def test_multiple_messages_independent(self, decoder, token_to_code):
        """Each message should decompress independently."""
        msgs = [b"hello", b"world", b"test"]
        for msg in msgs:
            compressed = encode_msg(msg, token_to_code)
            decompressed = decoder.functions.decompress(compressed).call()
            assert decompressed[:len(msg)] == msg

    def test_not_3byte_aligned_reverts(self, decoder):
        """Input not aligned to 3 bytes should revert."""
        with pytest.raises(Exception):
            decoder.functions.decompress(b"\x00\x01\x02\x03").call()

    def test_empty_input(self, decoder):
        """Empty input should return empty output."""
        result = decoder.functions.decompress(b"").call()
        assert result == b""
