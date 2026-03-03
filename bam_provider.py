"""bam_provider.py

Pluggable BAM (Blob-Authenticated Messaging) provider interface and
default implementation wrapping the existing encode/decode/sign modules.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from data_signer import Signer, aggregate_signatures, verify_signature
from blob_encoder import encode_blob, signing_payload
from bpe_encode import build_10bit_dict_from_corpus, encode_msg


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class Message:
    """A decoded BAM message."""
    sender: str          # 0x-prefixed hex address
    nonce: int
    contents: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender": self.sender,
            "nonce": self.nonce,
            "contents": "0x" + self.contents.hex(),
        }


@dataclass
class BatchResult:
    """Result of encoding a batch."""
    blob: bytes
    num_messages: int
    compressed_size: int
    signature: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blob": "0x" + self.blob.hex(),
            "numMessages": self.num_messages,
            "compressedSize": self.compressed_size,
            "signature": "0x" + self.signature.hex(),
        }


@dataclass
class VerifyResult:
    """Result of verifying a batch."""
    valid: bool
    num_messages: int
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"valid": self.valid, "numMessages": self.num_messages}
        if self.error:
            d["error"] = self.error
        return d


@dataclass
class DictInfo:
    """Metadata about the BPE dictionary."""
    num_codes: int
    bits_per_code: int
    dict_bytes_size: int
    corpus_path: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "numCodes": self.num_codes,
            "bitsPerCode": self.bits_per_code,
            "dictBytesSize": self.dict_bytes_size,
            "corpusPath": self.corpus_path,
        }


@dataclass
class StatusResult:
    """Server status."""
    version: str
    provider: str
    dict_info: DictInfo
    signers_loaded: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "provider": self.provider,
            "dictInfo": self.dict_info.to_dict(),
            "signersLoaded": self.signers_loaded,
        }


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------

class BAMProvider(ABC):
    """Abstract base for BAM API backends.

    Implementations must provide encode, decode, verify, compress, and
    decompress functionality. The RPC server delegates all calls to
    whichever provider is plugged in.
    """

    @abstractmethod
    def encode_batch(
        self,
        messages: List[Tuple[str, int, bytes]],
        private_keys: List[int],
    ) -> BatchResult:
        """Sign and encode a batch of messages into a blob."""
        ...

    @abstractmethod
    def decode_batch(self, payload: bytes) -> List[Message]:
        """Decode a blob/calldata payload into messages."""
        ...

    @abstractmethod
    def verify_batch(
        self,
        payload: bytes,
        pubkeys: List[bytes],
    ) -> VerifyResult:
        """Verify the aggregate BLS signature of a batch."""
        ...

    @abstractmethod
    def compress(self, data: bytes) -> bytes:
        """Compress raw bytes with BPE."""
        ...

    @abstractmethod
    def decompress(self, data: bytes) -> bytes:
        """Decompress BPE-encoded bytes."""
        ...

    @abstractmethod
    def get_dictionary(self) -> DictInfo:
        """Return metadata about the loaded dictionary."""
        ...

    @abstractmethod
    def status(self) -> StatusResult:
        """Return server health and configuration."""
        ...


# ---------------------------------------------------------------------------
# Default implementation
# ---------------------------------------------------------------------------

class DefaultBAMProvider(BAMProvider):
    """Default provider using the existing Python modules."""

    def __init__(self, corpus_path: str = "corpus.txt"):
        self._corpus_path = corpus_path
        self._token_to_code, self._dict_bytes, self._dict_offs, self._dict_len = (
            build_10bit_dict_from_corpus(corpus_path)
        )
        self._signers: Dict[str, Signer] = {}

    def _compressor(self, data: bytes) -> bytes:
        return encode_msg(data, self._token_to_code)

    def register_signer(self, name: str, signer: Signer) -> str:
        """Register a named signer for use in encode_batch."""
        self._signers[name] = signer
        return name

    def encode_batch(
        self,
        messages: List[Tuple[str, int, bytes]],
        private_keys: List[int],
    ) -> BatchResult:
        signers = [Signer(secret=sk) for sk in private_keys]
        sigs = [
            s.sign(signing_payload(nonce, content))
            for s, (_, nonce, content) in zip(signers, messages)
        ]
        blob = encode_blob(messages, sigs, self._compressor)
        agg_sig = aggregate_signatures(sigs)
        return BatchResult(
            blob=blob,
            num_messages=len(messages),
            compressed_size=len(blob),
            signature=agg_sig,
        )

    def decode_batch(self, payload: bytes) -> List[Message]:
        import struct
        n = struct.unpack("!H", payload[:2])[0]
        offsets_end = 2 + n * 2
        starts = [
            struct.unpack("!H", payload[2 + i * 2: 4 + i * 2])[0]
            for i in range(n)
        ]
        sig_start = len(payload) - 256
        messages = []
        for i in range(n):
            start = starts[i]
            end = starts[i + 1] if i + 1 < n else sig_start
            sender = "0x" + payload[start:start + 20].hex()
            nonce = int.from_bytes(payload[start + 20:start + 28], "big")
            contents = payload[start + 28:end]
            messages.append(Message(sender=sender, nonce=nonce, contents=contents))
        return messages

    def verify_batch(
        self,
        payload: bytes,
        pubkeys: List[bytes],
    ) -> VerifyResult:
        try:
            from py_ecc.optimized_bls12_381 import G1, multiply, FQ
            messages = self.decode_batch(payload)
            if len(messages) != len(pubkeys):
                return VerifyResult(
                    valid=False,
                    num_messages=len(messages),
                    error=f"pubkey count ({len(pubkeys)}) != message count ({len(messages)})",
                )
            sig_bytes = payload[-256:]
            for i, (msg, pk_bytes) in enumerate(zip(messages, pubkeys)):
                payload_to_verify = signing_payload(msg.nonce, msg.contents)
                x = int.from_bytes(pk_bytes[:64], "big")
                y = int.from_bytes(pk_bytes[64:128], "big")
                pub_pt = (FQ(x), FQ(y), FQ(1))
                if not verify_signature(pub_pt, payload_to_verify, sig_bytes):
                    return VerifyResult(
                        valid=False,
                        num_messages=len(messages),
                        error=f"signature verification failed for message {i}",
                    )
            return VerifyResult(valid=True, num_messages=len(messages))
        except Exception as e:
            return VerifyResult(valid=False, num_messages=0, error=str(e))

    def compress(self, data: bytes) -> bytes:
        return encode_msg(data, self._token_to_code)

    def decompress(self, data: bytes) -> bytes:
        """Pure-Python BPE decompression (mirrors decoder.vy logic)."""
        if len(data) % 5 != 0:
            raise ValueError("encoded data not 5-byte aligned")

        # Build code-to-token reverse lookup
        code_to_token: dict[int, bytes] = {}
        for token, code in self._token_to_code.items():
            code_to_token[code] = token

        out = bytearray()
        for i in range(0, len(data), 5):
            word = int.from_bytes(data[i:i + 5], "big")
            codes = [
                (word >> 30) & 0x3FF,
                (word >> 20) & 0x3FF,
                (word >> 10) & 0x3FF,
                word & 0x3FF,
            ]
            for code in codes:
                if code == 0:
                    continue  # padding
                token = code_to_token.get(code)
                if token is not None:
                    out.extend(token)
        return bytes(out)

    def get_dictionary(self) -> DictInfo:
        return DictInfo(
            num_codes=len(self._token_to_code),
            bits_per_code=10,
            dict_bytes_size=len(self._dict_bytes),
            corpus_path=self._corpus_path,
        )

    def status(self) -> StatusResult:
        return StatusResult(
            version="0.1.0",
            provider="DefaultBAMProvider",
            dict_info=self.get_dictionary(),
            signers_loaded=len(self._signers),
        )
