"""bam_client.py

Python client for the BAM JSON-RPC server.

Usage:
    from bam_client import BAMClient

    client = BAMClient("http://localhost:8545")
    status = client.status()
    compressed = client.compress(b"hello world")
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, List, Optional


class BAMClientError(Exception):
    """Error returned by the BAM RPC server."""
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.rpc_message = message
        self.data = data
        super().__init__(f"RPC error {code}: {message}")


class BAMClient:
    """Synchronous JSON-RPC client for the BAM server."""

    def __init__(self, url: str = "http://localhost:8545"):
        self.url = url
        self._id = 0

    def _call(self, method: str, params: Any = None) -> Any:
        self._id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": self._id,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read())

        if "error" in body:
            err = body["error"]
            raise BAMClientError(err["code"], err["message"], err.get("data"))
        return body["result"]

    def encode_batch(
        self,
        messages: List[Dict[str, Any]],
        private_keys: List[str],
    ) -> Dict:
        """Encode and sign a batch of messages.

        Args:
            messages: List of {"sender": "0x...", "nonce": int, "contents": "0x..."}.
            private_keys: List of hex-encoded private keys.

        Returns:
            {"blob": "0x...", "numMessages": int, "compressedSize": int, "signature": "0x..."}.
        """
        return self._call("bam_encodeBatch", [messages, private_keys])

    def decode_batch(self, payload: str) -> List[Dict]:
        """Decode a blob/calldata payload.

        Args:
            payload: 0x-prefixed hex-encoded blob.

        Returns:
            List of {"sender": "0x...", "nonce": int, "contents": "0x..."}.
        """
        return self._call("bam_decodeBatch", [payload])

    def verify_batch(self, payload: str, pubkeys: List[str]) -> Dict:
        """Verify aggregate BLS signature.

        Args:
            payload: 0x-prefixed hex-encoded blob.
            pubkeys: List of 0x-prefixed hex-encoded 128-byte public keys.

        Returns:
            {"valid": bool, "numMessages": int, "error": str | None}.
        """
        return self._call("bam_verifyBatch", [payload, pubkeys])

    def compress(self, data: bytes) -> str:
        """Compress raw bytes with BPE.

        Args:
            data: Raw bytes to compress.

        Returns:
            0x-prefixed hex-encoded compressed bytes.
        """
        return self._call("bam_compress", ["0x" + data.hex()])

    def decompress(self, data: str) -> str:
        """Decompress BPE-encoded bytes.

        Args:
            data: 0x-prefixed hex-encoded compressed bytes.

        Returns:
            0x-prefixed hex-encoded decompressed bytes.
        """
        return self._call("bam_decompress", [data])

    def get_dictionary(self) -> Dict:
        """Return the current dictionary metadata."""
        return self._call("bam_getDictionary")

    def status(self) -> Dict:
        """Return server health and configuration."""
        return self._call("bam_status")
