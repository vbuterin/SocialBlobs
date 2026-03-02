"""blob_encoder.py

Encodes a batch of signed messages into the binary blob format expected
by decoder.vy.

Blob layout:
    [0:2]       N                 — number of messages (uint16, big-endian)
    [2:2+2N]    offsets[0..N-1]   — per-message start offset (uint16, big-endian)
    [2+2N:−256] message bodies    — each: sender (20 B) | nonce (8 B) | contents
    [−256:]     aggregate BLS signature (256 bytes)
"""

from __future__ import annotations

import os
import struct
from typing import List, Tuple

from data_signer import aggregate_signatures

# (sender: str | bytes, nonce: int, contents: bytes)
MessageTuple = Tuple[bytes | str, int, bytes]


def _parse_sender(sender: bytes | str) -> bytes:
    if isinstance(sender, str):
        if not sender.startswith("0x"):
            raise ValueError(f"string sender must be 0x-prefixed, got {sender!r}")
        sender = bytes.fromhex(sender[2:])
    if len(sender) != 20:
        raise ValueError(f"sender must be 20 bytes, got {len(sender)}")
    return sender


def encode_blob(messages: List[MessageTuple], signatures: List[bytes], compressor: "function") -> bytes:
    """Encode *messages* and their *signatures* into a single blob.

    Args:
        messages:   List of (sender, nonce, contents) tuples.
                    Sender may be a 20-byte ``bytes`` or a 0x-prefixed hex string.
        signatures: Per-message BLS signatures; must be the same length as messages.

    Returns:
        Serialised blob bytes.
    """
    n = len(messages)
    if len(signatures) != n:
        raise ValueError("messages and signatures must have the same length")

    bodies: List[bytes] = []
    for sender, nonce, content in messages:
        content = compressor(content)
        sender_bytes = _parse_sender(sender)
        if not (0 <= nonce < (1 << 64)):
            raise ValueError(f"nonce {nonce} does not fit in 8 bytes")
        bodies.append(sender_bytes + nonce.to_bytes(8, "big") + content)

    # Header: [N (2 B)] [offset_0 (2 B)] … [offset_{N-1} (2 B)]
    header = bytearray(struct.pack("!H", n))
    offset = 2 + 2 * n
    for body in bodies:
        if offset >= (1 << 16):
            raise ValueError(f"offset {offset} exceeds 16-bit limit")
        header += struct.pack("!H", offset)
        offset += len(body)

    agg_sig = aggregate_signatures(signatures)
    if len(agg_sig) != 256:
        raise ValueError("aggregate signature must be 256 bytes")

    return bytes(header) + b"".join(bodies) + agg_sig


if __name__ == "__main__":
    from data_signer import Signer

    senders  = ["0x" + os.urandom(20).hex() for _ in range(3)]
    nonces   = [0, 1, 2]
    contents = [
        b"hello world",
        b"foo bar",
        b"the quick brown fox jumps over the yellow dog"
    ]
    signers  = [Signer.generate() for _ in range(3)]
    sigs     = [s.sign(c) for s, c in zip(signers, contents)]

    blob = encode_blob(list(zip(senders, nonces, contents)), sigs, lambda x: x)
    print(f"Generated blob: {len(blob)} bytes")
    with open("out.blob", "wb") as fh:
        fh.write(blob)
    print("Written to out.blob")
