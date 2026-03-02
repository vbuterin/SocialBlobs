# @version ^0.4.3
#
# signature_registry.vy — BLS12-381 signature registry.
#
# Verification equation (G1 keys, G2 signatures):
#   Single / aggregate:  ∏ e(pk_i, H(m_i)) · e(−G1, aggSig) = 1
#
# EIP-2537 PAIRING_CHECK takes concatenated (G1 ‖ G2) pairs, each 384 bytes:
#   G1 point : 128 bytes = 4 × bytes32
#   G2 point : 256 bytes = 8 × bytes32
#
# Variable-length calldata without loop-concat type errors:
#   Append words to a DynArray[bytes32] in a loop (no type tension).
#   Pad to MAX_WORDS so _abi_encode output is always a fixed size.
#   Route through the identity precompile (0x04) to obtain a Bytes value.
#   slice(out, 32, MAX_WORDS*32) strips the ABI length prefix with literal
#   offsets, leaving exactly MAX_PAIRS × 384 bytes for PAIRING_CHECK.
#   Zero-padded trailing pairs encode (∞, ∞), giving e(∞,∞) = 1 in GT.

# ── Precompiles ───────────────────────────────────────────────────────────────
SHA256_PC:           constant(address) = 0x0000000000000000000000000000000000000002
IDENTITY:            constant(address) = 0x0000000000000000000000000000000000000004
BIGMODEXP:           constant(address) = 0x0000000000000000000000000000000000000005
BLS12_G2ADD:         constant(address) = 0x000000000000000000000000000000000000000d
BLS12_MAP_FP2_TO_G2: constant(address) = 0x0000000000000000000000000000000000000011
BLS12_PAIRING_CHECK: constant(address) = 0x000000000000000000000000000000000000000F

# ── Pairing buffer sizing ─────────────────────────────────────────────────────
# To change the signer cap, update MAX_SIGNERS; everything else follows.
MAX_SIGNERS:  constant(uint256) = 64
MAX_PAIRS:    constant(uint256) = 65       # MAX_SIGNERS + 1 (the −G1 pair)
MAX_WORDS:    constant(uint256) = 780      # MAX_PAIRS × 12 words per pair
ABI_ENC_SIZE: constant(uint256) = 24992   # 32 (length prefix) + MAX_WORDS × 32
PAIRING_SIZE: constant(uint256) = 24960   # MAX_WORDS × 32  =  MAX_PAIRS × 384

# ── BLS domain separation tag ─────────────────────────────────────────────────
DST: constant(Bytes[255]) = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

# ── BLS12-381 field modulus p (48 bytes, split for BIGMODEXP concat) ──────────
# p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
P_HI: constant(bytes32) = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624
P_LO: constant(bytes16) = 0x1eabfffeb153ffffb9feffffffffaaab

# ── −G1 generator split into 4 × bytes32 for direct DynArray appending ───────
# G1.x = 0x17f1d3a7…c6bb  (unchanged under negation)
# −G1.y = p − G1.y = 0x114d1d68…c2ca
NEG_G1_W0: constant(bytes32) = 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f
NEG_G1_W1: constant(bytes32) = 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
NEG_G1_W2: constant(bytes32) = 0x00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f2
NEG_G1_W3: constant(bytes32) = 0x67816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca

# ── Storage ───────────────────────────────────────────────────────────────────
owner_pubkey: public(HashMap[address, Bytes[128]])
num_keys:     uint256
owner_index:  HashMap[address, uint256]

# ── Events ────────────────────────────────────────────────────────────────────
event KeyRegistered:
    owner:  indexed(address)
    pubKey: Bytes[128]
    index:  uint256

# ═════════════════════════════════════════════════════════════════════════════
# hash_to_G2  (RFC 9380 §5, EIP-2537)
#
# Pipeline matching py_ecc's hash_to_G2(message, DST, sha256):
#   1. expand_message_xmd(message, DST, 256)  →  256 pseudo-random bytes
#   2. hash_to_field_FQ2: four 64-byte chunks reduced mod p  →  u0, u1 ∈ FQ2
#   3. map_fp2_to_g2(u0), map_fp2_to_g2(u1)  via precompile 0x11
#      (SSWU + 3-isogeny + cofactor clearing handled by the precompile)
#   4. G2ADD(Q0, Q1)  via precompile 0x0d
#
# EIP-2537 encoding (big-endian throughout):
#   Fp   : 64 bytes; top 16 must be 0x00  (p < 2^381)
#   FQ2  : encode(c0) ‖ encode(c1) = 128 bytes
#   G2pt : encode(x) ‖ encode(y),  x, y ∈ FQ2  = 256 bytes
#
# FQ2 coefficient order: py_ecc FQ2([a, b]) = a + b·v, c0 = a, c1 = b.
# EIP-2537 encodes as encode(c0) ‖ encode(c1), matching concat(e[2i], e[2i+1]).
# ═════════════════════════════════════════════════════════════════════════════

@internal
@view
def _sha256(data: Bytes[1600]) -> bytes32:
    out: Bytes[32] = raw_call(
        SHA256_PC, data, max_outsize=32, gas=100000, is_static_call=True,
    )
    return convert(slice(out, 0, 32), bytes32)


@internal
@view
def _fp_mod_p(v: Bytes[64]) -> Bytes[64]:
    """Reduce a 64-byte big-endian integer mod p via BIGMODEXP(base=v, exp=1, mod=p).

    BIGMODEXP input layout:
      [0:32]    Blen = 64
      [32:64]   Elen = 1
      [64:96]   Mlen = 48
      [96:160]  base  (v)
      [160]     exp = 0x01
      [161:209] mod   (p, 48 bytes)

    Returns a 64-byte EIP-2537 Fp element (16 zero bytes ‖ 48-byte result).
    """
    raw: Bytes[48] = raw_call(
        BIGMODEXP,
        concat(
            convert(64, bytes32),  # Blen
            convert(1,  bytes32),  # Elen
            convert(48, bytes32),  # Mlen
            v,                     # base
            b"\x01",               # exp
            P_HI,                  # mod (high 32 bytes)
            P_LO,                  # mod (low  16 bytes)
        ),
        max_outsize=48,
        gas=100000,
        is_static_call=True,
    )
    return concat(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", raw)


@internal
@view
def _xmd(message: Bytes[1024], dst: Bytes[255]) -> Bytes[256]:
    """expand_message_xmd (RFC 9380 §5.4.1), H = SHA-256, len_in_bytes = 256.

    Returns b_1 ‖ b_2 ‖ … ‖ b_8  (256 bytes).
    """
    dst_prime: Bytes[256] = concat(dst, convert(convert(len(dst), uint8), bytes1))
    z_pad: Bytes[64] = concat(convert(0, bytes32), convert(0, bytes32))

    b0: bytes32 = self._sha256(concat(z_pad, message, b"\x01\x00", b"\x00", dst_prime))
    b1: bytes32 = self._sha256(concat(b0,        b"\x01", dst_prime))
    b2: bytes32 = self._sha256(concat(b0 ^ b1,   b"\x02", dst_prime))
    b3: bytes32 = self._sha256(concat(b0 ^ b2,   b"\x03", dst_prime))
    b4: bytes32 = self._sha256(concat(b0 ^ b3,   b"\x04", dst_prime))
    b5: bytes32 = self._sha256(concat(b0 ^ b4,   b"\x05", dst_prime))
    b6: bytes32 = self._sha256(concat(b0 ^ b5,   b"\x06", dst_prime))
    b7: bytes32 = self._sha256(concat(b0 ^ b6,   b"\x07", dst_prime))
    b8: bytes32 = self._sha256(concat(b0 ^ b7,   b"\x08", dst_prime))
    return concat(b1, b2, b3, b4, b5, b6, b7, b8)


@internal
@view
def _hash_to_g2(message: Bytes[1024], dst: Bytes[255]) -> Bytes[256]:
    """Map an arbitrary message to a G2 point (256-byte EIP-2537 encoding).

    Matches py_ecc hash_to_G2(message, DST, hashlib.sha256) exactly.
    Return layout:  x.c0 (64 B) ‖ x.c1 (64 B) ‖ y.c0 (64 B) ‖ y.c1 (64 B).
    """
    prb: Bytes[256] = self._xmd(message, dst)

    # hash_to_field_FQ2: four 64-byte chunks → two FQ2 elements u0, u1
    u0: Bytes[128] = concat(self._fp_mod_p(slice(prb,   0, 64)),
                            self._fp_mod_p(slice(prb,  64, 64)))
    u1: Bytes[128] = concat(self._fp_mod_p(slice(prb, 128, 64)),
                            self._fp_mod_p(slice(prb, 192, 64)))

    q0: Bytes[256] = raw_call(
        BLS12_MAP_FP2_TO_G2, u0, max_outsize=256, gas=100000, is_static_call=True,
    )
    q1: Bytes[256] = raw_call(
        BLS12_MAP_FP2_TO_G2, u1, max_outsize=256, gas=100000, is_static_call=True,
    )
    return raw_call(
        BLS12_G2ADD, concat(q0, q1), max_outsize=256, gas=100000, is_static_call=True,
    )


@external
@view
def hash_to_g2(message: Bytes[1024], dst: Bytes[255]) -> Bytes[256]:
    """Public entry point for hash_to_G2 (useful for off-chain testing)."""
    return self._hash_to_g2(message, dst)


# ═════════════════════════════════════════════════════════════════════════════
# Pairing helpers
# ═════════════════════════════════════════════════════════════════════════════

@internal
@pure
def _append_g1(buf: DynArray[bytes32, 780], pt: Bytes[128]) -> DynArray[bytes32, 780]:
    """Append a G1 point (128 bytes = 4 words) to the pairing word buffer."""
    buf.append(extract32(pt,   0))
    buf.append(extract32(pt,  32))
    buf.append(extract32(pt,  64))
    buf.append(extract32(pt,  96))
    return buf


@internal
@pure
def _append_g2(buf: DynArray[bytes32, 780], pt: Bytes[256]) -> DynArray[bytes32, 780]:
    """Append a G2 point (256 bytes = 8 words) to the pairing word buffer."""
    buf.append(extract32(pt,   0))
    buf.append(extract32(pt,  32))
    buf.append(extract32(pt,  64))
    buf.append(extract32(pt,  96))
    buf.append(extract32(pt, 128))
    buf.append(extract32(pt, 160))
    buf.append(extract32(pt, 192))
    buf.append(extract32(pt, 224))
    return buf


@internal
@view
def _run_pairing(buf: DynArray[bytes32, 780]) -> bool:
    """Run BLS12_PAIRING_CHECK on a word buffer of (G1, G2) pairs.

    Pads buf to exactly MAX_WORDS with zero words. Zero pairs encode
    (∞, ∞) per EIP-2537, contributing e(∞, ∞) = 1 to the GT product.

    _abi_encode(DynArray, ensure_tuple=False) produces:
        [32-byte element count] [MAX_WORDS × 32-byte words]
    The identity precompile echoes this back as a Bytes value; slicing off
    the 32-byte prefix with literal offsets gives exactly PAIRING_SIZE bytes.
    """
    b: DynArray[bytes32, 780] = buf
    for _: uint256 in range(780):
        if len(b) >= MAX_WORDS:
            break
        b.append(empty(bytes32))

    encoded: Bytes[24992] = raw_call(
        IDENTITY,
        _abi_encode(b, ensure_tuple=False),
        max_outsize=24992,
        is_static_call=True,
    )
    res: Bytes[32] = raw_call(
        BLS12_PAIRING_CHECK,
        slice(encoded, 32, 24960),
        max_outsize=32,
        is_static_call=True,
    )
    return convert(slice(res, 31, 1), uint8) == 1


@internal
@view
def _append_neg_g1_pair(buf: DynArray[bytes32, 780], sig: Bytes[256]) -> DynArray[bytes32, 780]:
    """Append the final (−G1, sig) pair to the buffer."""
    buf.append(NEG_G1_W0)
    buf.append(NEG_G1_W1)
    buf.append(NEG_G1_W2)
    buf.append(NEG_G1_W3)
    return self._append_g2(buf, sig)


# ═════════════════════════════════════════════════════════════════════════════
# Scheme metadata
# ═════════════════════════════════════════════════════════════════════════════

@external
@view
def schemeId() -> uint8:
    return 2  # BLS12-381

@external
@view
def schemeName() -> String[32]:
    return "BLS12-381"

@external
@view
def pubKeySize() -> uint256:
    return 128

@external
@view
def signatureSize() -> uint256:
    return 256

@external
@view
def supportsAggregation() -> bool:
    return True

# ═════════════════════════════════════════════════════════════════════════════
# Registration
# ═════════════════════════════════════════════════════════════════════════════

@internal
@view
def _verify_pop(pubKey: Bytes[128], popSig: Bytes[256]) -> bool:
    """Check proof-of-possession: e(pubKey, H("BLS_POP")) · e(−G1, popSig) = 1."""
    buf: DynArray[bytes32, 780] = []
    buf = self._append_g1(buf, pubKey)
    buf = self._append_g2(buf, self._hash_to_g2(b"BLS_POP", DST))
    buf = self._append_neg_g1_pair(buf, popSig)
    return self._run_pairing(buf)


@external
@payable
def register(pubKey: Bytes[128], popProof: Bytes[256]):
    """Register a BLS public key with a proof-of-possession."""
    assert len(pubKey) == 128, "Invalid public key length"
    assert len(popProof) == 256, "Invalid POP length"
    assert self._verify_pop(pubKey, popProof), "InvalidProofOfPossession"
    self.owner_pubkey[msg.sender] = pubKey
    idx: uint256 = self.num_keys
    self.owner_index[msg.sender] = idx
    self.num_keys += 1
    log KeyRegistered(owner=msg.sender, pubKey=pubKey, index=idx)

# ═════════════════════════════════════════════════════════════════════════════
# Verification
# ═════════════════════════════════════════════════════════════════════════════

@internal
@view
def _verify(pubKey: Bytes[128], message: Bytes[1024], sig: Bytes[256]) -> bool:
    """Core BLS check: e(pubKey, H(message)) · e(−G1, sig) = 1."""
    buf: DynArray[bytes32, 780] = []
    buf = self._append_g1(buf, pubKey)
    buf = self._append_g2(buf, self._hash_to_g2(message, DST))
    buf = self._append_neg_g1_pair(buf, sig)
    return self._run_pairing(buf)


@external
@view
def verify(pubKey: Bytes[128], message: Bytes[1024], signature: Bytes[256]) -> bool:
    """Verify a BLS signature against an explicit public key."""
    return self._verify(pubKey, message, signature)


@external
@view
def verifyWithRegisteredKey(owner: address, message: Bytes[1024], signature: Bytes[256]) -> bool:
    """Verify a BLS signature using the public key registered for owner."""
    pubKey: Bytes[128] = self.owner_pubkey[owner]
    assert pubKey != b"", "NotRegistered"
    return self._verify(pubKey, message, signature)


@external
@view
def verifyAggregated(
    owners:              DynArray[address, 64],
    messages:            DynArray[Bytes[1024], 64],
    aggregatedSignature: Bytes[256],
) -> bool:
    """Verify an aggregate BLS signature: ∏ e(pk_i, H(m_i)) · e(−G1, aggSig) = 1.

    All owners must be registered. Inactive trailing pair slots are zero-padded,
    encoding (∞, ∞) which contributes 1 to the GT product.
    """
    n: uint256 = len(owners)
    assert n > 0,              "Empty signer list"
    assert n == len(messages), "Array length mismatch"

    buf: DynArray[bytes32, 780] = []
    for i: uint256 in range(64):
        if i >= n:
            break
        pubKey: Bytes[128] = self.owner_pubkey[owners[i]]
        assert pubKey != b"", "NotRegistered"
        buf = self._append_g1(buf, pubKey)
        buf = self._append_g2(buf, self._hash_to_g2(messages[i], DST))

    buf = self._append_neg_g1_pair(buf, aggregatedSignature)
    return self._run_pairing(buf)

# ═════════════════════════════════════════════════════════════════════════════
# Queries
# ═════════════════════════════════════════════════════════════════════════════

@external
@view
def getKey(owner: address) -> Bytes[128]:
    return self.owner_pubkey[owner]


@external
@view
def isRegistered(owner: address) -> bool:
    return self.owner_pubkey[owner] != b""
