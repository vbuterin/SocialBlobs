# @version ^0.4.3
#
# decoder.vy -- IERC_BAM_Decoder implementation.
#
# Blob format:
#   [0:2]       N                 -- number of messages (uint16, big-endian)
#   [2:2+2N]    offsets[0..N-1]   -- per-message start offset (uint16, big-endian)
#   [2+2N:-256] message bodies    -- each: sender (20 B) | nonce (8 B) | contents
#   [-256:]     aggregate BLS signature (256 bytes)

MAX_MESSAGES: constant(uint256) = 64
MAX_MSG_LEN:  constant(uint256) = 256
MAX_MSG_WORDS: constant(uint256) = 8
MAX_PAYLOAD:  constant(uint256) = 4096

SENDER_SIZE: constant(uint256) = 20
NONCE_SIZE:  constant(uint256) = 8
HEADER_SIZE: constant(uint256) = 28  # SENDER_SIZE + NONCE_SIZE
SIG_SIZE:    constant(uint256) = 256

IDENTITY:            constant(address) = 0x0000000000000000000000000000000000000004

struct Message:
    sender:   address
    nonce:    uint64
    contents: Bytes[MAX_PAYLOAD]

DICT_BYTES: Bytes[10240]

# ------------------------------------------------------------
# 2  Constructor -- initialise with the dictionary blob
# ------------------------------------------------------------
@deploy
def __init__(dict_bytes: Bytes[10240]):
    self.DICT_BYTES = dict_bytes

# ------------------------------------------------------------
# 3  Helper -- unpack a 3-byte word into two 12-bit codes
# ------------------------------------------------------------
@internal
@view
def _unpack(word: uint256) -> uint256[2]:
    out: uint256[2] = [0, 0]
    out[0] = (word >> 12) & 4095
    out[1] = word & 4095
    return out

# ------------------------------------------------------------
# 4  Decode -- turn 3-byte blocks back into the original message
# ------------------------------------------------------------
# (Maximum encoded length is 3000 bytes -> 1000 words -> 2000 decoded bytes)

@internal
@view
def _decompress(encoded: Bytes[5000]) -> Bytes[MAX_MSG_LEN]:
    """
    `encoded` must be a multiple of 3 bytes.
    Returns the decoded message.
    """
    assert len(encoded) % 3 == 0, "encoded data not 3 byte aligned"
    assert len(encoded) <= 3000, "input too long"

    out: bytes32[MAX_MSG_WORDS] = empty(bytes32[MAX_MSG_WORDS])
    i: uint256 = 0
    pos_in_out: uint256 = 0


    for round: uint256 in range(MAX_MSG_LEN):
        if i >= len(encoded):
            outbytes: Bytes[MAX_MSG_LEN] = raw_call(
                IDENTITY,
                abi_encode(out, ensure_tuple=False),
                max_outsize=MAX_MSG_LEN,
                is_static_call=True,
            )
            return slice(outbytes, 0, pos_in_out)
        # turn 3 bytes into 24-bit word
        word: uint256 = convert(slice(encoded, i, 3), uint256)

        # expand into 2 codes
        c: uint256[2] = self._unpack(word)

        offs: uint256 = 0
        ln: uint256 = 0


        # helper -- compute offset & length for a single code
        for code: uint256 in c:
            # ---------- compute offset ----------
            if code < 1024:
                offs = code * 4          # 4-byte tokens
                ln = 4
            elif code < 2048:
                offs = 1024 * 4 + (code - 1024) * 3
                ln   = 3
            elif code < 3072:
                offs = 1024 * 4 + 1024 * 3 + (code - 2048) * 2
                ln   = 2
            else:
                offs = 1024 * 4 + 1024 * 3 + 1024 * 2 + (code - 3072)
                ln   = 1

            # ---------- sanity ----------
            assert offs + ln <= 10240, "dictionary index out of bounds"
            assert pos_in_out + ln <= MAX_MSG_LEN, "output buffer overflow"

            # ---------- append ----------
            if code > 0:
                for k:uint256 in range(ln, bound=4):
                    byte_to_add: uint256 = convert(convert(
                        slice(self.DICT_BYTES, offs + k, 1),
                    uint8), uint256)
                    out[(pos_in_out + k) // 32] ^= (
                        convert(byte_to_add << (248 - 8 * ((pos_in_out + k) % 32)),
                        bytes32)
                    )
                pos_in_out += ln
        i += 3

    raise "Should never get here, there's a bug"

@view
@external
def decompress(encoded: Bytes[5000]) -> Bytes[MAX_MSG_LEN]:
    return self._decompress(encoded)

@external
@view
def decode(payload: Bytes[MAX_PAYLOAD]) -> (DynArray[Message, MAX_MESSAGES], Bytes[256]):
    """Decode a message batch blob.

    Returns:
        messages:      Decoded message array (sender, nonce, contents).
        signatureData: The trailing 256-byte aggregate BLS signature.
    """
    payload_len: uint256 = len(payload)
    assert payload_len >= SIG_SIZE, "Payload too small: must contain signature"

    n: uint256 = convert(slice(payload, 0, 2), uint256)
    assert n <= MAX_MESSAGES, "Too many messages"

    offsets_end: uint256 = 2 + n * 2
    assert offsets_end <= payload_len, "Offsets exceed payload length"

    # Read all message start offsets.
    starts: DynArray[uint256, MAX_MESSAGES] = []
    for i: uint256 in range(MAX_MESSAGES):
        if i >= n:
            break
        starts.append(convert(slice(payload, 2 + i * 2, 2), uint256))

    sig_start: uint256 = payload_len - SIG_SIZE

    # Decode each message body: sender (20 B) | nonce (8 B) | contents.
    messages: DynArray[Message, MAX_MESSAGES] = []
    for i: uint256 in range(MAX_MESSAGES):
        if i >= n:
            break
        start: uint256 = starts[i]
        end:   uint256 = starts[i + 1] if i + 1 < n else sig_start
        msg_len: uint256 = end - start - HEADER_SIZE
        assert msg_len <= MAX_MSG_LEN, "Message too long"
        messages.append(Message(
            sender=convert(slice(payload, start,              SENDER_SIZE), address),
            nonce=convert( slice(payload, start + SENDER_SIZE, NONCE_SIZE), uint64),
            contents=self._decompress(slice(payload, start + HEADER_SIZE, msg_len)),
        ))

    return messages, slice(payload, sig_start, SIG_SIZE)
