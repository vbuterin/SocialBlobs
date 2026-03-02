# @version ^0.4.3
#
# decoder.vy — IERC_BAM_Decoder implementation.
#
# Blob format:
#   [0:2]       N                 — number of messages (uint16, big-endian)
#   [2:2+2N]    offsets[0..N-1]   — per-message start offset (uint16, big-endian)
#   [2+2N:−256] message bodies    — each: sender (20 B) | nonce (8 B) | contents
#   [−256:]     aggregate BLS signature (256 bytes)

MAX_MESSAGES: constant(uint256) = 64
MAX_MSG_LEN:  constant(uint256) = 256
MAX_PAYLOAD:  constant(uint256) = 4096

SENDER_SIZE: constant(uint256) = 20
NONCE_SIZE:  constant(uint256) = 8
HEADER_SIZE: constant(uint256) = 28  # SENDER_SIZE + NONCE_SIZE
SIG_SIZE:    constant(uint256) = 256

struct Message:
    sender:   address
    nonce:    uint64
    contents: Bytes[MAX_PAYLOAD]


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
            contents=      slice(payload, start + HEADER_SIZE, msg_len),
        ))

    return messages, slice(payload, sig_start, SIG_SIZE)
