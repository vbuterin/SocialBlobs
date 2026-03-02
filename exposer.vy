# @version ^0.4.3
#
# exposer.vy -- IERC_BAM_Exposer (ERC-8180).
#
# Proves individual messages on-chain from registered batches. Enables smart
# contracts to react to specific messages (governance, token gates, disputes).
#
# Message ID: keccak256(abi.encodePacked(author, nonce, contentHash))
#   - author:      message author's Ethereum address (20 bytes)
#   - nonce:       per-author monotonically increasing counter (uint64, 8 bytes)
#   - contentHash: batch identifier (bytes32, 32 bytes)
#
# The exposer checks that the batch was registered in the BAM Core contract,
# prevents double-exposure, and emits MessageExposed for indexers.

# ── Interfaces ───────────────────────────────────────────────────────────────

interface BAMCore:
    def registered(contentHash: bytes32) -> bool: view

# ── Events ───────────────────────────────────────────────────────────────────

event MessageExposed:
    contentHash: indexed(bytes32)
    messageId:   indexed(bytes32)
    author:      indexed(address)
    exposer:     address
    timestamp:   uint64

# ── Storage ──────────────────────────────────────────────────────────────────

bamCore: public(address)
exposed: public(HashMap[bytes32, bool])

# ── Constructor ──────────────────────────────────────────────────────────────

@deploy
def __init__(bam_core: address):
    """Initialize the exposer with a reference to the BAM Core contract.

    Parameters:
        bam_core: Address of the deployed BAM Core (ERC-8180) contract.
    """
    assert bam_core != empty(address), "InvalidCoreAddress"
    self.bamCore = bam_core

# ── View Functions ───────────────────────────────────────────────────────────

@external
@view
def isExposed(messageId: bytes32) -> bool:
    """Check whether a message has already been exposed.

    Parameters:
        messageId: The message ID to check.

    Returns:
        True if the message has been exposed, False otherwise.
    """
    return self.exposed[messageId]


@external
@pure
def computeMessageId(author: address, nonce: uint64, contentHash: bytes32) -> bytes32:
    """Compute the message ID per ERC-8180 convention.

    messageId = keccak256(abi.encodePacked(author, nonce, contentHash))
      - author:      20 bytes
      - nonce:       8 bytes (uint64, big-endian)
      - contentHash: 32 bytes

    Parameters:
        author:      The message author's Ethereum address.
        nonce:       The per-author monotonically increasing nonce.
        contentHash: The batch content hash (versioned hash or keccak256).

    Returns:
        The computed message ID.
    """
    return keccak256(
        concat(
            convert(author, bytes20),
            convert(nonce, bytes8),
            contentHash,
        )
    )

# ── Exposure ─────────────────────────────────────────────────────────────────

@external
def exposeMessage(batchContentHash: bytes32, author: address, nonce: uint64, contentHash: bytes32):
    """Prove that a specific message exists in a registered batch on-chain.

    Verifies the batch is registered in the BAM Core contract, computes the
    message ID, checks for double-exposure, records it, and emits
    MessageExposed.

    Parameters:
        batchContentHash: The content hash of the registered batch
                          (versioned hash for blobs, keccak256 for calldata).
        author:           The message author's Ethereum address.
        nonce:            The per-author monotonically increasing nonce.
        contentHash:      The content hash used in the message ID computation.
    """
    # Verify the batch is registered in the BAM Core contract
    isRegistered: bool = staticcall BAMCore(self.bamCore).registered(batchContentHash)
    assert isRegistered, "NotRegistered"

    # Compute message ID: keccak256(author || nonce || contentHash)
    messageId: bytes32 = keccak256(
        concat(
            convert(author, bytes20),
            convert(nonce, bytes8),
            contentHash,
        )
    )

    # Prevent double-exposure
    assert not self.exposed[messageId], "AlreadyExposed"

    # Record exposure
    self.exposed[messageId] = True

    # Emit event
    log MessageExposed(
        contentHash=batchContentHash,
        messageId=messageId,
        author=author,
        exposer=msg.sender,
        timestamp=convert(block.timestamp, uint64),
    )
