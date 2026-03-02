# @version ^0.4.3
#
# bam_core.vy -- IERC_BAM_Core (ERC-8180) extending IERC_BSS (ERC-8179).
#
# Implements the on-chain registration point for blob-authenticated messaging.
# Aggregators and self-publishing users call registerBlobBatch or
# registerCalldataBatch to declare that a batch exists. The core stores
# batch registrations and emits events that indexers use to discover batches.
#
# BSS (ERC-8179) provides blob segment declaration with field element bounds.
# BAM (ERC-8180) extends BSS with decoder and signature registry pointers.

# ── Constants ────────────────────────────────────────────────────────────────

MAX_FIELD_ELEMENTS: constant(uint16) = 4096
MAX_BATCH_DATA: constant(uint256) = 131072  # 128 KiB max calldata batch

# ── Events ───────────────────────────────────────────────────────────────────

# ERC-8179 (BSS) event
event BlobSegmentDeclared:
    versionedHash: indexed(bytes32)
    submitter:     indexed(address)
    startFE:       uint16
    endFE:         uint16
    contentTag:    bytes32

# ERC-8180 (BAM) events
event BlobBatchRegistered:
    versionedHash:     indexed(bytes32)
    submitter:         indexed(address)
    decoder:           indexed(address)
    signatureRegistry: address

event CalldataBatchRegistered:
    contentHash:       indexed(bytes32)
    submitter:         indexed(address)
    decoder:           indexed(address)
    signatureRegistry: address

# ── Storage ──────────────────────────────────────────────────────────────────

# Tracks registered batch content hashes (versioned hash or keccak256 of calldata).
registered: public(HashMap[bytes32, bool])

# ── BSS Interface (ERC-8179) ─────────────────────────────────────────────────

@external
def declareBlobSegment(blobIndex: uint256, startFE: uint16, endFE: uint16, contentTag: bytes32) -> bytes32:
    """Declare a blob segment with field element bounds.

    Validates segment coordinates and retrieves the versioned hash via BLOBHASH.
    Emits BlobSegmentDeclared per ERC-8179.

    Parameters:
        blobIndex:  Index of the blob within the transaction (0-based).
        startFE:    Start field element (inclusive). Must be < endFE.
        endFE:      End field element (exclusive). Must be <= 4096.
        contentTag: Protocol/content identifier.

    Returns:
        versionedHash: The EIP-4844 versioned hash of the blob.
    """
    assert startFE < endFE, "InvalidSegment: startFE >= endFE"
    assert endFE <= MAX_FIELD_ELEMENTS, "InvalidSegment: endFE > 4096"

    versionedHash: bytes32 = blobhash(blobIndex)
    assert versionedHash != empty(bytes32), "NoBlobAtIndex"

    log BlobSegmentDeclared(
        versionedHash=versionedHash,
        submitter=msg.sender,
        startFE=startFE,
        endFE=endFE,
        contentTag=contentTag,
    )
    return versionedHash

# ── BAM Core Interface (ERC-8180) ───────────────────────────────────────────

@external
def registerBlobBatch(
    blobIndex: uint256,
    startFE: uint16,
    endFE: uint16,
    contentTag: bytes32,
    decoder: address,
    signatureRegistry: address,
) -> bytes32:
    """Register a blob batch with segment coordinates, decoder, and signature registry.

    Calls declareBlobSegment internally (BSS validation), then emits
    BlobBatchRegistered. Stores the versioned hash as registered.

    Parameters:
        blobIndex:         Index of the blob within the transaction (0-based).
        startFE:           Start field element (inclusive). Must be < endFE.
        endFE:             End field element (exclusive). Must be <= 4096.
        contentTag:        Protocol/content identifier.
        decoder:           Decoder contract address for extracting messages.
        signatureRegistry: Signature registry address for verifying signatures.

    Returns:
        versionedHash: The EIP-4844 versioned hash of the blob.
    """
    # BSS validation: segment bounds and BLOBHASH retrieval
    assert startFE < endFE, "InvalidSegment: startFE >= endFE"
    assert endFE <= MAX_FIELD_ELEMENTS, "InvalidSegment: endFE > 4096"

    versionedHash: bytes32 = blobhash(blobIndex)
    assert versionedHash != empty(bytes32), "NoBlobAtIndex"

    # Emit BSS event first (per spec: declareBlobSegment before BlobBatchRegistered)
    log BlobSegmentDeclared(
        versionedHash=versionedHash,
        submitter=msg.sender,
        startFE=startFE,
        endFE=endFE,
        contentTag=contentTag,
    )

    # Record registration
    self.registered[versionedHash] = True

    # Emit BAM event
    log BlobBatchRegistered(
        versionedHash=versionedHash,
        submitter=msg.sender,
        decoder=decoder,
        signatureRegistry=signatureRegistry,
    )
    return versionedHash


@external
def registerCalldataBatch(
    batchData: Bytes[MAX_BATCH_DATA],
    decoder: address,
    signatureRegistry: address,
) -> bytes32:
    """Register a batch submitted via calldata.

    Computes contentHash as keccak256(batchData), records it as registered,
    and emits CalldataBatchRegistered.

    Parameters:
        batchData:         The batch payload bytes.
        decoder:           Decoder contract address for extracting messages.
        signatureRegistry: Signature registry address for verifying signatures.

    Returns:
        contentHash: The keccak256 hash of batchData.
    """
    contentHash: bytes32 = keccak256(batchData)

    # Record registration
    self.registered[contentHash] = True

    # Emit BAM event
    log CalldataBatchRegistered(
        contentHash=contentHash,
        submitter=msg.sender,
        decoder=decoder,
        signatureRegistry=signatureRegistry,
    )
    return contentHash
