# SocialBlobs

[![Tests](https://github.com/vbuterin/SocialBlobs/actions/workflows/test.yml/badge.svg)](https://github.com/vbuterin/SocialBlobs/actions/workflows/test.yml)
[![License: CC0-1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)](https://creativecommons.org/publicdomain/zero/1.0/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Vyper 0.4.3+](https://img.shields.io/badge/vyper-0.4.3+-green.svg)](https://github.com/vyperlang/vyper)

An implementation of [ERC-8180 (Blob Authenticated Messaging)](https://github.com/ethereum/ERCs/pull/1578) and [ERC-8179 (Blob Space Segments)](https://github.com/ethereum/ERCs/pull/1577) -- a minimalistic "social on Ethereum blobs/calldata" protocol.

## Overview

SocialBlobs enables authenticated social messaging on Ethereum using blobs or calldata. Messages are signed with BLS12-381 keys, packed into a compact binary format, and registered on-chain with a decoder and signature registry pointer. Individual messages can then be "exposed" (proven) on-chain for smart contract consumption.

**Key features:**
- BLS12-381 aggregate signature verification via EIP-2537 precompiles
- Compact binary blob format: `[count][offsets][sender|nonce|contents...][aggregate_sig]`
- On-chain hash-to-G2 matching py_ecc reference (RFC 9380)
- Message exposure with `messageId = keccak256(author || nonce || contentHash)`
- Zero-storage event-only batch registration

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the full integration test
python test.py

# Run the pytest suite
pytest -v
```

## Architecture

```
                  Off-chain                          On-chain
           ┌─────────────────┐          ┌──────────────────────────┐
           │  data_signer.py │          │     bam_core.vy          │
           │  (BLS12-381     │          │  (BSS + BAM Core)        │
           │   sign/verify)  │          │  registerCalldataBatch() │
           └────────┬────────┘          │  declareBlobSegment()    │
                    │                   └────────────┬─────────────┘
                    ▼                                │
           ┌─────────────────┐                       ▼
           │ blob_encoder.py │          ┌──────────────────────────┐
           │ (binary format) │────────► │     decoder.vy           │
           └─────────────────┘          │  (IERC_BAM_Decoder)      │
                                        │  decode() → messages     │
                                        └──────────────────────────┘
                                                     │
                    ┌────────────────────────────────┤
                    ▼                                ▼
           ┌─────────────────┐          ┌──────────────────────────┐
           │signature_registry│         │     exposer.vy           │
           │     .vy         │          │  (IERC_BAM_Exposer)      │
           │ register()/     │          │  exposeMessage()         │
           │ verifyAggregated│          │  isExposed()             │
           └─────────────────┘          └──────────────────────────┘
```

## ERC Coverage

| Interface | File | Status |
|-----------|------|--------|
| **IERC_BSS** (ERC-8179) -- Blob Space Segments | `bam_core.vy` | `declareBlobSegment` + `BlobSegmentDeclared` event |
| **IERC_BAM_Core** (ERC-8180) -- Batch Registration | `bam_core.vy` | `registerBlobBatch` + `registerCalldataBatch` |
| **IERC_BAM_Decoder** (ERC-8180) -- Message Decoding | `decoder.vy` | `decode()` returning messages + signature data |
| **IERC_BAM_SignatureRegistry** (ERC-8180) -- Key Registry | `signature_registry.vy` | BLS12-381 scheme with registration, verification, aggregation |
| **IERC_BAM_Exposer** (ERC-8180) -- Message Exposure | `exposer.vy` | `exposeMessage` + `isExposed` + `MessageExposed` event |

## Blob Format

```
Offset    Size    Field
──────    ────    ─────
0         2       N (message count, uint16 big-endian)
2         2*N     offsets[0..N-1] (per-message start, uint16 big-endian)
2+2*N     var     message bodies: sender (20B) | nonce (8B) | contents
-256      256     aggregate BLS signature (G2 point, uncompressed)
```

## Files

| File | Description |
|------|-------------|
| `bam_core.vy` | BAM Core contract -- BSS segment declaration + batch registration (ERC-8179/8180) |
| `decoder.vy` | Blob decoder -- extracts messages and aggregate BLS signature from payload |
| `signature_registry.vy` | BLS12-381 signature registry -- key registration with PoP, single + aggregate verification |
| `exposer.vy` | Message exposer -- on-chain message proving with ERC-8180 message ID formula |
| `blob_encoder.py` | Python encoder -- constructs binary blob format from messages + signatures |
| `data_signer.py` | Python BLS12-381 signing -- key generation, signing, aggregation, verification |
| `test.py` | End-to-end integration test -- deploys all contracts, full flow |
| `test_blob_encoder.py` | Unit tests for blob encoding (sender parsing, format, roundtrip) |
| `test_data_signer.py` | Unit tests for BLS signing (keygen, sign, verify, PoP, aggregation) |
| `test_decoder.py` | Unit tests for on-chain decoder (valid blobs, edge cases, errors) |
| `test_signature_registry.py` | Unit tests for signature registry (registration, verification, metadata) |
| `test_e2e.py` | Full pipeline tests (sign -> encode -> register -> decode -> verify -> expose) |
| `hash_to_point_test.py` | hash_to_G2 test -- verifies Vyper matches py_ecc reference |

## Testing

```bash
# Run all pytest tests
pytest -v

# Run specific test suites
pytest test_blob_encoder.py -v      # Blob encoding
pytest test_data_signer.py -v       # BLS signing
pytest test_decoder.py -v           # On-chain decoder
pytest test_signature_registry.py -v # Signature registry
pytest test_e2e.py -v               # End-to-end integration
pytest hash_to_point_test.py -v     # hash_to_G2 verification

# Run the original integration script
python test.py
```

## Dependencies

- **[py_ecc](https://github.com/ethereum/py_ecc)** -- BLS12-381 elliptic curve operations
- **[web3.py](https://github.com/ethereum/web3.py)** -- Ethereum interaction and testing
- **[Vyper](https://github.com/vyperlang/vyper)** -- Smart contract compiler (^0.4.3)
- **[eth-tester](https://github.com/ethereum/eth-tester)** -- In-memory test chain

## Related

- [ERC-8180: Blob Authenticated Messaging (BAM)](https://ethereum-magicians.org/t/blob-authenticated-messaging-bam/27868)
- [ERC-8179: Blob Space Segments (BSS)](https://ethereum-magicians.org/t/blob-space-segments-bss/27867)
- [ERC-8180 Pull Request](https://github.com/ethereum/ERCs/pull/1578)
- [ERC-8179 Pull Request](https://github.com/ethereum/ERCs/pull/1577)
- [EIP-2537: BLS12-381 Precompiles](https://eips.ethereum.org/EIPS/eip-2537)
- [EIP-4844: Shard Blob Transactions](https://eips.ethereum.org/EIPS/eip-4844)

## License

[CC0 1.0 Universal](LICENSE) -- Public Domain
