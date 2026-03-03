<h1 align="center">SocialBlobs</h1>

<p align="center">
  <strong>Blob-Authenticated Messaging for Ethereum</strong>
  <br />
  Reference implementation of <a href="https://github.com/ethereum/ERCs/pull/1578">ERC-8180</a> (BAM) and <a href="https://github.com/ethereum/ERCs/pull/1577">ERC-8179</a> (BSS)
</p>

<p align="center">
  <a href="https://github.com/vbuterin/SocialBlobs/actions"><img src="https://github.com/vbuterin/SocialBlobs/actions/workflows/test.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/tests-144%2B-brightgreen" alt="Tests 144+" />
</p>

> **Warning** — This is an experimental research project. The contracts and tooling are unaudited. Do not use in production without independent review.

**Quick links:** [Quick Start](#quick-start) | [Architecture](#architecture) | [Project Structure](#project-structure) | [API Reference](#related-standards) | [Contributing](CONTRIBUTING.md)

---

## What is BAM?

Blob-Authenticated Messaging (BAM) lets you publish signed messages on Ethereum at blob-data costs. Messages are compressed with a BPE dictionary, signed with BLS12-381 aggregate signatures, packed into EIP-4844 blobs, and verified on-chain via the EIP-2537 BLS precompiles.

The result is a minimalistic "social on Ethereum" protocol: authenticated, censorship-resistant messaging that piggybacks on Ethereum's data availability layer.

## Features

- **BPE compression** -- 12-bit dictionary (4,096 codes) learned from a natural-language corpus, achieving 2-4x compression on typical messages
- **BLS12-381 signatures** -- Keys on G1, signatures on G2, with aggregate verification supporting up to 64 signers per blob
- **On-chain decoding** -- Vyper contracts decode blobs and verify signatures using EIP-2537 precompiles
- **ERC-8180 compliant** -- Full BAM Core, Decoder, Signature Registry, and Exposer interfaces
- **Proof of possession** -- Rogue-key attack prevention via PoP during key registration
- **Sepolia deployed** -- Live deployment on Ethereum Sepolia testnet ([deployment details](sepolia_deployment.txt))

## Quick Start

```bash
git clone https://github.com/vbuterin/SocialBlobs.git
cd SocialBlobs
pip install -r requirements.txt
make test
```

Or run the full test suite directly:

```bash
# Legacy end-to-end test
python test.py

# Full pytest suite (144+ tests)
pytest -v

# Individual test modules
pytest test_bpe_encode.py -v        # Compression / decompression
pytest test_blob_encoder.py -v      # Blob encoding format
pytest test_data_signer.py -v       # BLS signing
pytest test_decoder.py -v           # On-chain decoding
pytest test_signature_registry.py -v  # BLS registry
pytest test_e2e.py -v               # Full pipeline integration
pytest test_erc_interfaces.py -v    # ERC interface compliance
```

## Architecture

```
User message --> BPE compress --> BLS sign --> Blob encode --> EIP-4844 blob tx
                                                                    |
                                                                    v
On-chain:  registerBlobBatch()  -->  decoder.decode()  -->  signature_registry.verify()
                                                                    |
                                                                    v
                                                          exposer.getMessages()
```

The pipeline has three stages:

1. **Off-chain encoding** -- Messages are BPE-compressed, BLS-signed, and packed into 128 KiB blobs.
2. **Blob submission** -- Blobs are submitted via EIP-4844 blob-carrying transactions.
3. **On-chain verification** -- Contracts decode the blob, look up registered BLS public keys, and verify aggregate signatures.

## Project Structure

| File | Description |
|------|-------------|
| `bam_core.vy` | BAM Core contract -- blob batch registration and message storage |
| `decoder.vy` | On-chain BPE decompressor for blob / calldata payloads |
| `signature_registry.vy` | BLS12-381 public key registry with PoP and aggregate verification |
| `exposer.vy` | Read-only exposer interface for querying decoded messages |
| `bpe_encode.py` | BPE tokenizer -- dictionary training and encode/decode |
| `blob_encoder.py` | Blob packing -- serializes compressed messages into 128 KiB blobs |
| `data_signer.py` | BLS signing utilities -- key generation, signing, aggregation |
| `deploy_sepolia.py` | Deployment script for Sepolia testnet |
| `conftest.py` | Shared pytest fixtures (Vyper compilation, contract deployment) |
| `corpus.txt` | Natural-language corpus for BPE dictionary training |
| `test*.py` | Test suite -- 144+ tests covering all modules |

## Related Standards

- [ERC-8180](https://github.com/ethereum/ERCs/pull/1578) -- Blob-Authenticated Messaging (BAM)
- [ERC-8179](https://github.com/ethereum/ERCs/pull/1577) -- Blob Segment Subscription (BSS)
- [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844) -- Shard Blob Transactions
- [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537) -- BLS12-381 curve operations precompiles

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, test commands, and the PR process.

## License

[MIT](LICENSE)
