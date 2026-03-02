# Contributing to SocialBlobs

Reference implementation for ERC-8180 (Blob-Authenticated Messaging).

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Running tests

```bash
# Legacy end-to-end test
python test.py

# Full pytest suite (80+ tests)
pytest -v

# Individual test modules
pytest test_bpe_encode.py -v      # Compression/decompression
pytest test_blob_encoder.py -v    # Blob encoding format
pytest test_data_signer.py -v     # BLS signing
pytest test_decoder.py -v         # On-chain decoding
pytest test_signature_registry.py -v  # BLS registry
pytest test_e2e.py -v             # Full pipeline integration

# Hash-to-point compatibility test
pytest hash_to_point_test.py -v
```

## PR process

1. Fork and create a feature branch from `main`
2. Ensure all tests pass: `pytest -v && python test.py`
3. Open a PR with a clear description
