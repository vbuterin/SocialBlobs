"""conftest.py -- Shared pytest fixtures for SocialBlobs.

Provides:
  - In-memory eth_tester chain (w3, deployer, accounts)
  - BPE compression dictionary (token_to_code, dict_bytes)
  - Deployed contracts (decoder, registry)
  - BLS signers and message helpers
"""

from pathlib import Path
from typing import List, Tuple

import pytest
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from vyper import compile_code

from data_signer import Signer, aggregate_signatures
from paths import CORPUS_PATH, CONTRACTS_DIR
from bpe_encode import build_12bit_dict_from_corpus, deploy_decoder, encode_msg
from blob_encoder import encode_blob


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def compile_vyper(source: str) -> dict:
    return compile_code(source, output_formats=["abi", "bytecode"])


def deploy(w3: Web3, compiled: dict, deployer: str, *args):
    factory = w3.eth.contract(abi=compiled["abi"], bytecode=compiled["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        factory.constructor(*args).transact({"from": deployer})
    )
    return w3.eth.contract(address=receipt.contractAddress, abi=compiled["abi"])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def w3():
    return Web3(EthereumTesterProvider())


@pytest.fixture(scope="session")
def deployer(w3):
    return w3.eth.accounts[0]


@pytest.fixture(scope="session")
def accounts(w3):
    return w3.eth.accounts


@pytest.fixture(scope="session")
def compression_dict():
    """Build the BPE 12-bit dictionary from corpus.txt."""
    token_to_code, dict_bytes, dict_offs, dict_len = build_12bit_dict_from_corpus(str(CORPUS_PATH))
    return token_to_code, dict_bytes, dict_offs, dict_len


@pytest.fixture(scope="session")
def token_to_code(compression_dict):
    return compression_dict[0]


@pytest.fixture(scope="session")
def dict_bytes(compression_dict):
    return compression_dict[1]


@pytest.fixture(scope="session")
def decoder(w3, deployer, dict_bytes):
    """Deploy decoder.vy with the compression dictionary."""
    return deploy_decoder(w3, deployer, dict_bytes)


@pytest.fixture(scope="session")
def registry(w3, deployer):
    """Deploy signature_registry.vy."""
    source = (CONTRACTS_DIR / "signature_registry.vy").read_text()
    return deploy(w3, compile_vyper(source), deployer)


@pytest.fixture(scope="session")
def core_contract(w3, deployer):
    """Deploy a minimal BAM Core contract for testing."""
    source = """
# @version ^0.4.3

event BlobBatchRegistered:
    versionedHash:     bytes32
    submitter:         address
    decoder:           address
    signatureRegistry: address

@external
def registerCalldataBatch(
    batchData: Bytes[4096], decoder: address, signatureRegistry: address
) -> bytes32:
    contentHash: bytes32 = keccak256(batchData)
    log BlobBatchRegistered(
        versionedHash=contentHash,
        submitter=msg.sender,
        decoder=decoder,
        signatureRegistry=signatureRegistry,
    )
    return contentHash
"""
    return deploy(w3, compile_vyper(source), deployer)


@pytest.fixture(scope="session")
def signers():
    """Generate 3 BLS signers."""
    return [Signer.generate() for _ in range(3)]


@pytest.fixture(scope="session")
def sample_messages():
    """Sample messages for testing."""
    return [
        b"hello world",
        b"the quick brown fox jumps over the yellow dog",
        b"A purely peer-to-peer version of electronic cash would allow "
        b"online payments to be sent directly from one party to another "
        b"without going through a financial institution",
    ]


def make_compressor(token_to_code):
    """Create a compressor function from a token_to_code dictionary."""
    return lambda msg: encode_msg(msg, token_to_code)
