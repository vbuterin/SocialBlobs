"""conftest.py — Shared pytest fixtures for SocialBlobs test suite.

Deploys all contracts once per session and provides reusable BLS signers,
encoded blobs, and helper functions.
"""

import pytest
from pathlib import Path

from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from vyper import compile_code

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob


def compile_vyper(source: str) -> dict:
    return compile_code(source, output_formats=["abi", "bytecode"])


def deploy(w3, compiled, deployer, *args):
    factory = w3.eth.contract(abi=compiled["abi"], bytecode=compiled["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        factory.constructor(*args).transact({"from": deployer})
    )
    return w3.eth.contract(address=receipt.contractAddress, abi=compiled["abi"])


@pytest.fixture(scope="session")
def w3():
    return Web3(EthereumTesterProvider())


@pytest.fixture(scope="session")
def accounts(w3):
    return w3.eth.accounts


@pytest.fixture(scope="session")
def deployer(accounts):
    return accounts[0]


@pytest.fixture(scope="session")
def core(w3, deployer):
    src = Path("bam_core.vy").read_text()
    return deploy(w3, compile_vyper(src), deployer)


@pytest.fixture(scope="session")
def decoder(w3, deployer):
    src = Path("decoder.vy").read_text()
    return deploy(w3, compile_vyper(src), deployer)


@pytest.fixture(scope="session")
def registry(w3, deployer):
    src = Path("signature_registry.vy").read_text()
    return deploy(w3, compile_vyper(src), deployer)


@pytest.fixture(scope="session")
def exposer(w3, deployer, core, registry):
    src = Path("exposer.vy").read_text()
    return deploy(w3, compile_vyper(src), deployer, core.address, registry.address)


@pytest.fixture(scope="session")
def signers():
    """Three BLS signers for testing."""
    return [Signer.generate() for _ in range(3)]


@pytest.fixture(scope="session")
def signer_accounts(accounts):
    """Ethereum accounts for the three BLS signers."""
    return accounts[1:4]


@pytest.fixture(scope="session")
def registered_signers(signers, signer_accounts, registry):
    """Register three BLS signers and return (signers, accounts) pair."""
    for signer, acct in zip(signers, signer_accounts):
        registry.functions.register(
            signer.public_bytes(), signer.make_pop()
        ).transact({"from": acct})
    return signers, signer_accounts
