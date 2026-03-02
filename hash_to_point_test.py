"""hash_to_point_test.py

Verifies that the Vyper implementation of hash_to_G2 inside
signature_registry.vy matches py_ecc's reference output exactly.

Usage:
    pytest hash_to_point_test.py -v
    python hash_to_point_test.py
"""

import hashlib
from pathlib import Path

import pytest
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.optimized_bls12_381 import normalize
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from vyper import compile_code

DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

MESSAGES = [
    b"",
    b"abc",
    b"test message",
    b"abcdef0123456789",
    b"q" * 128,
]


def g2_to_bytes(pt) -> bytes:
    """Convert a normalised py_ecc G2 point to 256-byte EIP-2537 encoding.

    Layout: x.c0 (64 B) ‖ x.c1 (64 B) ‖ y.c0 (64 B) ‖ y.c1 (64 B).
    Each Fp element is zero-padded to 64 bytes (top 16 bytes = 0x00).
    """
    x, y = pt
    return b"".join(
        int(c).to_bytes(64, "big") for c in (*x.coeffs, *y.coeffs)
    )


@pytest.fixture(scope="module")
def contract():
    source = Path("signature_registry.vy").read_text()
    compiled = compile_code(source, output_formats=["abi", "bytecode"])
    w3 = Web3(EthereumTesterProvider())
    acct = w3.eth.accounts[0]
    factory = w3.eth.contract(abi=compiled["abi"], bytecode=compiled["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        factory.constructor().transact({"from": acct})
    )
    return w3.eth.contract(address=receipt.contractAddress, abi=compiled["abi"])


@pytest.mark.parametrize("msg", MESSAGES)
def test_matches_py_ecc(contract, msg: bytes):
    expected = g2_to_bytes(normalize(hash_to_G2(msg, DST, hashlib.sha256)))
    actual   = bytes(contract.functions.hash_to_g2(msg, DST).call())
    assert actual == expected, (
        f"msg={msg!r}\n  expected: {expected.hex()}\n  actual:   {actual.hex()}"
    )


def test_deterministic(contract):
    msg  = b"deterministic test"
    assert (bytes(contract.functions.hash_to_g2(msg, DST).call()) ==
            bytes(contract.functions.hash_to_g2(msg, DST).call()))


def test_output_length(contract):
    assert len(bytes(contract.functions.hash_to_g2(b"length check", DST).call())) == 256


def test_distinct_messages(contract):
    out1 = bytes(contract.functions.hash_to_g2(b"message one", DST).call())
    out2 = bytes(contract.functions.hash_to_g2(b"message two", DST).call())
    assert out1 != out2


if __name__ == "__main__":
    source = Path("signature_registry.vy").read_text()
    compiled = compile_code(source, output_formats=["abi", "bytecode"])
    w3 = Web3(EthereumTesterProvider())
    acct = w3.eth.accounts[0]
    factory = w3.eth.contract(abi=compiled["abi"], bytecode=compiled["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        factory.constructor().transact({"from": acct})
    )
    c = w3.eth.contract(address=receipt.contractAddress, abi=compiled["abi"])

    print("Testing hash_to_g2 against py_ecc reference …")
    for msg in MESSAGES:
        expected = g2_to_bytes(normalize(hash_to_G2(msg, DST, hashlib.sha256)))
        actual   = bytes(c.functions.hash_to_g2(msg, DST).call())
        status   = "✓" if actual == expected else "✗ MISMATCH"
        print(f"  {msg[:24]!r:26s} {status}")
        if actual != expected:
            print(f"    expected: {expected.hex()}")
            print(f"    actual:   {actual.hex()}")
