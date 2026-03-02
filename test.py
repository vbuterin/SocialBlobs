"""test.py

End-to-end integration test using an in-memory eth_tester chain.

Deploys a minimal core contract, the blob decoder, and the BLS signature
registry; signs messages with BLS keys; constructs and registers a blob;
then verifies decoding and aggregate signature verification on-chain.
"""

from pathlib import Path
from typing import List, Tuple

from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from vyper import compile_code

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob


# ---------------------------------------------------------------------------
# Compile helpers
# ---------------------------------------------------------------------------

def compile_vyper(source: str) -> dict:
    """Compile a Vyper source string; return {"abi": ..., "bytecode": ...}."""
    return compile_code(source, output_formats=["abi", "bytecode"])


def deploy(w3: Web3, compiled: dict, deployer: str):
    """Deploy a compiled contract and return the bound contract instance."""
    factory = w3.eth.contract(abi=compiled["abi"], bytecode=compiled["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        factory.constructor().transact({"from": deployer})
    )
    return w3.eth.contract(address=receipt.contractAddress, abi=compiled["abi"])


# ---------------------------------------------------------------------------
# Chain setup
# ---------------------------------------------------------------------------

w3 = Web3(EthereumTesterProvider())
# eth_tester provides 10 pre-funded accounts.
# accounts[0] is the deployer; accounts[1..N] are the per-signer Ethereum accounts
# so each BLS key can be registered under a distinct address.
accounts = w3.eth.accounts
deployer = accounts[0]
w3.eth.default_account = deployer

# ---------------------------------------------------------------------------
# Deploy contracts
# ---------------------------------------------------------------------------

CORE_SOURCE = """
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

core     = deploy(w3, compile_vyper(CORE_SOURCE),                        deployer)
decoder  = deploy(w3, compile_vyper(Path("decoder.vy").read_text()),     deployer)
registry = deploy(w3, compile_vyper(Path("signature_registry.vy").read_text()), deployer)

# ---------------------------------------------------------------------------
# BLS signing
# ---------------------------------------------------------------------------

msg_contents = [b"hello world", b"test message", b"data blobs rock"]
n = len(msg_contents)

signers   = [Signer.generate() for _ in range(n)]
sigs      = [s.sign(m) for s, m in zip(signers, msg_contents)]
agg_sig   = aggregate_signatures(sigs)

# Each BLS signer uses a distinct Ethereum account so their public keys are
# stored at different addresses in the registry mapping.
signer_accounts = accounts[1:n + 1]
nonces: List[int] = list(range(n))
message_tuples: List[Tuple[str, int, bytes]] = list(
    zip(signer_accounts, nonces, msg_contents)
)
blob = encode_blob(message_tuples, sigs)

# ---------------------------------------------------------------------------
# Register BLS keys (one per Ethereum account)
# ---------------------------------------------------------------------------

for i, (signer, eth_acct) in enumerate(zip(signers, signer_accounts)):
    registry.functions.register(signer.public_bytes(), signer.make_pop()).transact(
        {"from": eth_acct}
    )
    print(f"PoP {i} registered for {eth_acct}")

print("Key registration complete")

# ---------------------------------------------------------------------------
# Register blob on-chain and verify the event
# ---------------------------------------------------------------------------

ZERO_ADDR = Web3.to_checksum_address("0x" + "00" * 20)
receipt = w3.eth.wait_for_transaction_receipt(
    core.functions.registerCalldataBatch(blob, decoder.address, ZERO_ADDR)
        .transact({"from": deployer})
)

logs = core.events.BlobBatchRegistered().process_receipt(receipt)
assert logs,                                         "No BlobBatchRegistered event"
assert logs[0].args.submitter == deployer,           "Wrong submitter"
assert logs[0].args.versionedHash == Web3.keccak(blob), "Wrong content hash"

# ---------------------------------------------------------------------------
# Decode the blob and verify its contents
# ---------------------------------------------------------------------------

decoded_messages, decoded_sig = decoder.functions.decode(blob).call()

assert decoded_messages == message_tuples, "Decoded messages do not match"
assert decoded_sig == agg_sig,             "Decoded signature does not match"
print("✅ Decoder test passed")

# ---------------------------------------------------------------------------
# Verify aggregate BLS signature on-chain
# ---------------------------------------------------------------------------

owners   = list(signer_accounts)
messages = list(msg_contents)

assert registry.functions.verifyAggregated(owners, messages, agg_sig).call(), \
    "verifyAggregated rejected a valid aggregate signature"
print("✅ Aggregate signature verified on-chain")

# Negative check: bit-flipped signature must be rejected (may revert or return False).
bad_sig = bytes([agg_sig[0] ^ 0xFF]) + agg_sig[1:]
try:
    bad_result = registry.functions.verifyAggregated(owners, messages, bad_sig).call()
except Exception:
    bad_result = False
assert not bad_result, "verifyAggregated accepted a tampered signature"
print("✅ Tampered signature correctly rejected")

# Negative check: wrong message must be rejected.
wrong_messages = [b"wrong message"] + messages[1:]
try:
    wrong_result = registry.functions.verifyAggregated(owners, wrong_messages, agg_sig).call()
except Exception:
    wrong_result = False
assert not wrong_result, "verifyAggregated accepted wrong messages"
print("✅ Wrong message correctly rejected")

print()
print(f"  Blob (hex)     : 0x{blob.hex()}")
print(f"  Aggregate sig  : 0x{agg_sig.hex()}")
print("✅ All tests passed")
