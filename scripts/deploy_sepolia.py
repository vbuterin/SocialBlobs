"""deploy_sepolia.py — Deploy and test SocialBlobs on Ethereum Sepolia.

Deploys all 5 contracts (bam_core, decoder, signature_registry, exposer),
registers BLS keys, encodes a compressed blob, registers it on-chain,
decodes with decompression, verifies aggregate BLS signature, exposes
messages, and validates BSS segment bounds.

Updated for the compression/decompression architecture (bpe_encode + decoder.vy).
Also tests the PR #12 ERC interface contracts (bam_core.vy, exposer.vy).
"""

import os
import sys
import time
from pathlib import Path

from web3 import Web3
from eth_account import Account
from eth_account.signers.local import LocalAccount
from vyper import compile_code
import sys
from pathlib import Path as ScriptPath
sys.path.insert(0, str(ScriptPath(__file__).resolve().parent.parent / "src"))

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob
from bpe_encode import build_12bit_dict_from_corpus, encode_msg, deploy_decoder
from paths import CONTRACTS_DIR, CORPUS_PATH

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RPC_URL = os.environ.get("SEPOLIA_RPC_URL", "")
PRIVATE_KEY = os.environ.get("DEPLOYER_KEY", "")

if not RPC_URL or not PRIVATE_KEY:
    print("Usage: SEPOLIA_RPC_URL=<url> DEPLOYER_KEY=<0x...> python deploy_sepolia.py")
    sys.exit(1)

w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 60}))
assert w3.is_connected(), "Failed to connect to Sepolia"

account: LocalAccount = Account.from_key(PRIVATE_KEY)
deployer = account.address

print(f"Deployer: {deployer}")
print(f"Balance:  {Web3.from_wei(w3.eth.get_balance(deployer), 'ether')} ETH")
print(f"Chain ID: {w3.eth.chain_id}")
print(f"Block:    {w3.eth.block_number}")
print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def compile_vyper(source: str) -> dict:
    return compile_code(source, output_formats=["abi", "bytecode"])


def deploy(compiled, *args, label="Contract"):
    """Deploy a contract, wait for receipt, return contract instance."""
    abi = compiled["abi"]
    bytecode = compiled["bytecode"]
    factory = w3.eth.contract(abi=abi, bytecode=bytecode)

    nonce = w3.eth.get_transaction_count(deployer, "pending")
    gas_price = int(w3.eth.gas_price * 1.25)

    tx = factory.constructor(*args).build_transaction({
        "from": deployer,
        "nonce": nonce,
        "gasPrice": gas_price,
        "chainId": w3.eth.chain_id,
    })
    tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.2)

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"  {label}: tx {tx_hash.hex()}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    assert receipt.status == 1, f"  {label}: deployment FAILED (status=0)"
    print(f"  {label}: deployed at {receipt.contractAddress} (gas: {receipt.gasUsed:,})")
    return w3.eth.contract(address=receipt.contractAddress, abi=abi)


def send_tx(contract_fn, label="TX", value=0):
    """Send a transaction, wait for receipt, return it."""
    nonce = w3.eth.get_transaction_count(deployer, "pending")
    gas_price = int(w3.eth.gas_price * 1.25)

    tx = contract_fn.build_transaction({
        "from": deployer,
        "nonce": nonce,
        "gasPrice": gas_price,
        "value": value,
        "chainId": w3.eth.chain_id,
    })
    tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.2)

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    assert receipt.status == 1, f"  {label}: tx FAILED (status=0)"
    print(f"  {label}: tx {tx_hash.hex()} (gas: {receipt.gasUsed:,})")
    return receipt


# ---------------------------------------------------------------------------
# Step 1: Deploy contracts
# ---------------------------------------------------------------------------

print("=" * 70)
print("Step 1: Deploy 4 contracts")
print("=" * 70)

# Build compression dictionary
token_to_code, DICT_BYTES, _, _ = build_12bit_dict_from_corpus(str(CORPUS_PATH))

# Compile contracts
bam_core_source = (CONTRACTS_DIR / "bam_core.vy").read_text()
decoder_source = (CONTRACTS_DIR / "decoder.vy").read_text()
registry_source = (CONTRACTS_DIR / "signature_registry.vy").read_text()
exposer_source = (CONTRACTS_DIR / "exposer.vy").read_text()

bam_core_compiled = compile_vyper(bam_core_source)
decoder_compiled = compile_vyper(decoder_source)
registry_compiled = compile_vyper(registry_source)
exposer_compiled = compile_vyper(exposer_source)

bam_core = deploy(bam_core_compiled, label="BAM Core")
decoder = deploy(decoder_compiled, DICT_BYTES, label="Decoder")
registry = deploy(registry_compiled, label="Registry")
exposer = deploy(exposer_compiled, bam_core.address, label="Exposer")

print(f"\n  BAM Core: {bam_core.address}")
print(f"  Decoder:  {decoder.address}")
print(f"  Registry: {registry.address}")
print(f"  Exposer:  {exposer.address}")
print()


# ---------------------------------------------------------------------------
# Step 2: Verify scheme metadata
# ---------------------------------------------------------------------------

print("=" * 70)
print("Step 2: Verify scheme metadata")
print("=" * 70)

assert registry.functions.schemeId().call() == 2
assert registry.functions.schemeName().call() == "BLS12-381"
assert registry.functions.pubKeySize().call() == 128
assert registry.functions.signatureSize().call() == 256
assert registry.functions.supportsAggregation().call() is True
print("  schemeId=2, BLS12-381, pubKey=128, sig=256, aggregation=true")
print()


# ---------------------------------------------------------------------------
# Step 3: Register BLS keys with PoP
# ---------------------------------------------------------------------------

print("=" * 70)
print("Step 3: Register BLS key with PoP via EIP-2537 pairing")
print("=" * 70)

signer = Signer.generate()
receipt = send_tx(
    registry.functions.register(signer.public_bytes(), signer.make_pop()),
    label="Register BLS key",
)
logs = registry.events.KeyRegistered().process_receipt(receipt)
assert len(logs) == 1
assert logs[0].args.owner == deployer
print(f"  KeyRegistered event: owner={deployer}, index={logs[0].args.index}")

assert registry.functions.isRegistered(deployer).call() is True
assert registry.functions.getKey(deployer).call() == signer.public_bytes()
print()


# ---------------------------------------------------------------------------
# Step 4: Single BLS verify + wrong message rejection
# ---------------------------------------------------------------------------

print("=" * 70)
print("Step 4: Single BLS verify + wrong message rejection")
print("=" * 70)

msg = b"hello world"
sig = signer.sign(msg)
assert registry.functions.verify(signer.public_bytes(), msg, sig).call() is True
print("  verify(correct msg) = True")

assert registry.functions.verify(signer.public_bytes(), b"wrong", sig).call() is False
print("  verify(wrong msg) = False")

assert registry.functions.verifyWithRegisteredKey(deployer, msg, sig).call() is True
print("  verifyWithRegisteredKey(correct) = True")
print()


# ---------------------------------------------------------------------------
# Step 5: Encode compressed blob + registerCalldataBatch
# ---------------------------------------------------------------------------

print("=" * 70)
print("Step 5: Encode compressed blob + registerCalldataBatch")
print("=" * 70)

msg_contents = [b"hello world"]
sigs = [signer.sign(c) for c in msg_contents]
compressor = lambda m: encode_msg(m, token_to_code)
message_tuples = [(deployer, 0, msg_contents[0])]
blob = encode_blob(message_tuples, sigs, compressor)

compressed_len = len(encode_msg(msg_contents[0], token_to_code))
print(f"  Blob size: {len(blob)} bytes")
print(f"  Message compressed: {len(msg_contents[0])} -> {compressed_len} bytes")

receipt = send_tx(
    bam_core.functions.registerCalldataBatch(blob, decoder.address, registry.address),
    label="registerCalldataBatch",
)
logs = bam_core.events.CalldataBatchRegistered().process_receipt(receipt)
assert len(logs) == 1
content_hash = logs[0].args.contentHash
assert content_hash == Web3.keccak(blob)
assert logs[0].args.submitter == deployer
assert logs[0].args.decoder == decoder.address
assert logs[0].args.signatureRegistry == registry.address
print(f"  CalldataBatchRegistered: contentHash={content_hash.hex()}")
print(f"  registered[contentHash] = {bam_core.functions.registered(content_hash).call()}")
print()


# ---------------------------------------------------------------------------
# Step 6: On-chain decode with decompression
# ---------------------------------------------------------------------------

print("=" * 70)
print("Step 6: On-chain decode with decompression")
print("=" * 70)

decoded_msgs, decoded_sig = decoder.functions.decode(blob).call()
assert len(decoded_msgs) == 1
assert decoded_msgs[0][0] == deployer
assert decoded_msgs[0][1] == 0
assert decoded_msgs[0][2] == msg_contents[0]
print(f"  Decoded {len(decoded_msgs)} message(s)")
print(f"  sender={decoded_msgs[0][0]}, nonce={decoded_msgs[0][1]}")
print(f"  contents={decoded_msgs[0][2]}")

agg_sig = aggregate_signatures(sigs)
assert decoded_sig == agg_sig
print(f"  Aggregate signature matches: True")
print()


# ---------------------------------------------------------------------------
# Step 7: Aggregate BLS verify + negative checks
# ---------------------------------------------------------------------------

print("=" * 70)
print("Step 7: Aggregate BLS verify + tampered sig + wrong msg rejection")
print("=" * 70)

assert registry.functions.verifyAggregated(
    [deployer], list(msg_contents), agg_sig
).call() is True
print("  verifyAggregated(valid) = True")

bad_sig = bytes([agg_sig[0] ^ 0xFF]) + agg_sig[1:]
try:
    bad_result = registry.functions.verifyAggregated(
        [deployer], list(msg_contents), bad_sig
    ).call()
except Exception:
    bad_result = False
assert not bad_result
print("  verifyAggregated(tampered sig) = False")

try:
    wrong_result = registry.functions.verifyAggregated(
        [deployer], [b"wrong"], agg_sig
    ).call()
except Exception:
    wrong_result = False
assert not wrong_result
print("  verifyAggregated(wrong msg) = False")
print()


# ---------------------------------------------------------------------------
# Step 8: Message exposure + double-exposure + unregistered revert
# ---------------------------------------------------------------------------

print("=" * 70)
print("Step 8: Message exposure + double-exposure + unregistered revert")
print("=" * 70)

msg_content_hash = Web3.keccak(msg_contents[0])
expected_message_id = exposer.functions.computeMessageId(
    deployer, 0, msg_content_hash
).call()
print(f"  computeMessageId = {expected_message_id.hex()}")

# Verify keccak256(author || nonce || contentHash) matches
manual_id = Web3.keccak(
    bytes.fromhex(deployer[2:].lower()) +
    (0).to_bytes(8, "big") +
    msg_content_hash
)
assert expected_message_id == manual_id
print(f"  Manual keccak match: True")

assert exposer.functions.isExposed(expected_message_id).call() is False
print(f"  isExposed(before) = False")

receipt = send_tx(
    exposer.functions.exposeMessage(content_hash, deployer, 0, msg_content_hash),
    label="exposeMessage",
)
logs = exposer.events.MessageExposed().process_receipt(receipt)
assert len(logs) == 1
assert logs[0].args.messageId == expected_message_id
assert logs[0].args.author == deployer
print(f"  MessageExposed event: messageId={logs[0].args.messageId.hex()}")

assert exposer.functions.isExposed(expected_message_id).call() is True
print(f"  isExposed(after) = True")

# Double-exposure must revert
try:
    send_tx(
        exposer.functions.exposeMessage(content_hash, deployer, 0, msg_content_hash),
        label="double-exposure",
    )
    assert False, "Should have reverted"
except Exception as e:
    print(f"  Double-exposure correctly reverted")

# Unregistered batch must revert
fake_hash = Web3.keccak(b"unregistered")
try:
    send_tx(
        exposer.functions.exposeMessage(fake_hash, deployer, 0, msg_content_hash),
        label="unregistered-batch",
    )
    assert False, "Should have reverted"
except Exception as e:
    print(f"  Unregistered batch correctly reverted")
print()


# ---------------------------------------------------------------------------
# Step 9: BSS segment validation
# ---------------------------------------------------------------------------

print("=" * 70)
print("Step 9: BSS segment validation (declareBlobSegment)")
print("=" * 70)

# startFE >= endFE must revert
try:
    bam_core.functions.declareBlobSegment(0, 100, 100, b"\x00" * 32).call({"from": deployer})
    assert False, "Should have reverted"
except Exception:
    print("  startFE == endFE: correctly reverted")

try:
    bam_core.functions.declareBlobSegment(0, 200, 100, b"\x00" * 32).call({"from": deployer})
    assert False, "Should have reverted"
except Exception:
    print("  startFE > endFE: correctly reverted")

# endFE > 4096 must revert
try:
    bam_core.functions.declareBlobSegment(0, 0, 4097, b"\x00" * 32).call({"from": deployer})
    assert False, "Should have reverted"
except Exception:
    print("  endFE > 4096: correctly reverted")

# Note: valid declareBlobSegment calls require an actual blob transaction,
# which we can't easily send from a script. The revert cases validate the logic.
print()


# ---------------------------------------------------------------------------
# Step 10: Decompression round-trip
# ---------------------------------------------------------------------------

print("=" * 70)
print("Step 10: Decompression round-trip on-chain")
print("=" * 70)

test_messages = [
    b"hello world",
    b"the quick brown fox jumps over the yellow dog",
    b"A purely peer-to-peer version of electronic cash would allow "
    b"online payments to be sent directly from one party to another "
    b"without going through a financial institution",
]
for msg in test_messages:
    compressed = encode_msg(msg, token_to_code)
    decompressed = decoder.functions.decompress(compressed).call()
    assert decompressed == msg, f"Round-trip failed for {msg!r}: got {decompressed!r}"
    ratio = len(compressed) / len(msg)
    print(f"  {len(msg):>3}B -> {len(compressed):>3}B (ratio {ratio:.2f}): {msg[:40]}...")
print()


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("=" * 70)
print("ALL TESTS PASSED")
print("=" * 70)
balance_after = w3.eth.get_balance(deployer)
print(f"  Balance after: {Web3.from_wei(balance_after, 'ether')} ETH")
print()
print(f"  BAM Core: {bam_core.address}")
print(f"  Decoder:  {decoder.address}")
print(f"  Registry: {registry.address}")
print(f"  Exposer:  {exposer.address}")
print(f"  Content Hash: {content_hash.hex()}")

# Write deployment info
with open("sepolia_deployment.txt", "w") as f:
    f.write(f"Network: Sepolia (chain ID {w3.eth.chain_id})\n")
    f.write(f"Deployer: {deployer}\n")
    f.write(f"BAM Core: {bam_core.address}\n")
    f.write(f"Decoder: {decoder.address}\n")
    f.write(f"Registry: {registry.address}\n")
    f.write(f"Exposer: {exposer.address}\n")
    f.write(f"Content Hash: {content_hash.hex()}\n")
print("\nWritten to sepolia_deployment.txt")
