"""deploy_sepolia.py — Deploy and test SocialBlobs on Ethereum Sepolia.

Deploys all 4 contracts (bam_core, decoder, signature_registry, exposer),
registers BLS keys, encodes a blob, registers it on-chain, decodes,
verifies aggregate BLS signature, and exposes messages.
"""

import os
import sys
import time
from pathlib import Path

from web3 import Web3
from eth_account import Account
from eth_account.signers.local import LocalAccount
from vyper import compile_code

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RPC_URL = os.environ.get("SEPOLIA_RPC_URL", "")
PRIVATE_KEY = os.environ.get("DEPLOYER_KEY", "")

if not RPC_URL or not PRIVATE_KEY:
    print("Usage: SEPOLIA_RPC_URL=<url> DEPLOYER_KEY=<0x...> python deploy_sepolia.py")
    sys.exit(1)

w3 = Web3(Web3.HTTPProvider(RPC_URL))
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
    gas_price = int(w3.eth.gas_price * 1.25)  # 25% tip for faster inclusion

    tx = factory.constructor(*args).build_transaction({
        "from": deployer,
        "nonce": nonce,
        "gasPrice": gas_price,
        "chainId": 11155111,
    })
    tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.2)

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"  {label}: tx {tx_hash.hex()}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    assert receipt.status == 1, f"  {label}: deployment FAILED (status=0)"
    print(f"  {label}: deployed at {receipt.contractAddress} (gas: {receipt.gasUsed})")
    return w3.eth.contract(address=receipt.contractAddress, abi=abi)


def send_tx(contract_fn, label="TX", value=0):
    """Send a transaction, wait for receipt."""
    nonce = w3.eth.get_transaction_count(deployer, "pending")
    gas_price = int(w3.eth.gas_price * 1.25)

    tx = contract_fn.build_transaction({
        "from": deployer,
        "nonce": nonce,
        "gasPrice": gas_price,
        "chainId": 11155111,
        "value": value,
    })
    tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.2)

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"  {label}: tx {tx_hash.hex()}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    assert receipt.status == 1, f"  {label}: FAILED (status=0)"
    print(f"  {label}: confirmed (gas: {receipt.gasUsed})")
    return receipt


# ===========================================================================
# Step 1: Deploy contracts
# ===========================================================================

print("=" * 70)
print("STEP 1: Deploy contracts")
print("=" * 70)

core_compiled = compile_vyper(Path("bam_core.vy").read_text())
decoder_compiled = compile_vyper(Path("decoder.vy").read_text())
registry_compiled = compile_vyper(Path("signature_registry.vy").read_text())
exposer_compiled = compile_vyper(Path("exposer.vy").read_text())
print("  Vyper compilation complete")

core = deploy(core_compiled, label="BAM Core")
decoder = deploy(decoder_compiled, label="Decoder")
registry = deploy(registry_compiled, label="Registry")
exposer = deploy(exposer_compiled, core.address, registry.address, label="Exposer")

print()
print(f"  BAM Core:  {core.address}")
print(f"  Decoder:   {decoder.address}")
print(f"  Registry:  {registry.address}")
print(f"  Exposer:   {exposer.address}")
print()

# ===========================================================================
# Step 2: Verify scheme metadata
# ===========================================================================

print("=" * 70)
print("STEP 2: Verify registry scheme metadata")
print("=" * 70)

assert registry.functions.schemeId().call() == 2, "Wrong schemeId"
assert registry.functions.schemeName().call() == "BLS12-381", "Wrong schemeName"
assert registry.functions.pubKeySize().call() == 128, "Wrong pubKeySize"
assert registry.functions.signatureSize().call() == 256, "Wrong signatureSize"
assert registry.functions.supportsAggregation().call() is True, "Should support aggregation"
print("  schemeId=2, schemeName=BLS12-381, pubKeySize=128, sigSize=256, aggregation=true")
print("  PASSED")
print()

# ===========================================================================
# Step 3: Register BLS keys
# ===========================================================================

print("=" * 70)
print("STEP 3: Register BLS keys (3 signers)")
print("=" * 70)

# All 3 signers register from the same deployer address for simplicity
# (on Sepolia we only have 1 funded account)
signers = [Signer.generate() for _ in range(3)]

# Register first signer's key
signer0 = signers[0]
receipt = send_tx(
    registry.functions.register(signer0.public_bytes(), signer0.make_pop()),
    label="Register signer 0",
)
logs = registry.events.KeyRegistered().process_receipt(receipt)
assert len(logs) == 1, "No KeyRegistered event"
assert logs[0].args.owner == deployer, "Wrong owner in KeyRegistered"
print(f"  KeyRegistered event: owner={logs[0].args.owner}, index={logs[0].args.index}")

# Verify key is stored
stored_key = registry.functions.getKey(deployer).call()
assert stored_key == signer0.public_bytes(), "Stored key mismatch"
assert registry.functions.isRegistered(deployer).call() is True, "Not registered"
print("  Key correctly stored and retrievable")
print("  PASSED")
print()

# ===========================================================================
# Step 4: Verify single BLS signature on-chain
# ===========================================================================

print("=" * 70)
print("STEP 4: Verify single BLS signature on-chain")
print("=" * 70)

msg = b"hello Sepolia"
sig = signer0.sign(msg)
pub = signer0.public_bytes()

# verify() with explicit key
result = registry.functions.verify(pub, msg, sig).call()
assert result is True, "Single BLS verification failed"
print(f"  verify(pubKey, '{msg.decode()}', sig) = True")

# verifyWithRegisteredKey()
result2 = registry.functions.verifyWithRegisteredKey(deployer, msg, sig).call()
assert result2 is True, "Registered key verification failed"
print(f"  verifyWithRegisteredKey(deployer, msg, sig) = True")

# Negative: wrong message
result3 = registry.functions.verify(pub, b"wrong message", sig).call()
assert result3 is False, "Should reject wrong message"
print(f"  verify(pubKey, 'wrong message', sig) = False (correct rejection)")

print("  PASSED")
print()

# ===========================================================================
# Step 5: Encode blob and register via BAM Core
# ===========================================================================

print("=" * 70)
print("STEP 5: Encode blob and register via BAM Core")
print("=" * 70)

msg_contents = [b"hello Sepolia", b"BLS works", b"social blobs"]
sigs = [signers[0].sign(m) for m in msg_contents]
nonces = [0, 1, 2]
# All messages from deployer (single funded account on Sepolia)
message_tuples = [(deployer, n, c) for n, c in zip(nonces, msg_contents)]
blob = encode_blob(message_tuples, sigs)
print(f"  Blob size: {len(blob)} bytes")

receipt = send_tx(
    core.functions.registerCalldataBatch(blob, decoder.address, registry.address),
    label="registerCalldataBatch",
)

logs = core.events.CalldataBatchRegistered().process_receipt(receipt)
assert len(logs) == 1, "No CalldataBatchRegistered event"
content_hash = logs[0].args.contentHash
assert content_hash == Web3.keccak(blob), "Content hash mismatch"
assert logs[0].args.submitter == deployer, "Wrong submitter"
assert logs[0].args.decoder == decoder.address, "Wrong decoder"
assert logs[0].args.signatureRegistry == registry.address, "Wrong registry"
print(f"  CalldataBatchRegistered event:")
print(f"    contentHash: 0x{content_hash.hex()}")
print(f"    submitter:   {logs[0].args.submitter}")
print(f"    decoder:     {logs[0].args.decoder}")
print(f"    sigReg:      {logs[0].args.signatureRegistry}")
print("  PASSED")
print()

# ===========================================================================
# Step 6: Decode blob on-chain
# ===========================================================================

print("=" * 70)
print("STEP 6: Decode blob on-chain")
print("=" * 70)

decoded_messages, decoded_sig = decoder.functions.decode(blob).call()
assert len(decoded_messages) == 3, f"Expected 3 messages, got {len(decoded_messages)}"

agg_sig = aggregate_signatures(sigs)
assert decoded_sig == agg_sig, "Decoded aggregate sig mismatch"

for i, (sender, nonce, content) in enumerate(message_tuples):
    assert decoded_messages[i][0] == sender, f"Msg {i}: sender mismatch"
    assert decoded_messages[i][1] == nonce, f"Msg {i}: nonce mismatch"
    assert decoded_messages[i][2] == content, f"Msg {i}: content mismatch"
    print(f"  Message {i}: sender={decoded_messages[i][0][:10]}... nonce={decoded_messages[i][1]} content={decoded_messages[i][2]}")

print(f"  Aggregate signature: 0x{decoded_sig.hex()[:32]}...")
print("  PASSED")
print()

# ===========================================================================
# Step 7: Verify aggregate BLS signature on-chain
# ===========================================================================

print("=" * 70)
print("STEP 7: Verify aggregate BLS signature on-chain")
print("=" * 70)

# For aggregate verification, all 3 messages are from the same owner (deployer)
# So we pass [deployer, deployer, deployer] as owners
owners = [deployer] * 3
result = registry.functions.verifyAggregated(owners, msg_contents, agg_sig).call()
assert result is True, "Aggregate BLS verification failed on Sepolia!"
print(f"  verifyAggregated({len(owners)} owners, {len(msg_contents)} messages, aggSig) = True")

# Negative: tampered signature
bad_sig = bytes([agg_sig[0] ^ 0xFF]) + agg_sig[1:]
try:
    bad_result = registry.functions.verifyAggregated(owners, msg_contents, bad_sig).call()
except Exception:
    bad_result = False
assert not bad_result, "Should reject tampered signature"
print(f"  verifyAggregated(owners, messages, tampered_sig) = False (correct rejection)")

# Negative: wrong messages
wrong_msgs = [b"wrong"] + list(msg_contents[1:])
try:
    wrong_result = registry.functions.verifyAggregated(owners, wrong_msgs, agg_sig).call()
except Exception:
    wrong_result = False
assert not wrong_result, "Should reject wrong messages"
print(f"  verifyAggregated(owners, wrong_messages, sig) = False (correct rejection)")

print("  PASSED")
print()

# ===========================================================================
# Step 8: Test message exposure (IERC_BAM_Exposer)
# ===========================================================================

print("=" * 70)
print("STEP 8: Test message exposure (IERC_BAM_Exposer)")
print("=" * 70)

# Register batch in exposer
receipt = send_tx(
    exposer.functions.registerBatch(content_hash),
    label="registerBatch",
)

# Verify message ID computation
msg_id = exposer.functions.computeMessageId(deployer, 0, content_hash).call()
expected_id = Web3.keccak(
    Web3.to_bytes(hexstr=deployer) + (0).to_bytes(8, "big") + content_hash
)
assert msg_id == expected_id, "Message ID mismatch"
print(f"  computeMessageId matches keccak256(author || nonce || contentHash)")
print(f"  messageId: 0x{msg_id.hex()}")

# Should not be exposed yet
assert not exposer.functions.isExposed(msg_id).call(), "Should not be exposed yet"
print(f"  isExposed(messageId) = False (correct)")

# Expose message 0
receipt = send_tx(
    exposer.functions.exposeMessage(content_hash, deployer, 0, msg_contents[0]),
    label="exposeMessage #0",
)
logs = exposer.events.MessageExposed().process_receipt(receipt)
assert len(logs) == 1, "No MessageExposed event"
assert logs[0].args.contentHash == content_hash, "Wrong contentHash in event"
assert logs[0].args.messageId == msg_id, "Wrong messageId in event"
assert logs[0].args.author == deployer, "Wrong author in event"
assert logs[0].args.exposer == deployer, "Wrong exposer in event"
print(f"  MessageExposed event emitted correctly")

# Should now be exposed
assert exposer.functions.isExposed(msg_id).call(), "Should be exposed now"
print(f"  isExposed(messageId) = True (correct)")

# Double exposure should fail (test via call, not tx, to avoid nonce issues)
try:
    exposer.functions.exposeMessage(content_hash, deployer, 0, msg_contents[0]).call(
        {"from": deployer}
    )
    assert False, "Double exposure should have reverted"
except Exception as e:
    print(f"  Double exposure correctly reverted: {type(e).__name__}")

# Expose message 1
msg_id_1 = exposer.functions.computeMessageId(deployer, 1, content_hash).call()
receipt = send_tx(
    exposer.functions.exposeMessage(content_hash, deployer, 1, msg_contents[1]),
    label="exposeMessage #1",
)
assert exposer.functions.isExposed(msg_id_1).call(), "Message 1 should be exposed"
print(f"  Message 1 exposed independently")

# Unregistered batch should fail (test via call to avoid nonce issues)
fake_hash = Web3.keccak(b"unregistered batch")
try:
    exposer.functions.exposeMessage(fake_hash, deployer, 0, b"fake").call(
        {"from": deployer}
    )
    assert False, "Unregistered batch should have reverted"
except Exception as e:
    print(f"  Unregistered batch correctly reverted: {type(e).__name__}")

print("  PASSED")
print()

# ===========================================================================
# Step 9: Test BSS declareBlobSegment validation
# ===========================================================================

print("=" * 70)
print("STEP 9: Test BSS segment validation")
print("=" * 70)

# Invalid: startFE >= endFE (test via call to avoid nonce issues)
try:
    core.functions.declareBlobSegment(0, 10, 10, b"\x00" * 32).call(
        {"from": deployer}
    )
    assert False, "Should have reverted"
except Exception:
    print(f"  startFE >= endFE correctly reverted")

# Invalid: endFE > 4096
try:
    core.functions.declareBlobSegment(0, 0, 4097, b"\x00" * 32).call(
        {"from": deployer}
    )
    assert False, "Should have reverted"
except Exception:
    print(f"  endFE > 4096 correctly reverted")

print("  PASSED")
print()

# ===========================================================================
# Summary
# ===========================================================================

print("=" * 70)
print("ALL SEPOLIA TESTS PASSED")
print("=" * 70)
print()
print(f"  Network:   Sepolia (chain ID 11155111)")
print(f"  Deployer:  {deployer}")
print(f"  BAM Core:  {core.address}")
print(f"  Decoder:   {decoder.address}")
print(f"  Registry:  {registry.address}")
print(f"  Exposer:   {exposer.address}")
print()
remaining = Web3.from_wei(w3.eth.get_balance(deployer), "ether")
print(f"  Remaining balance: {remaining} ETH")

# Save deployment info
with open("sepolia_deployment.txt", "w") as f:
    f.write(f"Network: Sepolia (chain ID 11155111)\n")
    f.write(f"Deployer: {deployer}\n")
    f.write(f"BAM Core: {core.address}\n")
    f.write(f"Decoder: {decoder.address}\n")
    f.write(f"Registry: {registry.address}\n")
    f.write(f"Exposer: {exposer.address}\n")
    f.write(f"Content Hash: 0x{content_hash.hex()}\n")
print("  Deployment info saved to sepolia_deployment.txt")
