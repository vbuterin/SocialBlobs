"""test_erc_interfaces.py -- Tests for PR #12 ERC interface contracts.

Tests bam_core.vy (IERC_BAM_Core / IERC_BSS) and exposer.vy (IERC_BAM_Exposer)
per the PR #12 test plan.
"""

import pytest
from pathlib import Path
from web3 import Web3
from vyper import compile_code

from data_signer import Signer, aggregate_signatures
from blob_encoder import encode_blob, signing_payload
from paths import CONTRACTS_DIR, CORPUS_PATH
from bpe_encode import build_12bit_dict_from_corpus, encode_msg


# -- Fixtures --


def compile_vyper(source: str) -> dict:
    return compile_code(source, output_formats=["abi", "bytecode"])


def deploy_contract(w3, compiled, deployer, *args):
    factory = w3.eth.contract(abi=compiled["abi"], bytecode=compiled["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        factory.constructor(*args).transact({"from": deployer})
    )
    return w3.eth.contract(address=receipt.contractAddress, abi=compiled["abi"])


@pytest.fixture(scope="module")
def w3():
    from web3.providers.eth_tester import EthereumTesterProvider
    return Web3(EthereumTesterProvider())


@pytest.fixture(scope="module")
def deployer(w3):
    return w3.eth.accounts[0]


@pytest.fixture(scope="module")
def accounts(w3):
    return w3.eth.accounts


@pytest.fixture(scope="module")
def bam_core(w3, deployer):
    source = (CONTRACTS_DIR / "bam_core.vy").read_text()
    return deploy_contract(w3, compile_vyper(source), deployer)


@pytest.fixture(scope="module")
def exposer(w3, deployer, bam_core):
    source = (CONTRACTS_DIR / "exposer.vy").read_text()
    return deploy_contract(w3, compile_vyper(source), deployer, bam_core.address)


@pytest.fixture(scope="module")
def compression():
    token_to_code, dict_bytes, _, _ = build_12bit_dict_from_corpus(str(CORPUS_PATH))
    return token_to_code


# -- BSS / declareBlobSegment --


class TestDeclareBlobSegment:
    """Verify declareBlobSegment reverts on startFE >= endFE and endFE > 4096."""

    def test_startFE_equals_endFE_reverts(self, bam_core, deployer):
        with pytest.raises(Exception, match="InvalidSegment"):
            bam_core.functions.declareBlobSegment(
                0, 100, 100, b"\x00" * 32
            ).call({"from": deployer})

    def test_startFE_greater_than_endFE_reverts(self, bam_core, deployer):
        with pytest.raises(Exception, match="InvalidSegment"):
            bam_core.functions.declareBlobSegment(
                0, 200, 100, b"\x00" * 32
            ).call({"from": deployer})

    def test_endFE_exceeds_4096_reverts(self, bam_core, deployer):
        with pytest.raises(Exception, match="InvalidSegment"):
            bam_core.functions.declareBlobSegment(
                0, 0, 4097, b"\x00" * 32
            ).call({"from": deployer})

    def test_endFE_exactly_4096_valid_bounds(self, bam_core, deployer):
        """endFE=4096 is within bounds (only fails due to no blob, not bounds)."""
        with pytest.raises(Exception, match="NoBlobAtIndex"):
            bam_core.functions.declareBlobSegment(
                0, 0, 4096, b"\x00" * 32
            ).call({"from": deployer})

    def test_startFE_zero_endFE_one_valid_bounds(self, bam_core, deployer):
        """Smallest valid segment (only fails due to no blob, not bounds)."""
        with pytest.raises(Exception, match="NoBlobAtIndex"):
            bam_core.functions.declareBlobSegment(
                0, 0, 1, b"\x00" * 32
            ).call({"from": deployer})


# -- registerBlobBatch --


class TestRegisterBlobBatch:
    """Verify registerBlobBatch validates BSS bounds before emitting events."""

    def test_startFE_equals_endFE_reverts(self, bam_core, deployer):
        with pytest.raises(Exception, match="InvalidSegment"):
            bam_core.functions.registerBlobBatch(
                0, 100, 100, b"\x00" * 32,
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002",
            ).call({"from": deployer})

    def test_endFE_exceeds_4096_reverts(self, bam_core, deployer):
        with pytest.raises(Exception, match="InvalidSegment"):
            bam_core.functions.registerBlobBatch(
                0, 0, 4097, b"\x00" * 32,
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002",
            ).call({"from": deployer})

    def test_valid_bounds_reverts_on_no_blob(self, bam_core, deployer):
        """Valid segment bounds pass BSS validation but fail on missing blob."""
        with pytest.raises(Exception, match="NoBlobAtIndex"):
            bam_core.functions.registerBlobBatch(
                0, 0, 4096, b"\x00" * 32,
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002",
            ).call({"from": deployer})


# -- registerCalldataBatch --


class TestRegisterCalldataBatch:
    """Verify registerCalldataBatch computes hash, emits event, stores registration."""

    def test_emits_CalldataBatchRegistered(self, w3, bam_core, deployer, compression):
        compressor = lambda msg: encode_msg(msg, compression)
        signer = Signer.generate()
        content = b"test message"
        sig = signer.sign(signing_payload(0, content))
        blob = encode_blob([(deployer, 0, content)], [sig], compressor)

        tx = bam_core.functions.registerCalldataBatch(
            blob, deployer, deployer
        ).transact({"from": deployer})
        receipt = w3.eth.wait_for_transaction_receipt(tx)

        logs = bam_core.events.CalldataBatchRegistered().process_receipt(receipt)
        assert len(logs) == 1
        assert logs[0].args.contentHash == Web3.keccak(blob)
        assert logs[0].args.submitter == deployer
        assert logs[0].args.decoder == deployer
        assert logs[0].args.signatureRegistry == deployer

    def test_stores_content_hash_in_registered(self, w3, bam_core, deployer, compression):
        compressor = lambda msg: encode_msg(msg, compression)
        signer = Signer.generate()
        content = b"another test"
        sig = signer.sign(signing_payload(1, content))
        blob = encode_blob([(deployer, 1, content)], [sig], compressor)

        content_hash = Web3.keccak(blob)
        assert bam_core.functions.registered(content_hash).call() is False

        tx = bam_core.functions.registerCalldataBatch(
            blob, deployer, deployer
        ).transact({"from": deployer})
        w3.eth.wait_for_transaction_receipt(tx)

        assert bam_core.functions.registered(content_hash).call() is True

    def test_content_hash_is_keccak256(self, w3, bam_core, deployer):
        data = b"raw data payload"
        tx = bam_core.functions.registerCalldataBatch(
            data, deployer, deployer
        ).transact({"from": deployer})
        receipt = w3.eth.wait_for_transaction_receipt(tx)

        logs = bam_core.events.CalldataBatchRegistered().process_receipt(receipt)
        assert logs[0].args.contentHash == Web3.keccak(data)


# -- Exposer --


class TestExposer:
    """Verify exposer contract: expose, double-expose revert, unregistered revert."""

    @pytest.fixture(autouse=True)
    def setup(self, w3, bam_core, exposer, deployer):
        """Register a batch so we can expose messages from it."""
        self.w3 = w3
        self.bam_core = bam_core
        self.exposer = exposer
        self.deployer = deployer
        self.batch_data = b"exposer test batch"
        self.content_hash = Web3.keccak(self.batch_data)

        # Register the batch
        tx = bam_core.functions.registerCalldataBatch(
            self.batch_data, deployer, deployer
        ).transact({"from": deployer})
        w3.eth.wait_for_transaction_receipt(tx)

    def test_exposeMessage_reverts_NotRegistered(self):
        fake_hash = Web3.keccak(b"unregistered batch")
        msg_content_hash = Web3.keccak(b"msg")
        with pytest.raises(Exception, match="NotRegistered"):
            self.exposer.functions.exposeMessage(
                fake_hash, self.deployer, 0, msg_content_hash
            ).transact({"from": self.deployer})

    def test_isExposed_false_before_exposure(self):
        msg_content_hash = Web3.keccak(b"unexposed msg")
        message_id = self.exposer.functions.computeMessageId(
            self.deployer, 99, msg_content_hash
        ).call()
        assert self.exposer.functions.isExposed(message_id).call() is False

    def test_exposeMessage_emits_MessageExposed(self):
        msg_content_hash = Web3.keccak(b"expose me")
        tx = self.exposer.functions.exposeMessage(
            self.content_hash, self.deployer, 0, msg_content_hash
        ).transact({"from": self.deployer})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx)

        logs = self.exposer.events.MessageExposed().process_receipt(receipt)
        assert len(logs) == 1
        assert logs[0].args.author == self.deployer
        assert logs[0].args.contentHash == self.content_hash

        expected_id = self.exposer.functions.computeMessageId(
            self.deployer, 0, msg_content_hash
        ).call()
        assert logs[0].args.messageId == expected_id

    def test_isExposed_true_after_exposure(self):
        msg_content_hash = Web3.keccak(b"check exposed")
        tx = self.exposer.functions.exposeMessage(
            self.content_hash, self.deployer, 1, msg_content_hash
        ).transact({"from": self.deployer})
        self.w3.eth.wait_for_transaction_receipt(tx)

        message_id = self.exposer.functions.computeMessageId(
            self.deployer, 1, msg_content_hash
        ).call()
        assert self.exposer.functions.isExposed(message_id).call() is True

    def test_exposeMessage_reverts_AlreadyExposed(self):
        msg_content_hash = Web3.keccak(b"double expose")
        tx = self.exposer.functions.exposeMessage(
            self.content_hash, self.deployer, 2, msg_content_hash
        ).transact({"from": self.deployer})
        self.w3.eth.wait_for_transaction_receipt(tx)

        with pytest.raises(Exception, match="AlreadyExposed"):
            self.exposer.functions.exposeMessage(
                self.content_hash, self.deployer, 2, msg_content_hash
            ).transact({"from": self.deployer})

    def test_computeMessageId_matches_keccak(self):
        author = self.deployer
        nonce = 42
        content_hash = Web3.keccak(b"test")

        on_chain_id = self.exposer.functions.computeMessageId(
            author, nonce, content_hash
        ).call()

        manual_id = Web3.keccak(
            bytes.fromhex(author[2:].lower()) +
            nonce.to_bytes(8, "big") +
            content_hash
        )
        assert on_chain_id == manual_id


# -- Existing contracts unmodified --


class TestExistingContractsUnmodified:
    """Verify decoder.vy and signature_registry.vy still work as before."""

    def test_decoder_decompress_roundtrip(self, w3, deployer):
        from bpe_encode import deploy_decoder
        token_to_code, dict_bytes, _, _ = build_12bit_dict_from_corpus(str(CORPUS_PATH))
        dec = deploy_decoder(w3, deployer, dict_bytes)

        msg = b"hello world"
        compressed = encode_msg(msg, token_to_code)
        assert dec.functions.decompress(compressed).call() == msg

    def test_registry_scheme_metadata(self, w3, deployer):
        source = (CONTRACTS_DIR / "signature_registry.vy").read_text()
        reg = deploy_contract(w3, compile_vyper(source), deployer)
        assert reg.functions.schemeId().call() == 2
        assert reg.functions.schemeName().call() == "BLS12-381"
