.PHONY: test test-unit test-e2e test-rpc lint install clean

# Run all tests
test:
	python -m pytest tests/ -v

# Run unit tests only (fast, no contract deployment)
test-unit:
	python -m pytest tests/test_bpe_encode.py tests/test_blob_encoder.py tests/test_data_signer.py -v

# Run integration / e2e tests (deploys contracts to eth_tester)
test-e2e:
	python -m pytest tests/test_decoder.py tests/test_erc_interfaces.py tests/test_signature_registry.py tests/test_e2e.py -v

# Run RPC server tests
test-rpc:
	python -m pytest tests/test_rpc_server.py -v

# Run the legacy integration script
test-legacy:
	python tests/test.py

# Install dependencies
install:
	pip install -e ".[dev]"

# Start the RPC server
serve:
	python -m src.rpc_server --port 8545

# Clean build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -f out.blob
