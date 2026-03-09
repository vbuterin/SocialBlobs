"""test_rpc_server.py

Integration tests for the BAM JSON-RPC server and client.
"""

import json
import threading
import time

import pytest

from bam_provider import BAMProvider, DefaultBAMProvider, Message, BatchResult, DictInfo
from rpc_server import BAMRPCDispatcher, RPCError, create_http_server
from bam_client import BAMClient, BAMClientError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def provider():
    return DefaultBAMProvider()


@pytest.fixture(scope="module")
def dispatcher(provider):
    return BAMRPCDispatcher(provider)


@pytest.fixture(scope="module")
def server_url(provider):
    """Start an HTTP server on a random port and return the URL."""
    import socket
    # Find a free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = create_http_server(provider, "127.0.0.1", port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)  # wait for server to start
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture(scope="module")
def client(server_url):
    return BAMClient(server_url)


# ---------------------------------------------------------------------------
# Dispatcher unit tests
# ---------------------------------------------------------------------------

class TestDispatcher:
    def test_status(self, dispatcher):
        result = dispatcher.dispatch("bam_status", None)
        assert result["version"] == "0.1.0"
        assert result["provider"] == "DefaultBAMProvider"
        assert "dictInfo" in result

    def test_get_dictionary(self, dispatcher):
        result = dispatcher.dispatch("bam_getDictionary", None)
        assert result["numCodes"] >= 1024
        assert result["bitsPerCode"] == 12
        assert result["dictBytesSize"] > 0

    def test_compress_decompress(self, dispatcher):
        msg = b"hello world"
        compressed = dispatcher.dispatch("bam_compress", ["0x" + msg.hex()])
        assert compressed.startswith("0x")
        decompressed = dispatcher.dispatch("bam_decompress", [compressed])
        assert decompressed.startswith("0x")
        # Decompressed should contain original (may have trailing padding)
        dec_bytes = bytes.fromhex(decompressed[2:])
        assert dec_bytes[:len(msg)] == msg

    def test_method_not_found(self, dispatcher):
        with pytest.raises(RPCError) as exc_info:
            dispatcher.dispatch("bam_nonExistent", None)
        assert exc_info.value.code == -32601

    def test_compress_hex(self, dispatcher):
        msg = b"The quick brown fox jumps over the lazy dog"
        result = dispatcher.dispatch("bam_compress", ["0x" + msg.hex()])
        assert isinstance(result, str)
        assert result.startswith("0x")
        compressed_bytes = bytes.fromhex(result[2:])
        # Should be shorter than original (compression works)
        assert len(compressed_bytes) <= len(msg)


# ---------------------------------------------------------------------------
# HTTP integration tests
# ---------------------------------------------------------------------------

class TestHTTPServer:
    def test_status_via_client(self, client):
        result = client.status()
        assert result["version"] == "0.1.0"
        assert "dictInfo" in result

    def test_get_dictionary_via_client(self, client):
        result = client.get_dictionary()
        assert result["numCodes"] >= 1024
        assert result["bitsPerCode"] == 12

    def test_compress_via_client(self, client):
        result = client.compress(b"hello world")
        assert result.startswith("0x")

    def test_decompress_via_client(self, client):
        compressed = client.compress(b"test message")
        decompressed = client.decompress(compressed)
        assert decompressed.startswith("0x")
        dec_bytes = bytes.fromhex(decompressed[2:])
        assert dec_bytes[:len(b"test message")] == b"test message"

    def test_method_not_found_via_client(self, client):
        with pytest.raises(BAMClientError) as exc_info:
            client._call("bam_doesNotExist", [])
        assert exc_info.value.code == -32601

    def test_batch_request(self, server_url):
        """Test JSON-RPC batch request."""
        import urllib.request
        batch = [
            {"jsonrpc": "2.0", "method": "bam_status", "params": [], "id": 1},
            {"jsonrpc": "2.0", "method": "bam_getDictionary", "params": [], "id": 2},
        ]
        data = json.dumps(batch).encode("utf-8")
        req = urllib.request.Request(
            server_url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            results = json.loads(resp.read())
        assert len(results) == 2
        assert results[0]["id"] == 1
        assert results[1]["id"] == 2
        assert "result" in results[0]
        assert "result" in results[1]

    def test_invalid_json(self, server_url):
        """Test malformed JSON returns parse error."""
        import urllib.request
        req = urllib.request.Request(
            server_url, data=b"not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
        assert "error" in result
        assert result["error"]["code"] == -32700


# ---------------------------------------------------------------------------
# Provider unit tests
# ---------------------------------------------------------------------------

class TestDefaultProvider:
    def test_compress_roundtrip(self, provider):
        msg = b"Ethereum is great"
        compressed = provider.compress(msg)
        decompressed = provider.decompress(compressed)
        assert decompressed[:len(msg)] == msg

    def test_status_returns_valid(self, provider):
        status = provider.status()
        assert status.version == "0.1.0"
        assert status.provider == "DefaultBAMProvider"
        assert status.dict_info.num_codes >= 1024

    def test_decode_empty_payload_raises(self, provider):
        with pytest.raises(Exception):
            provider.decode_batch(b"")

    def test_dict_info(self, provider):
        info = provider.get_dictionary()
        assert info.num_codes >= 1024
        assert info.bits_per_code == 12
        assert info.dict_bytes_size > 0
