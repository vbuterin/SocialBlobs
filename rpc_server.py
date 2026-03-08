"""rpc_server.py

JSON-RPC 2.0 server for the BAM (Blob-Authenticated Messaging) protocol.

Exposes the BAMProvider interface over HTTP and WebSocket transports.

Usage:
    python rpc_server.py --port 8545
    python rpc_server.py --port 8545 --ws-port 8546
    python -m rpc_server --port 8545
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import struct
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Dict, List, Optional, Set

from bam_provider import BAMProvider, DefaultBAMProvider

logger = logging.getLogger("bam-rpc")


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

class RPCError(Exception):
    """JSON-RPC error with code and message."""
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            d["data"] = self.data
        return d


PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def _hex_to_bytes(hex_str: str) -> bytes:
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def _make_response(id_: Any, result: Any = None, error: Any = None) -> Dict:
    resp: Dict[str, Any] = {"jsonrpc": "2.0", "id": id_}
    if error is not None:
        resp["error"] = error
    else:
        resp["result"] = result
    return resp


# ---------------------------------------------------------------------------
# RPC method dispatcher
# ---------------------------------------------------------------------------

class BAMRPCDispatcher:
    """Maps JSON-RPC method names to handler functions."""

    def __init__(self, provider: BAMProvider):
        self.provider = provider
        self._methods: Dict[str, Callable] = {
            "bam_encodeBatch": self._encode_batch,
            "bam_decodeBatch": self._decode_batch,
            "bam_verifyBatch": self._verify_batch,
            "bam_compress": self._compress,
            "bam_decompress": self._decompress,
            "bam_getDictionary": self._get_dictionary,
            "bam_status": self._status,
        }

    def dispatch(self, method: str, params: Any) -> Any:
        handler = self._methods.get(method)
        if handler is None:
            raise RPCError(METHOD_NOT_FOUND, f"Method not found: {method}")
        if params is None:
            params = []
        if isinstance(params, list):
            return handler(*params)
        elif isinstance(params, dict):
            return handler(**params)
        else:
            raise RPCError(INVALID_PARAMS, "params must be array or object")

    def _encode_batch(self, messages: List[Dict], private_keys: List[str]) -> Dict:
        parsed = []
        for m in messages:
            sender = m["sender"]
            nonce = m["nonce"]
            contents = _hex_to_bytes(m["contents"]) if isinstance(m["contents"], str) else m["contents"]
            if isinstance(contents, str):
                contents = contents.encode("utf-8")
            parsed.append((sender, nonce, contents))
        keys = [int(k, 16) if isinstance(k, str) else k for k in private_keys]
        result = self.provider.encode_batch(parsed, keys)
        return result.to_dict()

    def _decode_batch(self, payload: str) -> List[Dict]:
        data = _hex_to_bytes(payload)
        messages = self.provider.decode_batch(data)
        return [m.to_dict() for m in messages]

    def _verify_batch(self, payload: str, pubkeys: List[str]) -> Dict:
        data = _hex_to_bytes(payload)
        pk_bytes = [_hex_to_bytes(pk) for pk in pubkeys]
        result = self.provider.verify_batch(data, pk_bytes)
        return result.to_dict()

    def _compress(self, data: str) -> str:
        raw = _hex_to_bytes(data) if data.startswith("0x") else data.encode("utf-8")
        compressed = self.provider.compress(raw)
        return "0x" + compressed.hex()

    def _decompress(self, data: str) -> str:
        raw = _hex_to_bytes(data)
        decompressed = self.provider.decompress(raw)
        return "0x" + decompressed.hex()

    def _get_dictionary(self) -> Dict:
        return self.provider.get_dictionary().to_dict()

    def _status(self) -> Dict:
        return self.provider.status().to_dict()


# ---------------------------------------------------------------------------
# HTTP JSON-RPC server
# ---------------------------------------------------------------------------

class RPCHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for JSON-RPC 2.0 requests."""

    dispatcher: BAMRPCDispatcher  # set by server factory

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug(format, *args)

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(
                _make_response(None, error=RPCError(PARSE_ERROR, "Parse error").to_dict())
            )
            return

        # Handle batch requests
        if isinstance(request, list):
            responses = [self._handle_single(r) for r in request]
            self._send_json(responses)
        else:
            response = self._handle_single(request)
            self._send_json(response)

    def _handle_single(self, request: Dict) -> Dict:
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params")

        if not method or request.get("jsonrpc") != "2.0":
            return _make_response(
                req_id, error=RPCError(INVALID_REQUEST, "Invalid JSON-RPC 2.0 request").to_dict()
            )

        try:
            result = self.dispatcher.dispatch(method, params)
            return _make_response(req_id, result=result)
        except RPCError as e:
            return _make_response(req_id, error=e.to_dict())
        except Exception as e:
            logger.exception("Internal error in %s", method)
            return _make_response(
                req_id, error=RPCError(INTERNAL_ERROR, str(e)).to_dict()
            )

    def _send_json(self, data: Any) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ---------------------------------------------------------------------------
# WebSocket server (asyncio-based, minimal RFC 6455)
# ---------------------------------------------------------------------------

class WebSocketServer:
    """Minimal WebSocket JSON-RPC server using asyncio.

    Supports:
    - JSON-RPC 2.0 method calls
    - bam_subscribe / bam_unsubscribe for push notifications
    """

    def __init__(self, dispatcher: BAMRPCDispatcher, host: str = "0.0.0.0", port: int = 8546):
        self.dispatcher = dispatcher
        self.host = host
        self.port = port
        self._subscribers: Dict[str, Set[asyncio.StreamWriter]] = {}
        self._server: Optional[asyncio.Server] = None

    async def start(self) -> None:
        try:
            import websockets
        except ImportError:
            logger.warning(
                "websockets package not installed — WebSocket server disabled. "
                "Install with: pip install websockets"
            )
            return

        async def handler(websocket: Any) -> None:
            try:
                async for raw_msg in websocket:
                    try:
                        request = json.loads(raw_msg)
                    except json.JSONDecodeError:
                        await websocket.send(json.dumps(
                            _make_response(None, error=RPCError(PARSE_ERROR, "Parse error").to_dict())
                        ))
                        continue

                    method = request.get("method", "")
                    params = request.get("params")
                    req_id = request.get("id")

                    if method == "bam_subscribe":
                        topic = params[0] if params else "batches"
                        if topic not in self._subscribers:
                            self._subscribers[topic] = set()
                        self._subscribers[topic].add(websocket)
                        await websocket.send(json.dumps(
                            _make_response(req_id, result={"subscribed": topic})
                        ))
                    elif method == "bam_unsubscribe":
                        topic = params[0] if params else "batches"
                        if topic in self._subscribers:
                            self._subscribers[topic].discard(websocket)
                        await websocket.send(json.dumps(
                            _make_response(req_id, result={"unsubscribed": topic})
                        ))
                    else:
                        try:
                            result = self.dispatcher.dispatch(method, params)
                            await websocket.send(json.dumps(
                                _make_response(req_id, result=result)
                            ))
                        except RPCError as e:
                            await websocket.send(json.dumps(
                                _make_response(req_id, error=e.to_dict())
                            ))
                        except Exception as e:
                            await websocket.send(json.dumps(
                                _make_response(req_id, error=RPCError(INTERNAL_ERROR, str(e)).to_dict())
                            ))
            except Exception:
                pass
            finally:
                for subs in self._subscribers.values():
                    subs.discard(websocket)

        self._server = await websockets.serve(handler, self.host, self.port)
        logger.info("WebSocket server listening on ws://%s:%d", self.host, self.port)

    async def notify(self, topic: str, data: Any) -> None:
        """Push a notification to all subscribers of a topic."""
        subscribers = self._subscribers.get(topic, set())
        if not subscribers:
            return
        msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "bam_subscription",
            "params": {"topic": topic, "data": data},
        })
        dead = set()
        for ws in subscribers:
            try:
                await ws.send(msg)
            except Exception:
                dead.add(ws)
        subscribers -= dead

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------

def create_http_server(
    provider: BAMProvider,
    host: str = "0.0.0.0",
    port: int = 8545,
) -> HTTPServer:
    """Create and return an HTTP JSON-RPC server."""
    dispatcher = BAMRPCDispatcher(provider)
    RPCHTTPHandler.dispatcher = dispatcher
    server = HTTPServer((host, port), RPCHTTPHandler)
    logger.info("HTTP JSON-RPC server listening on http://%s:%d", host, port)
    return server


def create_ws_server(
    provider: BAMProvider,
    host: str = "0.0.0.0",
    port: int = 8546,
) -> WebSocketServer:
    """Create a WebSocket JSON-RPC server."""
    dispatcher = BAMRPCDispatcher(provider)
    return WebSocketServer(dispatcher, host, port)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="BAM JSON-RPC Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8545, help="HTTP port (default: 8545)")
    parser.add_argument("--ws-port", type=int, default=0, help="WebSocket port (0 = disabled)")
    parser.add_argument("--corpus", default="corpus.txt", help="Path to BPE corpus file")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    provider = DefaultBAMProvider(corpus_path=args.corpus)
    logger.info("BAM provider initialized (corpus=%s)", args.corpus)

    http_server = create_http_server(provider, args.host, args.port)

    if args.ws_port > 0:
        ws_server = create_ws_server(provider, args.host, args.ws_port)
        loop = asyncio.new_event_loop()
        loop.run_until_complete(ws_server.start())
        ws_thread = threading.Thread(target=loop.run_forever, daemon=True)
        ws_thread.start()

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        http_server.shutdown()


if __name__ == "__main__":
    main()
