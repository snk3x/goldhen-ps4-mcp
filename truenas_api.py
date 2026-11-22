"""Tiny TrueNAS JSON-RPC client (WebSocket). The API key is read from the
TRUENAS_API_KEY environment variable or from ~/.truenas/api_key; it is never printed.

  python truenas_api.py <method> [json params list]
  python truenas_api.py app.query '[[["name","=","ps4-mcp"]]]'

TRUENAS_HOST is required (self-signed certificate: not verified).
Needs: pip install websockets
"""
import asyncio
import json
import os
import ssl
import sys
from pathlib import Path

import websockets

HOST = os.environ.get("TRUENAS_HOST", "").strip()
if not HOST:
    raise SystemExit("set TRUENAS_HOST to your TrueNAS address, e.g. TRUENAS_HOST=192.168.0.20")


def _key() -> str:
    k = os.environ.get("TRUENAS_API_KEY")
    if not k:
        p = Path.home() / ".truenas" / "api_key"
        k = p.read_text().strip() if p.is_file() else ""
    if not k:
        raise SystemExit("no TrueNAS API key (set TRUENAS_API_KEY or create ~/.truenas/api_key)")
    return k


async def call(method: str, params: list | None = None, timeout: float = 60):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    async with websockets.connect(f"wss://{HOST}/api/current", ssl=ctx, max_size=None,
                                  open_timeout=15) as ws:
        async def rpc(i, m, p):
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": i, "method": m, "params": p}))
            while True:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout))
                if msg.get("id") == i:
                    if "error" in msg:
                        raise RuntimeError(json.dumps(msg["error"])[:1500])
                    return msg.get("result")
        if not await rpc(1, "auth.login_with_api_key", [_key()]):
            raise SystemExit("API key rejected")
        return await rpc(2, method, params or [])


if __name__ == "__main__":
    out = asyncio.run(call(sys.argv[1], json.loads(sys.argv[2]) if len(sys.argv) > 2 else []))
    print(json.dumps(out, indent=2, default=str)[:6000])
