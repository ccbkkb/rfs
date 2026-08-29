#!/usr/bin/env python3
"""aioquic H3 客户端：GET/PUT 探测，用于验证 rfs HTTP/3 服务器（独立客户端）"""
import argparse, asyncio, ssl, sys
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import H3Event, DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

async def run(host, port, timeout):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    conf.verify_mode = ssl.CERT_NONE
    got = []
    async with connect(host, port, configuration=conf) as client:
        h3 = H3Connection(client._quic)
        stream_id = h3._get_next_stream_id()
        h3.send_headers(stream_id, [(b":method", b"GET"), (b":authority", f"{host}:{port}".encode()), (b":path", b"/index.html"), (b":scheme", b"https")])
        client.transmit()
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                event = await asyncio.wait_for(client.wait_for(0.05), timeout=1)
            except asyncio.TimeoutError:
                continue
            if event is None:
                continue
            for e in h3.handle_event(event):
                if isinstance(e, HeadersReceived):
                    got.append(("HEADERS", dict(e.headers)))
                elif isinstance(e, DataReceived):
                    got.append(("DATA", len(e.data)))
        return got

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=19443)
    ap.add_argument("--timeout", type=float, default=6)
    args = ap.parse_args()
    try:
        res = asyncio.run(run(args.host, args.port, args.timeout))
        ok = any(t == "HEADERS" for t, _ in res)
        print("SUCCESS", res)
        sys.exit(0 if ok else 1)
    except Exception as e:
        print("FAIL:", type(e).__name__, e)
        sys.exit(2)

if __name__ == "__main__":
    main()