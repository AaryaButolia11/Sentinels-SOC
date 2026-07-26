"""
routes/stream.py
================
WS /ws/alerts - clients connect and receive each new Alert as JSON the
moment pipeline.process() raises one. A tiny in-process pub/sub
(ConnectionManager) is enough for a hackathon demo; swap for
Redis pub/sub if you need multiple API worker processes.
"""
from __future__ import annotations
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["stream"])


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def alerts_ws(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect client -> server messages, but keep the
            # socket alive by waiting on receive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)