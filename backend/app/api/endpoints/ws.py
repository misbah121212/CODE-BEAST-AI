from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import json
import os
import asyncio
from app.agents.nodes import register_ws_listener, unregister_ws_listener

router = APIRouter()

@router.websocket("/updates")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    loop = asyncio.get_running_loop()
    queue = asyncio.Queue()
    register_ws_listener(queue, loop)
    
    # Try Redis fallback task if available
    async def queue_listener():
        while True:
            payload = await queue.get()
            await websocket.send_text(payload)

    async def client_listener():
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass

    q_task = asyncio.create_task(queue_listener())
    c_task = asyncio.create_task(client_listener())

    try:
        done, pending = await asyncio.wait(
            [q_task, c_task],
            return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()
    except Exception:
        pass
    finally:
        unregister_ws_listener(queue, loop)
        try:
            await websocket.close()
        except Exception:
            pass

