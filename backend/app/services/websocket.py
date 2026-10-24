import asyncio
import json
import logging
from typing import Dict, Set, Optional, Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class ConnectionManager:
    """
    Manages live WebSocket client connections for real-time instant notifications,
    threat alerts, and access request lifecycle events.
    """
    def __init__(self):
        # Map user_id -> Set of active WebSocket connections
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # Track admin user_ids for targeted security alert broadcasts
        self.admin_users: Set[str] = set()

    async def connect(self, websocket: WebSocket, user_id: str, role: str):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        self.active_connections[user_id].add(websocket)
        if role == "admin":
            self.admin_users.add(user_id)
        logger.info(f"[WebSocket] User {user_id} ({role}) connected. Active users: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket, user_id: str):
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                self.admin_users.discard(user_id)
        logger.info(f"[WebSocket] User {user_id} disconnected. Active users: {len(self.active_connections)}")

    async def send_to_user(self, user_id: str, message: Dict[str, Any]):
        if user_id in self.active_connections:
            dead = set()
            for ws in list(self.active_connections[user_id]):
                try:
                    await ws.send_text(json.dumps(message))
                except Exception:
                    dead.add(ws)
            for ws in dead:
                self.active_connections[user_id].discard(ws)

    async def broadcast_to_admins(self, message: Dict[str, Any]):
        dead = []
        for admin_id in list(self.admin_users):
            if admin_id in self.active_connections:
                for ws in list(self.active_connections[admin_id]):
                    try:
                        await ws.send_text(json.dumps(message))
                    except Exception:
                        dead.append((admin_id, ws))
        for admin_id, ws in dead:
            if admin_id in self.active_connections:
                self.active_connections[admin_id].discard(ws)

    async def broadcast(self, message: Dict[str, Any]):
        dead = []
        for user_id, conns in list(self.active_connections.items()):
            for ws in list(conns):
                try:
                    await ws.send_text(json.dumps(message))
                except Exception:
                    dead.append((user_id, ws))
        for user_id, ws in dead:
            if user_id in self.active_connections:
                self.active_connections[user_id].discard(ws)

    # Sync-safe helper methods callable from synchronous database operations and services
    def sync_send_to_user(self, user_id: str, message: Dict[str, Any]):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.send_to_user(user_id, message))
        except RuntimeError:
            pass

    def sync_broadcast_to_admins(self, message: Dict[str, Any]):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast_to_admins(message))
        except RuntimeError:
            pass

    def sync_broadcast(self, message: Dict[str, Any]):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(message))
        except RuntimeError:
            pass

manager = ConnectionManager()
