import logging
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from app.core.security import decode_access_token
from app.core.config import settings
from app.db.session import SessionLocal
from app.models.user import User
from app.services.websocket import manager

logger = logging.getLogger(__name__)

router = APIRouter()

@router.websocket("/ws")
async def websocket_notifications(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for real-time live notification delivery,
    security threat alerts, and access request state synchronization.
    """
    # 1. Resolve authentication token
    auth_token = token
    if not auth_token:
        # Check cookie fallback
        auth_token = websocket.cookies.get(settings.SESSION_COOKIE_NAME)
    if not auth_token:
        # Check authorization header in websocket headers
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            auth_token = auth_header[7:].strip()

    if not auth_token:
        logger.warning("[WebSocket] Connection rejected: No authentication token provided.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # 2. Decode and validate JWT
    payload = decode_access_token(auth_token)
    if not payload or not payload.get("sub"):
        logger.warning("[WebSocket] Connection rejected: Invalid or expired token.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user_id = payload.get("sub")

    # 3. Verify active user in database
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
        if not user:
            logger.warning(f"[WebSocket] Connection rejected: User {user_id} inactive or not found.")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        user_role = str(user.role.value if hasattr(user.role, "value") else user.role)
    finally:
        db.close()

    # 4. Register connection
    await manager.connect(websocket, user_id=str(user_id), role=user_role)
    try:
        await websocket.send_json({
            "type": "CONNECTED",
            "user_id": str(user_id),
            "role": user_role,
            "message": "Connected to TrustVault real-time notifications stream."
        })

        while True:
            raw_text = await websocket.receive_text()
            if raw_text == "ping":
                await websocket.send_text("pong")
            elif raw_text:
                try:
                    import json
                    msg = json.loads(raw_text)
                    if msg.get("type") == "PING":
                        await websocket.send_json({"type": "PONG"})
                except Exception:
                    pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id=str(user_id))
    except Exception as e:
        logger.debug(f"[WebSocket] Client {user_id} disconnected with exception: {e}")
        manager.disconnect(websocket, user_id=str(user_id))
