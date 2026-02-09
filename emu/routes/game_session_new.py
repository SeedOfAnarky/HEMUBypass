"""
Server-side game session creation endpoint
Called by HytaleServer.exe to create authenticated server sessions
"""

import base64
import json
import time
import uuid


def _b64url_decode_no_verify(jwt_token):
    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    payload_b64 = parts[1]
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)


def handle_game_session_new(body, headers, ctx):
    """
    POST /game-session/new - Create server-side game session

    HytaleServer.exe calls this after OAuth to create an authenticated session.
    """
    log = ctx["log"]
    data = ctx["data"]
    config = ctx["config"]

    log("GAME_SESSION", "Server session creation request")

    # Extract access token from Authorization header or body
    auth_header = headers.get("authorization", headers.get("Authorization", ""))
    access_token = body.get("access_token") if isinstance(body, dict) else None

    if auth_header.startswith("Bearer "):
        access_token = auth_header[7:]

    if not access_token:
        log("GAME_SESSION", "No access token provided!", "ERROR")
        return 401, {"error": "unauthorized"}

    # Prefer the requested UUID in the request body (when present).
    requested_uuid = body.get("uuid") if isinstance(body, dict) else None

    # Decode token payload (no signature verification here).
    token_sub = None
    try:
        token_payload = _b64url_decode_no_verify(access_token)
        token_sub = token_payload.get("sub")
        log("GAME_SESSION", f"Token subject (UUID): {token_sub}")
    except Exception as e:
        log("GAME_SESSION", f"Failed to decode access token: {e}", "ERROR")

    user_uuid = requested_uuid or token_sub
    if not user_uuid:
        log("GAME_SESSION", "No user UUID available (body.uuid or token.sub)", "ERROR")
        return 401, {"error": "invalid_token"}

    if requested_uuid and token_sub and requested_uuid != token_sub:
        log("GAME_SESSION", f"Body UUID differs from token sub. body={requested_uuid} token={token_sub}", "WARN")

    # Find user by UUID
    users = data.get("users", {}).get("users", [])
    user = next((u for u in users if u.get("uuid") == user_uuid), None)
    if not user:
        log("GAME_SESSION", f"User not found: {user_uuid}", "ERROR")
        return 404, {"error": "user_not_found"}

    username = user.get("username", "Player")
    entitlements = user.get("entitlements", ["game.base"])
    skin = user.get("skin", {})
    skin_string = json.dumps(skin, separators=(",", ":")) if isinstance(skin, dict) else str(skin)

    issuer = (
        config.get("emulation", {}).get("issuer")
        or config.get("issuer")
        or "https://sessions.hytale.com"
    )

    # Create session + tokens (EdDSA, matching sessions service style)
    session_id = str(uuid.uuid4())
    now = int(time.time())
    expiry_seconds = 3600
    exp = now + expiry_seconds

    base_payload = {
        "exp": exp,
        "iat": now,
        "iss": issuer,
        "jti": session_id,
        "scope": "hytale:server",
        "sub": user_uuid,
    }

    identity_payload = dict(base_payload)
    identity_payload["profile"] = {
        "username": username,
        "entitlements": entitlements,
        "skin": skin_string,
    }

    session_payload = dict(base_payload)

    identity_token = ctx["sign_jwt"](identity_payload)
    session_token = ctx["sign_jwt"](session_payload)

    # Persist session in the emulator store
    ctx["sessions"][session_id] = {
        "username": username,
        "user_uuid": user_uuid,
        "created_at": now,
        "expires_at": exp,
        "type": "server_session",
    }
    ctx["save_sessions"]()

    # RFC3339 (seconds) with Z, matching official docs/examples.
    import datetime as _dt
    expires_at = _dt.datetime.utcfromtimestamp(exp).strftime("%Y-%m-%dT%H:%M:%SZ")

    response = {
        "expiresAt": expires_at,
        "identityToken": identity_token,
        "sessionToken": session_token,
    }

    log("GAME_SESSION", f"Server session created: {session_id}", "OK")
    return 200, response
