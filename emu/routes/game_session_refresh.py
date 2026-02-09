"""
Server-side game session refresh endpoint
Called by HytaleServer.exe to refresh an existing server session
"""

import json
import time


def handle_game_session_refresh(body, headers, ctx):
    """
    POST /game-session/refresh

    Expected input:
    - Authorization: Bearer <sessionToken>

    Returns:
    - sessionToken, identityToken, expiresAt (RFC3339 "Z")
    """
    log = ctx["log"]
    data = ctx["data"]
    config = ctx["config"]

    auth_header = headers.get("Authorization", headers.get("authorization", ""))
    if not auth_header.startswith("Bearer "):
        return 401, {"error": "unauthorized"}

    old_session_token = auth_header[7:]
    payload = ctx["verify_jwt"](old_session_token)
    if not payload:
        return 401, {"error": "invalid_token"}

    user_uuid = payload.get("sub")
    session_id = payload.get("jti")
    if not user_uuid or not session_id:
        return 400, {"error": "invalid_request"}

    # Find user record for profile claims (optional but helpful).
    username = payload.get("username") or "Player"
    entitlements = ["game.base"]
    skin_string = "{}"
    for u in data.get("users", {}).get("users", []):
        if u.get("uuid") == user_uuid or u.get("username") == username:
            username = u.get("username", username)
            entitlements = u.get("entitlements", entitlements)
            skin = u.get("skin", {})
            skin_string = json.dumps(skin, separators=(",", ":")) if isinstance(skin, dict) else str(skin)
            break

    issuer = (
        config.get("emulation", {}).get("issuer")
        or config.get("issuer")
        or "https://sessions.hytale.com"
    )

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

    # Update stored session record if present.
    if session_id in ctx["sessions"]:
        ctx["sessions"][session_id]["expires_at"] = exp
    else:
        ctx["sessions"][session_id] = {
            "username": username,
            "user_uuid": user_uuid,
            "created_at": now,
            "expires_at": exp,
            "type": "server_session",
        }
    ctx["save_sessions"]()

    import datetime as _dt
    expires_at = _dt.datetime.utcfromtimestamp(exp).strftime("%Y-%m-%dT%H:%M:%SZ")

    log("GAME_SESSION", f"Refreshed server session: {session_id}", "OK")
    return 200, {"expiresAt": expires_at, "identityToken": identity_token, "sessionToken": session_token}

