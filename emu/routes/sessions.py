"""
Sessions Route Handler
======================
Handles: POST /game-session/child
Domain:  sessions.SeedOfAnark.fr

This is the second call the launcher makes.
It sends the identity token in Authorization header and gets a session token back.
The session token is then passed to HytaleClient.exe.
"""

import json
import time
import uuid as uuid_lib


def handle_game_session_child(request_body, headers, ctx):
    """
    POST /game-session/child
    
    Request Headers: Authorization: Bearer <identity_token>
    Request Body:    {"scope": "hytale:client"}
    Response:        {"sessionToken": "<jwt>"}
    """
    log = ctx["log"]

    # ---- MODE 1: Passthrough ----
    if ctx["mode"] == 1:
        log("SESSION", "Mode 1 - Forwarding to real server", "INFO")
        return ctx["forward_request"]("POST", "/game-session/child", request_body, headers)

    # ---- MODE 2: Emulation ----
    log("SESSION", "Mode 2 - Emulating session creation locally")

    # Extract and verify identity token
    auth_header = headers.get("Authorization", headers.get("authorization", ""))
    if not auth_header.startswith("Bearer "):
        log("SESSION", "Missing or invalid Authorization header", "ERROR")
        return 401, {"error": "Missing Bearer token"}

    identity_token = auth_header[7:]  # strip "Bearer "
    log("SESSION", f"Identity token (first 50 chars): {identity_token[:50]}...")

    # Verify the identity token
    identity_payload = ctx["verify_jwt"](identity_token)
    if identity_payload is None:
        log("SESSION", "Identity token verification FAILED", "ERROR")
        return 401, {"error": "Invalid identity token"}

    log("SESSION", f"Identity token verified: sub={identity_payload.get('sub')}")

    # Parse request body for scope(s)
    try:
        body = json.loads(request_body) if request_body else {}
    except (json.JSONDecodeError, TypeError):
        body = {}

    scopes_list = body.get("scopes") if isinstance(body.get("scopes"), list) else []
    scope = body.get("scope")
    requested_scopes = scopes_list[:] if scopes_list else ([scope] if scope else [])
    log("SESSION", f"Requested scopes: {requested_scopes if requested_scopes else ['(none)']}")

    # Build profile payload (real server includes profile in identityToken)
    config = ctx["config"]
    user_uuid = identity_payload.get("sub", "unknown")
    username = identity_payload.get("username")
    profile = identity_payload.get("profile")
    if not profile:
        # Reconstruct profile from users.json if missing
        user_record = None
        for u in ctx["data"].get("users", {}).get("users", []):
            if u.get("uuid") == user_uuid or (username and u.get("username") == username):
                user_record = u
                break
        if user_record:
            skin = user_record.get("skin", {})
            skin_string = json.dumps(skin, separators=(',', ':')) if isinstance(skin, dict) else str(skin)
            profile = {
                "username": user_record.get("username", username or "unknown"),
                "entitlements": user_record.get("entitlements", ["game.base"]),
                "skin": skin_string
            }
        else:
            profile = {
                "username": username or "unknown",
                "entitlements": ["game.base"],
                "skin": "{}"
            }

    # Generate tokens matching sessions.hytale.com format
    now = int(time.time())
    now_ns = time.time_ns()
    expiry_seconds = 3600  # real server uses ~1 hour for session tokens
    exp = now + expiry_seconds
    jti = str(uuid_lib.uuid4())

    base_payload = {
        "exp": exp,
        "iat": now,
        "iss": config["emulation"]["issuer"],
        "jti": jti,
        "scope": "hytale:server",
        "sub": user_uuid
    }

    identity_payload_new = dict(base_payload)
    identity_payload_new["profile"] = profile

    session_payload = dict(base_payload)

    identity_token_new = ctx["sign_jwt"](identity_payload_new)
    session_token = ctx["sign_jwt"](session_payload)

    log("SESSION", f"Generated session token (first 50 chars): {session_token[:50]}...")
    log("SESSION", f"Generated identity token (first 50 chars): {identity_token_new[:50]}...")
    log("SESSION", f"Session token payload: {json.dumps(session_payload, indent=2)}")

    # Update session state
    for sid, sess in ctx["sessions"].items():
        if sess.get("user_uuid") == user_uuid and sess.get("state") == "authenticated":
            sess["session_token"] = session_token
            sess["state"] = "session_active"
            sess["scope"] = "hytale:server"
            log("SESSION", f"Updated session {sid} -> session_active")
            break
    
    ctx["save_sessions"]()

    # Expiry timestamp (RFC3339 with nanoseconds + Z)
    import datetime
    expires_ns = now_ns + (expiry_seconds * 1_000_000_000)
    dt = datetime.datetime.utcfromtimestamp(expires_ns / 1_000_000_000)
    expires_at = dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{expires_ns % 1_000_000_000:09d}Z"

    # Response matches real server format
    response = {
        "expiresAt": expires_at,
        "identityToken": identity_token_new,
        "sessionToken": session_token
    }

    return 200, response
