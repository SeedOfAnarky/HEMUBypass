"""
Auth Route Handler
==================
Handles: POST /auth/login
Domain:  sessions.SeedOfAnark.fr

Real JWT payload structure (decoded from Fiddler capture):
{
    "sub": "<uuid>",
    "username": "<username>",
    "profile": {
        "username": "<username>",
        "entitlements": ["game.base", "game.deluxe", "game.founder"],
        "skin": "{json-encoded skin string}"
    },
    "iat": <unix_ts>, "iss": "https://sessions.SeedOfAnark.fr", "exp": <unix_ts>,
    "scope": "hytale:server", "ver": "2.0",
    "aud": "<md5 hex hash>", "scopes": ["game.child"]
}
"""

import json
import time
import hashlib
import uuid as uuid_lib


def handle_login(request_body, ctx):
    """
    POST /auth/login
    Request:  {"username": "...", "password": "..."}
    Response: {"data": {"token": "<jwt>", "user": {"uuid": "...", "username": "..."}}}
    """
    log = ctx["log"]
    
    try:
        body = json.loads(request_body)
    except (json.JSONDecodeError, TypeError):
        log("AUTH", "Failed to parse login request body", "ERROR")
        return 400, {"error": "Invalid JSON body"}

    username = body.get("username", "")
    password = body.get("password", "")
    log("AUTH", f"Login attempt: username='{username}'")

    # ---- MODE 1: Passthrough ----
    if ctx["mode"] == 1:
        log("AUTH", "Mode 1 - Forwarding to real server", "INFO")
        return ctx["forward_request"]("POST", "/auth/login", request_body)

    # ---- MODE 2: Emulation ----
    log("AUTH", "Mode 2 - Emulating login locally")
    
    users = ctx["data"]["users"]
    user_record = None
    for u in users.get("users", []):
        if u["username"] == username and u["password"] == password:
            user_record = u
            break

    if not user_record:
        log("AUTH", f"Login FAILED for '{username}' - invalid credentials", "WARN")
        return 401, {"error": "Invalid credentials", "message": "Username or password incorrect"}

    user_uuid = user_record["uuid"]
    display_name = user_record.get("display_name", username)
    entitlements = user_record.get("entitlements", ["game.base"])
    skin = user_record.get("skin", {})

    log("AUTH", f"Login SUCCESS: uuid={user_uuid}, display_name={display_name}", "OK")
    log("AUTH", f"Entitlements: {entitlements}")

    now = int(time.time())
    config = ctx["config"]
    
    # Skin is a JSON-encoded STRING inside profile (real server format)
    skin_json_string = json.dumps(skin, separators=(',', ':'))
    
    # Audience hash (real server uses a hex hash)
    aud_hash = hashlib.md5(f"{user_uuid}:{now}".encode()).hexdigest()

    # Identity token payload - MUST have scope "hytale:client", NO aud, NO scopes
    # (confirmed from real /auth/login Fiddler capture)
    payload = {
        "sub": user_uuid,
        "username": username,
        "profile": {
            "username": username,
            "entitlements": entitlements,
            "skin": skin_json_string
        },
        "iss": config["emulation"]["issuer"],
        "jti": str(uuid_lib.uuid4()),
        "iat": now,
        "exp": now + config["emulation"]["token_expiry_seconds"],
        "scope": "hytale:client",
        "ver": "2.0"
    }

    identity_token = ctx["sign_jwt"](payload)
    
    log("AUTH", f"Generated identity token (first 80 chars): {identity_token[:80]}...")
    log("AUTH", f"Token payload: {json.dumps(payload, indent=2)}")

    # Store session
    session_id = str(uuid_lib.uuid4())
    ctx["sessions"][session_id] = {
        "user_uuid": user_uuid,
        "username": username,
        "identity_token": identity_token,
        "entitlements": entitlements,
        "created": now,
        "state": "authenticated"
    }
    log("AUTH", f"Session created: {session_id}")
    ctx["save_sessions"]()

    return 200, {
        "success": True,
        "message": "Login successful",
        "data": {
            "user": {
                "username": username,
                "entitlements": entitlements,
                "skin": skin_json_string,
                "uuid": user_uuid
            },
            "token": identity_token
        }
    }
