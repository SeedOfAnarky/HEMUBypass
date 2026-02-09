"""
Account Data Route Handler
===========================
Handles: Requests to account-data.SeedOfAnark.fr
Domain:  account-data.SeedOfAnark.fr

Confirmed endpoints from Fiddler captures:
  #12: GET /my-account/game-profile  -> returns uuid, username, entitlements, skin, accessfiles
  #13: GET /my-account/cosmetics     -> returns all available cosmetic items by category
"""

import json
from datetime import datetime, timedelta


def handle_account_data(method, path, request_body, headers, ctx):
    """Route dispatcher for account-data.SeedOfAnark.fr"""
    log = ctx["log"]
    
    log("ACCOUNT-DATA", f">>> {method} {path}")
    
    # Log Authorization header (truncated)
    auth = headers.get("Authorization", headers.get("authorization", ""))
    if auth:
        log("ACCOUNT-DATA", f"Authorization: {auth[:60]}...")

    # ---- MODE 1: Passthrough ----
    if ctx["mode"] == 1:
        log("ACCOUNT-DATA", "Mode 1 - Forwarding to real server", "INFO")
        return ctx["forward_request"](method, path, request_body, headers,
                                       target_host="account-data.SeedOfAnark.fr")

    # ---- MODE 2: Emulation ----
    log("ACCOUNT-DATA", "Mode 2 - Emulating response")

    # Authenticate the request
    user_record = _authenticate(auth, ctx)
    
    path_lower = path.lower().rstrip("/")

    # GET /my-account/game-profile (#12)
    if "/my-account/game-profile" in path_lower:
        return _handle_game_profile(user_record, ctx)

    # GET /my-account/get-profiles (HytaleServer)
    if "/my-account/get-profiles" in path_lower:
        return _handle_get_profiles(user_record, ctx)

    # GET /my-account/cosmetics (#13)
    if "/my-account/cosmetics" in path_lower:
        return _handle_cosmetics(ctx)

    # Unknown endpoint - log it and return 200
    log("ACCOUNT-DATA", f"*** UNKNOWN ENDPOINT: {method} {path} ***", "WARN")
    log("ACCOUNT-DATA", f"*** Need Fiddler capture for this! ***", "WARN")
    if request_body:
        log("ACCOUNT-DATA", f"Body: {request_body[:500]}", "WARN")
    return 200, {"status": "ok", "message": "endpoint not yet mapped - check emu logs"}


def _authenticate(auth_header, ctx):
    """Extract user from Bearer token. Returns user_record or None."""
    log = ctx["log"]
    
    if not auth_header or not auth_header.startswith("Bearer "):
        log("ACCOUNT-DATA", "No Bearer token in request", "WARN")
        return None

    token = auth_header[7:]
    payload = ctx["verify_jwt"](token)
    if not payload:
        log("ACCOUNT-DATA", "Token verification failed", "WARN")
        return None

    user_uuid = payload.get("sub")
    username = payload.get("username")
    log("ACCOUNT-DATA", f"Authenticated: uuid={user_uuid} username={username}", "OK")

    # Find matching user record
    for u in ctx["data"]["users"].get("users", []):
        if u["uuid"] == user_uuid or u["username"] == username:
            return u

    # No match in users.json - build a minimal record from token
    log("ACCOUNT-DATA", "User not in users.json, building from token", "WARN")
    return {
        "uuid": user_uuid,
        "username": username,
        "entitlements": payload.get("profile", {}).get("entitlements", ["game.base"]),
        "skin": json.loads(payload.get("profile", {}).get("skin", "{}"))
    }


def _handle_game_profile(user_record, ctx):
    """
    GET /my-account/game-profile
    
    Real response format (from Fiddler #12):
    {
        "uuid": "20939e50-...",
        "username": "nvite",
        "entitlements": ["game.base", "game.deluxe", "game.founder"],
        "skin": "{json-encoded skin string}",
        "accessfiles": false
    }
    """
    log = ctx["log"]
    log("ACCOUNT-DATA", "=== GAME PROFILE ===")

    if not user_record:
        log("ACCOUNT-DATA", "No authenticated user for game-profile", "ERROR")
        return 401, {"error": "Unauthorized"}

    skin = user_record.get("skin", {})
    # Skin must be a JSON-encoded STRING in the response (matching real server)
    if isinstance(skin, dict):
        skin_string = json.dumps(skin, separators=(',', ':'))
    else:
        skin_string = str(skin)

    response = {
        "uuid": user_record.get("uuid", ""),
        "username": user_record.get("username", ""),
        "entitlements": user_record.get("entitlements", ["game.base"]),
        "skin": skin_string,
        "accessfiles": False
    }

    log("ACCOUNT-DATA", f"Returning game-profile for {response['username']}")
    log("ACCOUNT-DATA", f"Entitlements: {response['entitlements']}")
    log("ACCOUNT-DATA", f"Response: {json.dumps(response, indent=2)}")

    return 200, response


def _handle_cosmetics(ctx):
    """
    GET /my-account/cosmetics
    
    Returns ALL available cosmetic items grouped by category.
    Real response is ~14KB of cosmetic item names.
    Data loaded from data/cosmetics.json.
    """
    log = ctx["log"]
    log("ACCOUNT-DATA", "=== COSMETICS CATALOG ===")

    cosmetics = ctx["data"].get("cosmetics", {})
    
    # Remove any metadata keys (like "comment")
    response = {k: v for k, v in cosmetics.items() 
                if isinstance(v, list)}

    categories = len(response)
    total_items = sum(len(v) for v in response.values())
    log("ACCOUNT-DATA", f"Returning cosmetics: {categories} categories, {total_items} total items")

    return 200, response


def _handle_get_profiles(user_record, ctx):
    """
    GET /my-account/get-profiles

    Expected by HytaleServer SessionServiceClient. Response mirrors real service:
    {
        "owner": "<uuid>",
        "profiles": [{
            "createdAt": "<iso8601>",
            "entitlements": ["..."],
            "nextNameChangeAt": "<iso8601>",
            "skin": "{json-string}",
            "uuid": "...",
            "username": "..."
        }]
    }
    """
    log = ctx["log"]
    log("ACCOUNT-DATA", "=== GET PROFILES ===")

    if not user_record:
        log("ACCOUNT-DATA", "No authenticated user for get-profiles", "ERROR")
        return 401, {"error": "Unauthorized"}

    now_iso = datetime.utcnow().isoformat() + "Z"
    next_name_change = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"

    skin_value = user_record.get("skin", {})
    skin_str = json.dumps(skin_value) if isinstance(skin_value, dict) else str(skin_value)

    # Match the shape returned by the original Server emulator (Flask),
    # which HytaleServer expects.
    profile = {
        "createdAt": user_record.get("created") or now_iso,
        "entitlements": user_record.get("entitlements", ["game.base"]),
        "nextNameChangeAt": next_name_change,
        "skin": skin_str,
        "username": user_record.get("username", "Player"),
        "uuid": user_record.get("uuid", ""),
    }
    response = {"owner": profile["uuid"], "profiles": [profile]}

    log("ACCOUNT-DATA", f"Returning get-profiles for {profile['username']}")
    return 200, response
