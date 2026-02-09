"""
Server Join Route Handlers
==========================
Handles:
  POST /server-join/auth-grant
  POST /server-join/auth-token
Domain: sessions.hytale.com

These endpoints are used when the client wants to join/create a server.
We emulate them locally so the game can proceed without hitting real services.
"""

import json
import time
import uuid as uuid_lib
import base64


def _get_client_ip(headers, ctx):
    xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return ctx.get("client_ip", "127.0.0.1")


def _get_user_record(identity_payload, ctx):
    user_uuid = identity_payload.get("sub")
    username = identity_payload.get("username")
    for u in ctx["data"].get("users", {}).get("users", []):
        if u.get("uuid") == user_uuid or (username and u.get("username") == username):
            return u
    # Fallback minimal record
    return {
        "uuid": user_uuid,
        "username": username or "unknown"
    }


def _generate_grant():
    # Opaque, URL-safe-ish grant string
    raw = base64.urlsafe_b64encode(uuid_lib.uuid4().bytes + uuid_lib.uuid4().bytes).decode().rstrip("=")
    return raw


def handle_auth_grant(request_body, headers, ctx):
    """
    POST /server-join/auth-grant
    Request: {"identityToken": "<jwt>", "aud": "hytale-client"}
    Response: {"authorizationGrant": "<opaque>"}
    """
    log = ctx["log"]

    try:
        body = json.loads(request_body) if request_body else {}
    except (json.JSONDecodeError, TypeError):
        log("SERVER-JOIN", "Invalid JSON body for auth-grant", "ERROR")
        return 400, {"error": "Invalid JSON body"}

    identity_token = body.get("identityToken")
    requested_aud = body.get("aud")
    if not identity_token:
        log("SERVER-JOIN", "Missing identityToken in auth-grant request", "ERROR")
        return 400, {"error": "Missing identityToken"}

    identity_payload = ctx["verify_jwt"](identity_token)
    if not identity_payload:
        log("SERVER-JOIN", "Identity token verification failed", "ERROR")
        return 401, {"error": "Invalid identity token"}

    user_record = _get_user_record(identity_payload, ctx)
    grant = _generate_grant()

    grants = ctx["data"].setdefault("auth_grants", {})
    grants[grant] = {
        "sub": user_record.get("uuid"),
        "username": user_record.get("username"),
        "aud": requested_aud,
        "issued_at": int(time.time())
    }

    log("SERVER-JOIN", f"Issued authorizationGrant for {user_record.get('username')}: {grant[:16]}...")

    return 200, {"authorizationGrant": grant}


def handle_auth_token(request_body, headers, ctx):
    """
    POST /server-join/auth-token
    Request: {"authorizationGrant": "...", "x509Fingerprint": "..."}
    Response: {"accessToken": "<jwt>"}
    """
    log = ctx["log"]

    try:
        body = json.loads(request_body) if request_body else {}
    except (json.JSONDecodeError, TypeError):
        log("SERVER-JOIN", "Invalid JSON body for auth-token", "ERROR")
        return 400, {"error": "Invalid JSON body"}

    grant = body.get("authorizationGrant")
    fingerprint = body.get("x509Fingerprint") or body.get("x509_fingerprint")

    grants = ctx["data"].setdefault("auth_grants", {})
    grant_info = grants.get(grant) if grant else None

    # Be permissive if grant isn't found
    if not grant_info:
        log("SERVER-JOIN", "Unknown or missing authorizationGrant; continuing anyway", "WARN")
        # Fallback to first user record
        users = ctx["data"].get("users", {}).get("users", [])
        if users:
            grant_info = {
                "sub": users[0].get("uuid"),
                "username": users[0].get("username")
            }
        else:
            grant_info = {"sub": None, "username": "unknown"}

    now = int(time.time())
    exp = now + 3600
    aud = grant_info.get("aud") or str(uuid_lib.uuid4())
    client_ip = _get_client_ip(headers, ctx)

    payload = {
        "aud": aud,
        "exp": exp,
        "iat": now,
        "ip": client_ip,
        "iss": ctx["config"]["emulation"]["issuer"],
        "sub": grant_info.get("sub"),
        "username": grant_info.get("username")
    }

    if fingerprint:
        payload["cnf"] = {"x5t#S256": fingerprint}

    access_token = ctx["sign_jwt"](payload)
    log("SERVER-JOIN", f"Issued accessToken for {payload.get('username')}: {access_token[:20]}...")

    return 200, {"accessToken": access_token}
