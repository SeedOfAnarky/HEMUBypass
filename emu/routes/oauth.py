#!/usr/bin/env python3
"""
OAuth2 routes for Hytale emulator.

Implements:
- /oauth2/auth (authorization endpoint)
- /oauth2/token (token endpoint)
- /.well-known/openid-configuration (discovery)

FIXED VERSION - Now correctly handles HytaleServer OAuth callback:
- Uses 127.0.0.1 instead of localhost
- Redirects to /authorization-callback endpoint
- Extracts and uses INNER state value (not outer encoded state)
- Includes scope parameter in redirect
"""

import time
import uuid
import base64
import hashlib
import json
from urllib.parse import urlparse, parse_qs, quote, urlencode


def handle_oauth_auth(method, path, body, headers, ctx):
    """
    Handle OAuth2 authorization request.
    
    CRITICAL FIX: Properly handles double-encoded state parameter and
    redirects to the correct HytaleServer callback endpoint.
    """
    parsed = urlparse(path)
    params = parse_qs(parsed.query)
    
    # Extract OAuth parameters
    response_type = params.get("response_type", [""])[0]
    client_id = params.get("client_id", [""])[0]
    redirect_uri = params.get("redirect_uri", [""])[0]
    scope = params.get("scope", [""])[0]
    state = params.get("state", [""])[0]
    code_challenge = params.get("code_challenge", [""])[0]
    code_challenge_method = params.get("code_challenge_method", [""])[0]
    
    ctx["log"]("OAUTH", f"Authorization request: client_id={client_id}, redirect_uri={redirect_uri}")
    ctx["log"]("OAUTH", f"Scopes: {scope}")
    ctx["log"]("OAUTH", f"PKCE challenge: {code_challenge[:30]}... (method={code_challenge_method})")
    
    # Generate authorization code
    auth_code = str(uuid.uuid4())
    
    # Store PKCE challenge and metadata for token exchange
    if "oauth_codes" not in ctx["data"]:
        ctx["data"]["oauth_codes"] = {}
    
    ctx["data"]["oauth_codes"][auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "created_at": time.time(),
        "used": False
    }
    
    ctx["log"]("OAUTH", f"Generated auth code: {auth_code}", "OK")
    ctx["log"]("OAUTH", "Stored PKCE challenge for later verification")
    
    # CRITICAL: Decode state to extract callback port AND inner state value
    # The state parameter is double-encoded:
    # 1. Outer layer: base64-encoded JSON with {state: "...", port: "..."}
    # 2. Inner state value: the actual state HytaleServer expects back
    callback_port = None
    state_value = None
    try:
        # Pad the base64 string if needed
        state_padded = state
        if len(state) % 4:
            state_padded = state + '=' * (4 - len(state) % 4)
        
        # Decode base64 to get JSON
        state_decoded = base64.b64decode(state_padded).decode('utf-8')
        state_json = json.loads(state_decoded)
        
        # Extract BOTH port and inner state value
        callback_port = state_json.get('port')
        state_value = state_json.get('state')  # This is what HytaleServer validates!
        
        ctx["log"]("OAUTH", f"Decoded state: port={callback_port}, inner_state={state_value[:20]}...", "OK")
        
    except Exception as e:
        ctx["log"]("OAUTH", f"Failed to decode state parameter: {e}", "WARN")
        ctx["log"]("OAUTH", f"State value (first 50 chars): {state[:50]}...", "DEBUG")
        state_value = state  # Fallback to outer state
    
    # Build redirect URL - CRITICAL CHANGES HERE!
    if callback_port and state_value:
        # IMPORTANT: HytaleServer expects:
        # 1. URL: http://127.0.0.1:{port}/authorization-callback (NOT localhost, must have /authorization-callback)
        # 2. Parameters: code, scope, and INNER state value (not outer encoded state)
        
        actual_redirect_uri = f"http://127.0.0.1:{callback_port}/authorization-callback"
        
        # Build query parameters - must include scope AND use inner state value
        redirect_params = {
            'code': auth_code,
            'scope': scope,
            'state': state_value  # Use INNER state value, not the original state parameter!
        }
        
        # Properly encode the URL with urlencode
        redirect_url = f"{actual_redirect_uri}?{urlencode(redirect_params)}"
        
        ctx["log"]("OAUTH", f"Redirecting to HytaleServer callback: 127.0.0.1:{callback_port}/authorization-callback", "OK")
        ctx["log"]("OAUTH", f"Parameters: code={auth_code}, scope={scope}, state={state_value[:20]}...", "DEBUG")
    else:
        # Fallback to the original redirect_uri (shouldn't happen in normal operation)
        redirect_url = f"{redirect_uri}?code={auth_code}&state={state}"
        ctx["log"]("OAUTH", f"Using fallback redirect: {redirect_uri}", "WARN")
    
    # Return 302 redirect
    return 302, None, {"Location": redirect_url}


def handle_oauth_token(method, path, body, headers, ctx):
    """
    Handle OAuth2 token exchange.
    
    Validates PKCE and exchanges authorization code for access/refresh tokens.
    """
    if not body:
        ctx["log"]("OAUTH", "Token request with no body", "ERROR")
        return 400, {"error": "invalid_request", "error_description": "Missing request body"}
    
    # Parse form data
    try:
        params = {}
        for pair in body.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params[key] = value
    except Exception as e:
        ctx["log"]("OAUTH", f"Failed to parse token request body: {e}", "ERROR")
        return 400, {"error": "invalid_request", "error_description": "Malformed request body"}
    
    grant_type = params.get("grant_type", "")
    code = params.get("code", "")
    redirect_uri = params.get("redirect_uri", "")
    client_id = params.get("client_id", "")
    code_verifier = params.get("code_verifier", "")
    refresh_token = params.get("refresh_token", "")
    
    ctx["log"]("OAUTH", f"Token request: grant_type={grant_type}, client_id={client_id}")
    ctx["log"]("OAUTH", f"Authorization code: {code}")
    ctx["log"]("OAUTH", f"Code verifier: {code_verifier[:30]}..." if code_verifier else "No code verifier")
    
    # Support both authorization_code and refresh_token.
    if grant_type not in ("authorization_code", "refresh_token"):
        ctx["log"]("OAUTH", f"Unsupported grant type: {grant_type}", "ERROR")
        return 400, {"error": "unsupported_grant_type"}

    if grant_type == "refresh_token":
        if not refresh_token:
            return 400, {"error": "invalid_request", "error_description": "Missing refresh_token"}

        refresh_payload = ctx["verify_jwt"](refresh_token)
        if not refresh_payload:
            return 400, {"error": "invalid_grant", "error_description": "Invalid refresh token"}

        if refresh_payload.get("token_type") != "refresh":
            ctx["log"]("OAUTH", "Refresh token missing token_type=refresh", "WARN")

        user_uuid = refresh_payload.get("sub")
        if not user_uuid:
            return 400, {"error": "invalid_grant", "error_description": "Refresh token missing sub"}

        # Look up username for convenience claims.
        username = "Player"
        for u in ctx["data"].get("users", {}).get("users", []):
            if u.get("uuid") == user_uuid:
                username = u.get("username", username)
                break

        scope_out = refresh_payload.get("scope") or "openid offline auth:server"

        now = int(time.time())
        access_payload = {
            "sub": user_uuid,
            "iss": ctx["config"].get("oauth_issuer", "https://oauth.accounts.hytale.com"),
            "aud": client_id or "hytale-server",
            "exp": now + 3600,
            "iat": now,
            "scope": scope_out,
            "username": username,
        }
        access_token = ctx["sign_jwt"](access_payload)

        id_payload = {
            "sub": user_uuid,
            "iss": ctx["config"].get("oauth_issuer", "https://oauth.accounts.hytale.com"),
            "aud": client_id or "hytale-server",
            "exp": now + 3600,
            "iat": now,
            "preferred_username": username,
        }
        id_token = ctx["sign_jwt"](id_payload)

        return 200, {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "id_token": id_token,
            "scope": scope_out,
        }
    
    # Retrieve stored authorization code data
    oauth_codes = ctx["data"].get("oauth_codes", {})
    code_data = oauth_codes.get(code)
    
    if not code_data:
        ctx["log"]("OAUTH", f"Invalid or expired authorization code", "ERROR")
        return 400, {"error": "invalid_grant", "error_description": "Authorization code not found"}
    
    if code_data.get("used"):
        ctx["log"]("OAUTH", "Authorization code already used", "ERROR")
        return 400, {"error": "invalid_grant", "error_description": "Code already used"}
    
    # Check expiration (codes valid for 10 minutes)
    if time.time() - code_data["created_at"] > 600:
        ctx["log"]("OAUTH", "Authorization code expired", "ERROR")
        return 400, {"error": "invalid_grant", "error_description": "Code expired"}
    
    # Validate PKCE
    stored_challenge = code_data.get("code_challenge", "")
    challenge_method = code_data.get("code_challenge_method", "S256")
    
    if stored_challenge and code_verifier:
        # Compute challenge from verifier
        if challenge_method == "S256":
            verifier_hash = hashlib.sha256(code_verifier.encode()).digest()
            computed_challenge = base64.urlsafe_b64encode(verifier_hash).rstrip(b'=').decode()
        elif challenge_method == "plain":
            computed_challenge = code_verifier
        else:
            ctx["log"]("OAUTH", f"Unsupported challenge method: {challenge_method}", "ERROR")
            return 400, {"error": "invalid_request", "error_description": "Unsupported PKCE method"}
        
        if computed_challenge != stored_challenge:
            ctx["log"]("OAUTH", "PKCE verification failed", "ERROR")
            ctx["log"]("OAUTH", f"Expected: {stored_challenge}", "DEBUG")
            ctx["log"]("OAUTH", f"Got:      {computed_challenge}", "DEBUG")
            return 400, {"error": "invalid_grant", "error_description": "PKCE verification failed"}
        
        ctx["log"]("OAUTH", "PKCE verification successful", "OK")
    else:
        ctx["log"]("OAUTH", "No PKCE challenge to verify", "WARN")
    
    # Mark code as used
    code_data["used"] = True
    
    # Get user info (use first user from users.json)
    users = ctx["data"].get("users", {}).get("users", [])
    if not users:
        ctx["log"]("OAUTH", "No users configured in users.json", "ERROR")
        return 500, {"error": "server_error", "error_description": "No users configured"}
    
    user = users[0]
    user_uuid = user.get("uuid", "00000000-0000-0000-0000-000000000000")
    username = user.get("username", "Player")
    
    ctx["log"]("OAUTH", f"Issuing tokens for user: {username} ({user_uuid})")
    
    # Generate tokens
    now = int(time.time())
    
    # Access token (1 hour)
    access_payload = {
        "sub": user_uuid,
        "iss": ctx["config"].get("oauth_issuer", "https://oauth.accounts.hytale.com"),
        "aud": client_id,
        "exp": now + 3600,
        "iat": now,
        "scope": code_data.get("scope", "openid offline auth:server"),
        "username": username
    }
    access_token = ctx["sign_jwt"](access_payload)
    
    # Refresh token (30 days)
    refresh_payload = {
        "sub": user_uuid,
        "iss": ctx["config"].get("oauth_issuer", "https://oauth.accounts.hytale.com"),
        "aud": client_id,
        "exp": now + 2592000,
        "iat": now,
        "scope": code_data.get("scope", "openid offline"),
        "token_type": "refresh"
    }
    refresh_token = ctx["sign_jwt"](refresh_payload)
    
    # ID token (contains user identity claims)
    id_payload = {
        "sub": user_uuid,
        "iss": ctx["config"].get("oauth_issuer", "https://oauth.accounts.hytale.com"),
        "aud": client_id,
        "exp": now + 3600,
        "iat": now,
        "preferred_username": username
    }
    id_token = ctx["sign_jwt"](id_payload)
    
    ctx["log"]("OAUTH", "Successfully issued access, refresh, and ID tokens", "OK")
    
    # Return token response
    response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "scope": code_data.get("scope", "openid offline auth:server")
    }
    
    return 200, response


def handle_openid_configuration(method, path, body, headers, ctx):
    """
    Return OpenID Connect discovery document.
    """
    issuer = ctx["config"].get("oauth_issuer", "https://oauth.accounts.hytale.com")
    
    config = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth2/auth",
        "token_endpoint": f"{issuer}/oauth2/token",
        "jwks_uri": f"https://sessions.hytale.com/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "offline", "auth:server"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256", "plain"]
    }
    
    ctx["log"]("OAUTH", "Served OpenID configuration")
    return 200, config
