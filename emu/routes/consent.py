#!/usr/bin/env python3
"""
OAuth2 consent handler for accounts.hytale.com domain

This handles the redirect endpoint that sends the authorization code
back to the server's local callback listener.
"""

import json
import socket
import urllib.parse


def handle_consent_client(method, path, body, headers, ctx):
    """
    Handle GET /consent/client - OAuth2 consent/callback endpoint
    
    This endpoint receives the authorization code from the OAuth flow
    and needs to redirect it to the server's local callback listener.
    
    Query parameters:
    - code: Authorization code
    - state: Base64 encoded JSON with {state, port}
    """
    log = ctx["log"]
    
    # Parse query parameters
    parsed = urllib.parse.urlparse(path)
    params = urllib.parse.parse_qs(parsed.query)
    
    code = params.get('code', [''])[0]
    state = params.get('state', [''])[0]
    
    log("CONSENT", f"Consent callback received: code={code[:20]}...", "INFO")
    log("CONSENT", f"State: {state[:30]}...", "DEBUG")
    
    if not code or not state:
        return 400, {"error": "invalid_request", "error_description": "Missing code or state"}
    
    # Decode the state to get the callback port
    import base64
    try:
        state_decoded = base64.b64decode(state).decode('utf-8')
        state_obj = json.loads(state_decoded)
        callback_port = int(state_obj.get('port', 0))
        original_state = state_obj.get('state', '')
    except Exception as e:
        log("CONSENT", f"Failed to decode state: {e}", "ERROR")
        return 400, {"error": "invalid_request", "error_description": "Invalid state parameter"}
    
    log("CONSENT", f"Decoded callback port: {callback_port}", "INFO")
    
    # Build the callback URL for the server's local listener
    callback_url = f"http://localhost:{callback_port}/callback"
    callback_params = urllib.parse.urlencode({
        'code': code,
        'state': state
    })
    full_callback_url = f"{callback_url}?{callback_params}"
    
    log("CONSENT", f"Forwarding to server callback: {full_callback_url[:80]}...", "INFO")
    
    # Send the callback to the server's local listener
    import http.client
    try:
        conn = http.client.HTTPConnection('localhost', callback_port, timeout=5)
        conn.request('GET', f'/callback?{callback_params}')
        response = conn.getresponse()
        response_body = response.read().decode('utf-8')
        
        log("CONSENT", f"Server callback responded: {response.status}", "OK" if response.status == 200 else "WARN")
        
        # Return a success page
        return 200, {
            "success": True,
            "message": "Authentication successful! You can close this window.",
            "server_response": response.status
        }
    
    except socket.timeout:
        log("CONSENT", f"Timeout connecting to server callback on port {callback_port}", "ERROR")
        return 500, {
            "error": "server_timeout",
            "error_description": "Server callback listener did not respond in time"
        }
    
    except ConnectionRefusedError:
        log("CONSENT", f"Connection refused to server callback on port {callback_port}", "ERROR")
        log("CONSENT", "The server's OAuth callback listener may not be ready yet", "WARN")
        return 500, {
            "error": "server_unavailable",
            "error_description": "Server callback listener is not available. Please wait a moment and try again."
        }
    
    except Exception as e:
        log("CONSENT", f"Failed to forward callback: {e}", "ERROR")
        return 500, {
            "error": "callback_failed",
            "error_description": f"Failed to send callback to server: {str(e)}"
        }
