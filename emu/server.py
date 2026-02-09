#!/usr/bin/env python3
"""
==========================================================
  SeedOfAnarky Emulator Server
  HTTPS server with dual-mode operation
  
  Mode 1: Passthrough - Forward requests to real server
  Mode 2: Emulation  - Handle everything locally
==========================================================

Handles all domains via SNI / Host header routing:
  sessions.SeedOfAnarky.fr    -> auth, session, jwks
  account-data.SeedOfAnarky.fr -> entitlements, cosmetics, account
  telemetry.SeedOfAnarky.fr   -> telemetry sink
  cdn.SeedOfAnarky.fr         -> CDN requests (stubbed)
  api.SeedOfAnarky.fr         -> API requests (stubbed)

Usage:
  python server.py                    # Uses mode from config.json
  python server.py --mode 1           # Force passthrough mode
  python server.py --mode 2           # Force emulation mode
  python server.py --generate-certs   # Generate certs and exit
"""

import os
import sys
import ssl
import json
import time
import base64
import socket
import argparse
import threading
import traceback
import datetime
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ============================================================
# Paths
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
LOGS_DIR = os.path.join(SCRIPT_DIR, "logs")

# ============================================================
# Globals (set in main)
# ============================================================

CONFIG = {}
MODE = 2
ED25519_PRIVATE_KEY = None
ED25519_PUBLIC_KEY = None
SESSIONS = {}
DATA_STORE = {}
LOG_FILE = None
LOG_LOCK = threading.Lock()
REQUEST_COUNTER = 0
REQUEST_COUNTER_LOCK = threading.Lock()

# OAuth-specific storage (for authorization codes)
# Will be merged into DATA_STORE at runtime

# ============================================================
# Logging
# ============================================================

def log(source, message, level="INFO"):
    """Thread-safe logging to both console and file."""
    global LOG_FILE
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    line = f"[{timestamp}] [{source}] [{level}] {message}"
    
    # Color map for console
    colors = {
        "INFO": "\033[37m",    # White
        "OK": "\033[32m",      # Green
        "WARN": "\033[33m",    # Yellow
        "ERROR": "\033[31m",   # Red
        "DEBUG": "\033[36m",   # Cyan
        "REQUEST": "\033[35m", # Magenta
    }
    reset = "\033[0m"
    color = colors.get(level, "\033[37m")
    
    with LOG_LOCK:
        print(f"{color}{line}{reset}")
        if LOG_FILE:
            try:
                LOG_FILE.write(line + "\n")
                LOG_FILE.flush()
            except Exception:
                pass

def log_section(source, title):
    """Log a section header."""
    border = "=" * 70
    log(source, border, "DEBUG")
    log(source, title, "DEBUG")
    log(source, border, "DEBUG")

# ============================================================
# JWT Utilities
# ============================================================

def _b64url_encode(data):
    """Base64url encode bytes."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def _b64url_decode(s):
    """Base64url decode string to bytes."""
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def sign_jwt(payload):
    """Sign a JWT using our Ed25519 private key."""
    header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": CONFIG["certs"]["kid"]
    }
    
    header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(',', ':')))
    
    signing_input = f"{header_b64}.{payload_b64}".encode()
    
    signature = ED25519_PRIVATE_KEY.sign(signing_input)
    signature_b64 = _b64url_encode(signature)
    
    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    return token

def verify_jwt(token):
    """Verify a JWT using our Ed25519 public key. Returns payload dict or None."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            log("JWT", f"Invalid token format (expected 3 parts, got {len(parts)})", "ERROR")
            return None
        
        header_b64, payload_b64, signature_b64 = parts
        
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = _b64url_decode(signature_b64)
        
        ED25519_PUBLIC_KEY.verify(signature, signing_input)
        
        payload = json.loads(_b64url_decode(payload_b64))
        
        # Check expiry
        if "exp" in payload and payload["exp"] < time.time():
            log("JWT", f"Token expired (exp={payload['exp']})", "WARN")
            # Still return it - let the caller decide
        
        return payload
    except Exception as e:
        log("JWT", f"Token verification failed: {e}", "ERROR")
        return None

# ============================================================
# Session management
# ============================================================

def save_sessions():
    """Save active sessions to file."""
    try:
        path = os.path.join(DATA_DIR, "sessions.json")
        with open(path, "w") as f:
            json.dump({"active_sessions": SESSIONS}, f, indent=2, default=str)
    except Exception as e:
        log("SESSION", f"Failed to save sessions: {e}", "ERROR")

# ============================================================
# Passthrough (Mode 1) - Forward to real server
# ============================================================

def forward_request(method, path, body=None, headers=None, target_host=None):
    """Forward a request to the real server and return (status_code, response_json)."""
    import http.client
    
    host = target_host or CONFIG["passthrough"].get("real_ip", "83.113.67.135")
    real_domain = target_host or "sessions.SeedOfAnarky.fr"
    
    log("FORWARD", f"Forwarding {method} {path} -> {host}:443")
    
    try:
        # Connect with SNI
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        conn = http.client.HTTPSConnection(host, 443, context=context)
        
        req_headers = {}
        if headers:
            req_headers = dict(headers)
        req_headers["Host"] = real_domain
        
        conn.request(method, path, body=body, headers=req_headers)
        resp = conn.getresponse()
        
        status = resp.status
        raw_body = resp.read().decode("utf-8", errors="replace")
        
        log("FORWARD", f"Real server responded: {status}")
        log("FORWARD", f"Response body: {raw_body[:500]}")
        
        try:
            return status, json.loads(raw_body)
        except (json.JSONDecodeError, TypeError):
            return status, {"raw": raw_body}
    
    except Exception as e:
        log("FORWARD", f"Forward FAILED: {e}", "ERROR")
        return 502, {"error": f"Failed to forward: {str(e)}"}

# ============================================================
# Request Handler
# ============================================================

class SeedOfAnarkyRequestHandler(BaseHTTPRequestHandler):
    """Handle all incoming HTTPS requests."""
    # Match real server protocol/headers more closely.
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.22.1"
    sys_version = ""

    def version_string(self):
        return "nginx/1.22.1"
    
    # Suppress default logging
    def log_message(self, format, *args):
        pass

    def _get_request_id(self):
        global REQUEST_COUNTER
        with REQUEST_COUNTER_LOCK:
            REQUEST_COUNTER += 1
            return f"{REQUEST_COUNTER:06d}"

    def _read_body(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            return self.rfile.read(content_length).decode("utf-8", errors="replace")
        return None

    def _get_host(self):
        """Get the target hostname from the Host header."""
        host = self.headers.get("Host", "")
        # Strip port if present
        if ":" in host:
            host = host.split(":")[0]
        return host.lower()

    def _build_context(self):
        """Build the context dict passed to all route handlers."""
        return {
            "mode": MODE,
            "config": CONFIG,
            "log": log,
            "sessions": SESSIONS,
            "save_sessions": save_sessions,
            "sign_jwt": sign_jwt,
            "verify_jwt": verify_jwt,
            "forward_request": forward_request,
            "data": DATA_STORE,
            "ed25519_public_key": ED25519_PUBLIC_KEY,
            "ed25519_private_key": ED25519_PRIVATE_KEY,
            "client_ip": self.client_address[0],
        }

    def _send_json_response(self, status_code, body_dict, extra_headers=None):
        """Send a JSON response with standard headers matching the real server."""
        # Handle HTTP 302 redirects (for OAuth flow)
        if status_code == 302 and extra_headers and 'Location' in extra_headers:
            redirect_url = extra_headers['Location']
            log("HTTP", f"Redirecting to: {redirect_url}", "DEBUG")
            self.send_response(302)
            self.send_header("Location", redirect_url)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        
        # Match real server formatting (pretty JSON + trailing newline).
        if body_dict is None:
            body_bytes = b""
        else:
            body_json = json.dumps(body_dict, indent=4) + "\n"
            body_bytes = body_json.encode("utf-8")
        
        self.send_response(status_code)
        
        # Mimic real server headers
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Powered-By", "PHP/8.5.1")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Hytale-Client-Version")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "Thu, 19 Nov 1981 08:52:00 GMT")
        
        # Generate a PHP-like session cookie
        import hashlib
        cookie_val = hashlib.md5(os.urandom(16)).hexdigest()
        self.send_header("Set-Cookie", f"PHPSESSID={cookie_val}; path=/")
        
        self.end_headers()
        self.wfile.write(body_bytes)

    def _handle_request(self, method):
        """Central request dispatcher."""
        request_id = self._get_request_id()
        host = self._get_host()
        path = self.path
        body = self._read_body() if method in ("POST", "PUT", "PATCH") else None
        headers = dict(self.headers)
        
        start_time = time.time()
        
        # ---- Log request ----
        log_section("SERVER", f"REQUEST [{request_id}] {method} https://{host}{path}")
        log("SERVER", f"Request ID: {request_id}", "REQUEST")
        log("SERVER", f"Host: {host}", "REQUEST")
        log("SERVER", f"Method: {method}", "REQUEST")
        log("SERVER", f"Path: {path}", "REQUEST")
        log("SERVER", f"User-Agent: {headers.get('User-Agent', 'unknown')}", "REQUEST")
        log("SERVER", f"Mode: {'PASSTHROUGH' if MODE == 1 else 'EMULATION'}", "REQUEST")
        
        if body:
            log("SERVER", f"Request Body: {body[:1000]}", "REQUEST")
        
        # Log all headers
        for k, v in headers.items():
            # Truncate long values (like auth tokens)
            display_v = v if len(v) < 100 else v[:100] + "..."
            log("SERVER", f"  Header: {k}: {display_v}", "DEBUG")

        ctx = self._build_context()
        
        # ---- Route to handler ----
        try:
            result = self._route(method, host, path, body, headers, ctx)
            # Handle tuple response: (status, response) or (status, response, headers)
            if isinstance(result, tuple):
                if len(result) == 3:
                    status, response, extra_headers = result
                else:
                    status, response = result
                    extra_headers = None
            else:
                status, response, extra_headers = 500, {"error": "Invalid handler response"}, None
        except Exception as e:
            log("SERVER", f"Handler EXCEPTION: {e}", "ERROR")
            log("SERVER", traceback.format_exc(), "ERROR")
            status = 500
            response = {"error": "Internal server error", "detail": str(e)}
            extra_headers = None

        # ---- Log response ----
        elapsed_ms = (time.time() - start_time) * 1000
        log("SERVER", f"Response [{request_id}]: {status} ({elapsed_ms:.1f}ms)", 
            "OK" if 200 <= status < 300 else "WARN" if 300 <= status < 500 else "ERROR")
        if response:
            log("SERVER", f"Response Body: {json.dumps(response)[:500]}", "DEBUG")

        # ---- Send response ----
        self._send_json_response(status, response, extra_headers)

    def _route(self, method, host, path, body, headers, ctx):
        """Route request to the appropriate handler based on host and path."""
        
        path_lower = path.lower().rstrip("/")
        
        # Parse query params for GET requests
        from urllib.parse import parse_qs, urlparse
        query_params = {}
        if '?' in path:
            parsed = urlparse(path)
            query_params = parse_qs(parsed.query)
            path_lower = parsed.path.lower().rstrip("/")
        
        # ---- OPTIONS (CORS preflight) ----
        if method == "OPTIONS":
            log("SERVER", "CORS preflight request - responding OK")
            return 200, {"status": "ok"}

        # ============================================================
        # OAuth and Account Domains (for HytaleServer.exe)
        # ============================================================
        
        # ---- oauth.accounts.hytale.com / oauth.accounts.SeedOfAnarky.fr ----
        if "oauth.accounts" in host or host in ("oauth.hytale.com", "oauth.SeedOfAnarky.fr"):
            
            # OAuth2 authorization endpoint
            if "/oauth2/auth" in path_lower and method == "GET":
                from routes.oauth import handle_oauth_auth
                return handle_oauth_auth(method, path, body, headers, ctx)
            
            # OAuth2 token exchange endpoint
            if "/oauth2/token" in path_lower and method == "POST":
                from routes.oauth import handle_oauth_token
                return handle_oauth_token(method, path, body, headers, ctx)
            
            # JWKS for OAuth (might use different key)
            if ".well-known/jwks" in path_lower:
                from routes.jwks import handle_jwks
                return handle_jwks(ctx)
            
            log("SERVER", f"Unknown OAuth endpoint: {method} {path}", "WARN")
            return 200, {"status": "ok", "message": "oauth endpoint not yet mapped"}
        
        # ---- accounts.hytale.com / backend.accounts.hytale.com ----
        if "accounts" in host and "oauth" not in host:
            
            # OAuth consent/callback endpoint
            if "/consent/client" in path_lower and method == "GET":
                from routes.consent import handle_consent_client
                return handle_consent_client(method, path, body, headers, ctx)
            
            # Account profiles endpoint
            if "/my-account/get-profiles" in path_lower and method == "GET":
                from routes.account_profiles import handle_get_profiles
                return handle_get_profiles(ctx)
            
            # JWKS
            if ".well-known/jwks" in path_lower:
                from routes.jwks import handle_jwks
                return handle_jwks(ctx)
            
            log("SERVER", f"Unknown accounts endpoint: {method} {path}", "WARN")
            return 200, {"status": "ok", "message": "accounts endpoint not yet mapped"}

        # ============================================================
        # Sessions Domain (serves both HytaleClient.exe and HytaleServer.exe)
        # ============================================================
        
        # ---- sessions.SeedOfAnarky.fr / sessions.hytale.com ----
        if "sessions" in host or host in ("SeedOfAnarky.fr", "www.SeedOfAnarky.fr", "hytale.com", "127.0.0.1", "localhost"):
            log("SERVER", f"Matched SESSIONS domain (host={host})", "DEBUG")
            
            # JWKS
            if ".well-known/jwks" in path_lower:
                from routes.jwks import handle_jwks
                return handle_jwks(ctx)
            
            # Login (client-side)
            if "/auth/login" in path_lower and method == "POST":
                log("SERVER", f"Matched /auth/login route", "DEBUG")
                from routes.auth import handle_login
                return handle_login(body, ctx)
            
            # Game session - CLIENT child session
            if "/game-session/child" in path_lower and method == "POST":
                from routes.sessions import handle_game_session_child
                return handle_game_session_child(body, headers, ctx)
            
            # Game session - SERVER session creation
            if "/game-session/new" in path_lower and method == "POST":
                from routes.game_session_new import handle_game_session_new
                # Parse body
                import json
                body_dict = json.loads(body) if body else {}
                return handle_game_session_new(body_dict, headers, ctx)

            # Game session refresh (extend/rotate server session tokens)
            if "/game-session/refresh" in path_lower and method == "POST":
                from routes.game_session_refresh import handle_game_session_refresh
                return handle_game_session_refresh(body, headers, ctx)

            # Server join
            if "/server-join/auth-grant" in path_lower and method == "POST":
                from routes.server_join import handle_auth_grant
                return handle_auth_grant(body, headers, ctx)
            if "/server-join/auth-token" in path_lower and method == "POST":
                from routes.server_join import handle_auth_token
                return handle_auth_token(body, headers, ctx)
            
            # OAuth2 endpoints
            if "/oauth2/auth" in path_lower and method == "GET":
                from routes.oauth import handle_oauth_auth
                return handle_oauth_auth(method, path, body, headers, ctx)
            if "/oauth2/token" in path_lower and method == "POST":
                from routes.oauth import handle_oauth_token
                return handle_oauth_token(method, path, body, headers, ctx)
            
            # OpenID Connect Discovery
            if "/.well-known/openid-configuration" in path_lower and method == "GET":
                from routes.oauth import handle_openid_configuration
                return handle_openid_configuration(method, path, body, headers, ctx)
            
            # DELETE /game-session (session cleanup)
            if path_lower == "/game-session" and method == "DELETE":
                return 204, None

            # Unknown sessions endpoint
            log("SERVER", f"Unknown sessions endpoint: {method} {path}", "WARN")
            return 200, {"status": "ok", "message": "endpoint not yet mapped"}

        # ---- account-data.SeedOfAnarky.fr ----
        if "account-data" in host:
            from routes.account_data import handle_account_data
            return handle_account_data(method, path, body, headers, ctx)

        # ---- telemetry.SeedOfAnarky.fr ----
        if "telemetry" in host:
            from routes.telemetry import handle_telemetry
            return handle_telemetry(method, path, body, headers, ctx)

        # ---- cdn.SeedOfAnarky.fr ----
        if "cdn" in host:
            log("CDN", f"CDN request: {method} {path} - stubbed", "WARN")
            return 200, {"status": "ok", "message": "CDN endpoint stubbed"}

        # ---- api.SeedOfAnarky.fr ----
        if "api" in host:
            log("API", f"API request: {method} {path} - stubbed", "WARN")
            return 200, {"status": "ok", "message": "API endpoint stubbed"}

        # ---- Unknown host ----
        log("SERVER", f"UNKNOWN HOST: {host} - Path: {path}", "WARN")
        return 200, {"status": "ok", "message": f"Unknown host: {host}"}

    # HTTP method handlers
    def do_GET(self):     self._handle_request("GET")
    def do_POST(self):    self._handle_request("POST")
    def do_PUT(self):     self._handle_request("PUT")
    def do_DELETE(self):  self._handle_request("DELETE")
    def do_PATCH(self):   self._handle_request("PATCH")
    def do_OPTIONS(self): self._handle_request("OPTIONS")
    def do_HEAD(self):    self._handle_request("HEAD")

# ============================================================
# Server startup
# ============================================================

def load_config():
    """Load config.json (tolerate UTF-8 BOM)."""
    with open(CONFIG_FILE, "r", encoding="utf-8-sig") as f:
        return json.load(f)

def load_data():
    """Load all data files."""
    store = {}
    for name in ("users", "entitlements", "cosmetics", "sessions"):
        path = os.path.join(DATA_DIR, f"{name}.json")
        if os.path.exists(path):
            # Tolerate UTF-8 BOM and keep encoding consistent across platforms.
            with open(path, "r", encoding="utf-8-sig") as f:
                store[name] = json.load(f)
            log("DATA", f"Loaded {name}.json ({os.path.getsize(path)} bytes)")
        else:
            store[name] = {}
            log("DATA", f"{name}.json not found - using empty", "WARN")
    return store

def load_keys(config):
    """Load Ed25519 keys."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
    
    priv_path = os.path.join(SCRIPT_DIR, config["certs"]["ed25519_private"])
    pub_path = os.path.join(SCRIPT_DIR, config["certs"]["ed25519_public"])
    
    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        log("KEYS", "Ed25519 keys not found! Run: python generate_certs.py", "ERROR")
        sys.exit(1)
    
    with open(priv_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)
    log("KEYS", f"Loaded Ed25519 private key from {priv_path}")
    
    with open(pub_path, "rb") as f:
        public_key = load_pem_public_key(f.read())
    log("KEYS", f"Loaded Ed25519 public key from {pub_path}")
    
    return private_key, public_key

def create_ssl_context(config):
    """Create SSL context for HTTPS."""
    cert_path = os.path.join(SCRIPT_DIR, config["certs"]["tls_cert"])
    key_path = os.path.join(SCRIPT_DIR, config["certs"]["tls_key"])
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        log("TLS", "TLS cert/key not found! Run: python generate_certs.py", "ERROR")
        sys.exit(1)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    
    # Support TLS 1.2+ (matching what HytaleClient.exe requests)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    log("TLS", f"SSL context created with cert: {cert_path}")
    return context

def main():
    global CONFIG, MODE, ED25519_PRIVATE_KEY, ED25519_PUBLIC_KEY
    global SESSIONS, DATA_STORE, LOG_FILE

    parser = argparse.ArgumentParser(description="SeedOfAnarky Emulator Server")
    parser.add_argument("--mode", type=int, choices=[1, 2], help="1=Passthrough, 2=Emulation")
    parser.add_argument("--port", type=int, help="Override HTTPS port")
    parser.add_argument("--generate-certs", action="store_true", help="Generate certs and exit")
    args = parser.parse_args()

    # Generate certs mode
    if args.generate_certs:
        from generate_certs import main as gen_main
        gen_main()
        return

    # Load config
    CONFIG = load_config()
    MODE = args.mode or CONFIG.get("mode", 2)
    port = args.port or CONFIG["server"]["https_port"]
    
    # Add OAuth issuer defaults if not present
    if "issuer" not in CONFIG:
        CONFIG["issuer"] = "https://sessions.hytale.com"
    if "oauth_issuer" not in CONFIG:
        CONFIG["oauth_issuer"] = "https://oauth.accounts.hytale.com"

    # Setup logging
    os.makedirs(LOGS_DIR, exist_ok=True)
    log_path = os.path.join(SCRIPT_DIR, CONFIG["logging"]["log_file"])
    LOG_FILE = open(log_path, "a", encoding="utf-8")

    # Banner
    print()
    print("\033[36m" + "=" * 60 + "\033[0m")
    print("\033[36m  SeedOfAnarky EMULATOR SERVER\033[0m")
    print(f"\033[33m  Mode: {'PASSTHROUGH (forward to real server)' if MODE == 1 else 'EMULATION (fully local)'}\033[0m")
    print("\033[36m" + "=" * 60 + "\033[0m")
    print()

    log_section("SERVER", f"STARTING - MODE {MODE}")
    log("SERVER", f"Config: {CONFIG_FILE}")
    log("SERVER", f"Mode: {MODE} ({'Passthrough' if MODE == 1 else 'Emulation'})")
    log("SERVER", f"Port: {port}")
    log("SERVER", f"Log: {log_path}")

    # Load data
    DATA_STORE = load_data()
    
    # Initialize OAuth storage
    if "oauth_codes" not in DATA_STORE:
        DATA_STORE["oauth_codes"] = {}
    
    # Load sessions from file
    SESSIONS = DATA_STORE.get("sessions", {}).get("active_sessions", {})
    log("SERVER", f"Loaded {len(SESSIONS)} existing sessions")

    # Load keys
    try:
        ED25519_PRIVATE_KEY, ED25519_PUBLIC_KEY = load_keys(CONFIG)
    except Exception as e:
        log("KEYS", f"Failed to load keys: {e}", "ERROR")
        if isinstance(e, ImportError):
            log("KEYS", "Install deps: python -m pip install --upgrade cryptography cffi", "ERROR")
        else:
            log("KEYS", "Run: python generate_certs.py", "ERROR")
        sys.exit(1)

    # Create SSL context
    ssl_context = create_ssl_context(CONFIG)

    # Start server
    server_address = (CONFIG["server"]["host"], port)
    # Use threading server so keep-alive connections don't block other clients.
    httpd = ThreadingHTTPServer(server_address, SeedOfAnarkyRequestHandler)
    httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

    log_section("SERVER", "SERVER READY")
    log("SERVER", f"Listening on https://{CONFIG['server']['host']}:{port}")
    log("SERVER", f"Serving domains: {', '.join(CONFIG['server']['domains'])}")
    
    if MODE == 2:
        log("SERVER", "Emulation mode - all requests handled locally", "OK")
        log("SERVER", f"Users loaded: {len(DATA_STORE.get('users', {}).get('users', []))}")
    else:
        log("SERVER", "Passthrough mode - forwarding to real server", "OK")
        log("SERVER", f"Real server: {CONFIG['passthrough']['real_server']}")
    
    print()
    log("SERVER", "Waiting for connections... (Ctrl+C to stop)", "OK")
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("SERVER", "Shutting down...", "WARN")
        httpd.shutdown()
        if LOG_FILE:
            LOG_FILE.close()
        save_sessions()
        log("SERVER", "Server stopped.", "OK")


if __name__ == "__main__":
    main()
