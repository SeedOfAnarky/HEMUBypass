"""
JWKS Route Handler
==================
Handles: GET /.well-known/jwks.json
Domain:  sessions.SeedOfAnark.fr

HytaleClient.exe fetches this TWICE on startup (per Fiddler trace).
It uses the public key from here to verify the JWT signatures
on the identity and session tokens it was given at launch.

This endpoint works the same in both modes - it always serves our
Ed25519 public key so the client can verify our signed tokens.
"""

import json
import base64


def handle_jwks(ctx):
    """
    GET /.well-known/jwks.json
    
    Response: {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "...", "use": "sig", "x": "..."}]}
    """
    log = ctx["log"]
    config = ctx["config"]
    
    log("JWKS", "Client requesting JWKS public key")

    # In mode 1, we STILL serve our own key (because the client is redirected
    # to us via hosts file and needs to verify our tokens)
    # In mode 2, same thing - serve our key
    
    # Get the Ed25519 public key raw bytes for the 'x' parameter
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    
    public_key = ctx["ed25519_public_key"]
    raw_public = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )
    
    x_b64url = base64.urlsafe_b64encode(raw_public).rstrip(b'=').decode()
    kid = config["certs"]["kid"]

    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "alg": "EdDSA",
                "use": "sig",
                "x": x_b64url
            }
        ]
    }

    log("JWKS", f"Serving JWKS: kid={kid}, x={x_b64url[:30]}...")
    log("JWKS", f"Full JWKS response: {json.dumps(jwks)}")

    return 200, jwks
