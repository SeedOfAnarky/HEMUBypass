#!/usr/bin/env python3
"""
Generate all certificates needed for the SeedOfAnarky Emulator.
  1. Self-signed TLS cert (RSA) with SANs for all SeedOfAnarky domains + 127.0.0.1
  2. Ed25519 keypair for JWT signing (matches what the real server uses)

Run once before starting the emulator.
"""

import os
import sys
import datetime
import json

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
    from cryptography.hazmat.backends import default_backend
    import ipaddress
except ImportError:
    print("[!] Python crypto dependencies are missing or broken. Install with:")
    print("    pip install --upgrade cryptography cffi")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(SCRIPT_DIR, "certs")
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

def load_config():
    # Use utf-8-sig to tolerate BOMs written by PowerShell.
    with open(CONFIG_FILE, "r", encoding="utf-8-sig") as f:
        return json.load(f)

def generate_tls_cert(config):
    """Generate self-signed RSA TLS certificate with SANs."""
    print("[*] Generating RSA TLS certificate...")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    domains = config["server"]["domains"]
    # Prefer the sessions domain for CN if present (most clients connect to it first).
    primary_domain = "sessions.SeedOfAnarky.fr"
    if isinstance(domains, list) and domains:
        if "sessions.SeedOfAnarky.fr" in domains:
            primary_domain = "sessions.SeedOfAnarky.fr"
        else:
            primary_domain = domains[0]
    # Allow override via environment for testing.
    env_cn = os.environ.get("SeedOfAnarky_CERT_CN")
    if env_cn:
        primary_domain = env_cn
    
    # Build SAN list: all domains + www variants + 127.0.0.1 + localhost
    san_list = []
    for d in domains:
        san_list.append(x509.DNSName(d))
        san_list.append(x509.DNSName(f"www.{d}"))
    san_list.append(x509.DNSName("localhost"))
    san_list.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SeedOfAnarky Emulator"),
        x509.NameAttribute(NameOID.COMMON_NAME, primary_domain),
    ])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    # Write private key
    key_path = os.path.join(CERTS_DIR, "server.key")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"    [+] TLS private key: {key_path}")

    # Write certificate
    cert_path = os.path.join(CERTS_DIR, "server.crt")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"    [+] TLS certificate: {cert_path}")

    # Print SANs for verification
    print(f"    [+] Subject CN: {primary_domain}")
    print(f"    [+] SANs: {', '.join(str(s.value) for s in san_list)}")

    return key_path, cert_path


def generate_ed25519_keys(config):
    """Generate Ed25519 keypair for JWT signing."""
    print("[*] Generating Ed25519 JWT signing keypair...")

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Write private key
    priv_path = os.path.join(CERTS_DIR, "ed25519_private.pem")
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"    [+] Ed25519 private key: {priv_path}")

    # Write public key
    pub_path = os.path.join(CERTS_DIR, "ed25519_public.pem")
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"    [+] Ed25519 public key: {pub_path}")

    # Also compute and display the base64url x coordinate for JWKS
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    import base64
    x_b64url = base64.urlsafe_b64encode(raw_public).rstrip(b'=').decode()
    kid = config["certs"]["kid"]
    
    print(f"    [+] JWKS 'x' value: {x_b64url}")
    print(f"    [+] JWKS 'kid': {kid}")
    print(f"    [+] JWKS entry: {{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"{kid}\",\"use\":\"sig\",\"x\":\"{x_b64url}\"}}")

    return priv_path, pub_path


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)
    
    config = load_config()

    print("=" * 60)
    print("  SeedOfAnarky Emulator - Certificate Generator")
    print("=" * 60)
    print()

    # Check if certs already exist
    existing = []
    for f in ["server.key", "server.crt", "ed25519_private.pem", "ed25519_public.pem"]:
        p = os.path.join(CERTS_DIR, f)
        if os.path.exists(p):
            existing.append(f)

    if existing:
        print(f"[!] Found existing cert files: {', '.join(existing)}")
        resp = input("    Overwrite? (y/N): ").strip().lower()
        if resp != 'y':
            print("[*] Keeping existing certs.")
            return

    generate_tls_cert(config)
    print()
    generate_ed25519_keys(config)
    
    print()
    print("=" * 60)
    print("  DONE! Certs generated in ./certs/")
    print()
    print("  IMPORTANT: To make HytaleClient.exe trust the TLS cert,")
    print("  you need to install server.crt as a Trusted Root CA")
    print("  on your Windows machine, OR configure Fiddler to")
    print("  intercept and re-sign traffic.")
    print("=" * 60)


if __name__ == "__main__":
    main()
