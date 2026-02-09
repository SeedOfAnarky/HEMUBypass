#!/usr/bin/env python3
"""
HytaleServer wrapper (runs from ./emu)

Features:
- Syncs ./Server/certs from ./emu/certs (source of truth)
- Ensures Java truststore contains the emulator TLS certificate
- Auto-triggers OAuth URLs (follow redirect and deliver callback)
"""

import http.client
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


# Disable SSL verification for localhost (only used for local emulator calls).
ssl._create_default_https_context = ssl._create_unverified_context


class ServerWrapper:
    def __init__(self) -> None:
        self.process: Optional[subprocess.Popen] = None
        self.running = False
        self.oauth_pattern = re.compile(r"https://oauth\.accounts\.hytale\.com/oauth2/auth\?[^\s]+")

        self.emu_dir = Path(__file__).resolve().parent
        self.game_dir = self.emu_dir.parent
        self.server_dir = self.game_dir / "Server"

        self.emu_certs_dir = self.emu_dir / "certs"
        self.server_certs_dir = self.server_dir / "certs"

        # Reuse the emulator truststore file (kept fresh by start_server_emu.ps1 when available).
        self.truststore_path = self.emu_certs_dir / "emu-truststore.jks"
        self.exported_cert_path = self.emu_dir / "emu-cert.cer"

        # Set up file logging
        self.log_filename = self.emu_dir / f"hytale_server_wrapper_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
        self.log_file = None

    def log_and_print(self, msg: str) -> None:
        print(msg)
        if self.log_file:
            self.log_file.write(msg + "\n")
            self.log_file.flush()

    def sync_certs_from_emu(self) -> bool:
        """Sync ./Server/certs from ./emu/certs (source of truth)."""
        src_dir = self.emu_certs_dir
        dst_dir = self.server_certs_dir
        if not src_dir.exists():
            self.log_and_print(f"[CERT] Source certs not found: {src_dir}")
            return False

        dst_dir.mkdir(parents=True, exist_ok=True)
        cert_files = [
            "server.crt",
            "server.key",
            "emu-truststore.jks",
            "ed25519_private.pem",
            "ed25519_public.pem",
        ]

        synced = 0
        for name in cert_files:
            src_file = src_dir / name
            if not src_file.exists():
                self.log_and_print(f"[CERT] Missing source cert: {src_file}")
                continue

            dst_file = dst_dir / name
            try:
                if (
                    not dst_file.exists()
                    or src_file.stat().st_mtime > dst_file.stat().st_mtime
                    or src_file.stat().st_size != dst_file.stat().st_size
                ):
                    shutil.copy2(src_file, dst_file)
                synced += 1
            except Exception as e:
                self.log_and_print(f"[CERT] Failed to sync {name}: {e}")
                return False

        self.log_and_print(f"[CERT] Synced {synced} cert file(s) into {dst_dir}")
        return True

    def setup_certificate_trust(self) -> bool:
        """Ensure the truststore exists and trusts the emulator TLS cert."""
        self.log_and_print("")
        self.log_and_print("=" * 70)
        self.log_and_print("[CERT] Checking SSL certificate trust...")
        self.log_and_print("=" * 70)

        cert_source = self.emu_certs_dir / "server.crt"
        if cert_source.exists():
            self.log_and_print(f"[CERT] Using cert from: {cert_source}")
        else:
            cert_source = None

        # If truststore exists and is newer than the cert source, skip regeneration.
        if self.truststore_path.exists() and cert_source and cert_source.exists():
            if self.truststore_path.stat().st_mtime >= cert_source.stat().st_mtime:
                self.log_and_print("[CERT] Truststore is up-to-date, skipping setup")
                self.log_and_print("")
                return True

        self.log_and_print("[CERT] Setting up SSL certificate trust...")
        self.log_and_print("")

        # If we don't have a cert file, export from the running emulator
        if not cert_source:
            self.log_and_print("[CERT] Step 1/2: Checking if emulator is running...")
            try:
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection("127.0.0.1", 443, context=context, timeout=3)
                conn.request("GET", "/health")
                resp = conn.getresponse()
                resp.read()
                conn.close()
                self.log_and_print("[CERT] ✓ Emulator is running")
            except Exception as e:
                self.log_and_print(f"[CERT] ✗ Cannot connect to emulator: {e}")
                self.log_and_print("")
                self.log_and_print("[ERROR] Please start the emulator first!")
                self.log_and_print(f"  1. Open a terminal in: {self.emu_dir}")
                self.log_and_print("  2. Run: START_EMU.bat")
                self.log_and_print("  3. Wait for the emulator to listen on https://127.0.0.1:443")
                self.log_and_print("  4. Then restart the server wrapper")
                self.log_and_print("")
                return False

            # Export certificate from emulator
            self.log_and_print("[CERT] Step 2/2: Exporting emulator certificate...")
            try:
                context = ssl._create_unverified_context()
                with socket.create_connection(("127.0.0.1", 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname="oauth.accounts.hytale.com") as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)

                from base64 import b64encode

                with open(self.exported_cert_path, "w", encoding="ascii") as f:
                    f.write("-----BEGIN CERTIFICATE-----\n")
                    cert_b64 = b64encode(cert_der).decode("ascii")
                    for i in range(0, len(cert_b64), 64):
                        f.write(cert_b64[i : i + 64] + "\n")
                    f.write("-----END CERTIFICATE-----\n")

                self.log_and_print(f"[CERT] ✓ Certificate exported to: {self.exported_cert_path.name}")
                cert_source = self.exported_cert_path
            except Exception as e:
                self.log_and_print(f"[CERT] ✗ Failed to export certificate: {e}")
                import traceback

                self.log_and_print(traceback.format_exc())
                return False

        # Create truststore using keytool
        self.log_and_print("[CERT] Creating truststore...")
        try:
            keytool = shutil.which("keytool")

            if not keytool:
                # Try to find in JAVA_HOME
                java_home = os.environ.get("JAVA_HOME")
                if java_home:
                    possible_keytool = Path(java_home) / "bin" / "keytool.exe"
                    if possible_keytool.exists():
                        keytool = str(possible_keytool)

                # Try to find next to java
                if not keytool:
                    java_path = shutil.which("java")
                    if java_path:
                        java_dir = Path(java_path).parent.parent
                        possible_keytool = java_dir / "bin" / "keytool.exe"
                        if possible_keytool.exists():
                            keytool = str(possible_keytool)

            if not keytool:
                self.log_and_print("[CERT] ✗ keytool not found")
                self.log_and_print("[CERT] Please install Java JDK or add it to PATH")
                return False

            self.log_and_print(f"[CERT] Found keytool: {keytool}")

            # Delete old truststore if exists
            if self.truststore_path.exists():
                self.truststore_path.unlink()

            result = subprocess.run(
                [
                    keytool,
                    "-import",
                    "-noprompt",
                    "-trustcacerts",
                    "-alias",
                    "hytale-emu",
                    "-file",
                    str(cert_source),
                    "-keystore",
                    str(self.truststore_path),
                    "-storepass",
                    "changeit",
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                self.log_and_print(f"[CERT] ✓ Truststore created: {self.truststore_path.name}")
                self.log_and_print("")
                self.log_and_print("[CERT] ✓ SSL certificate trust configured successfully!")
                self.log_and_print("")
                return True

            self.log_and_print("[CERT] ✗ Failed to create truststore")
            self.log_and_print(f"[CERT] keytool stdout: {result.stdout}")
            self.log_and_print(f"[CERT] keytool stderr: {result.stderr}")
            return False

        except Exception as e:
            self.log_and_print(f"[CERT] ✗ Failed to create truststore: {e}")
            import traceback

            self.log_and_print(traceback.format_exc())
            return False

    def auto_trigger_oauth(self, url: str) -> None:
        """Automatically trigger OAuth request and follow redirect to callback."""
        self.log_and_print("")
        self.log_and_print("[AUTO-AUTH] =====================================")
        self.log_and_print("[AUTO-AUTH] OAuth URL detected!")
        self.log_and_print("[AUTO-AUTH] Auto-triggering authentication...")
        self.log_and_print("[AUTO-AUTH] =====================================")
        self.log_and_print("")

        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            self.log_and_print("[AUTO-AUTH] Step 1: Requesting emulator OAuth endpoint...")

            context = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection("127.0.0.1", 443, context=context)
            request_path = f"{parsed.path}?{parsed.query}"
            conn.request("GET", request_path)
            response = conn.getresponse()

            if response.status in (301, 302, 303, 307, 308):
                redirect_location = response.getheader("Location")
                self.log_and_print(f"[AUTO-AUTH] Step 2: Got redirect to: {redirect_location[:80]}...")

                callback_parsed = urlparse(redirect_location)
                self.log_and_print("[AUTO-AUTH] Step 3: Sending callback to HytaleServer...")

                callback_conn = http.client.HTTPConnection("127.0.0.1", callback_parsed.port or 80)
                callback_path = f"{callback_parsed.path}?{callback_parsed.query}"
                callback_conn.request("GET", callback_path)
                callback_response = callback_conn.getresponse()
                callback_response.read()
                self.log_and_print(f"[AUTO-AUTH] ✓ SUCCESS! Callback delivered (HTTP {callback_response.status})")
                callback_conn.close()
            else:
                self.log_and_print(f"[AUTO-AUTH] ✗ Unexpected response: HTTP {response.status}")

            conn.close()
        except Exception as e:
            self.log_and_print(f"[AUTO-AUTH] ✗ Error: {e}")

        self.log_and_print("")

    def send_command(self, cmd: str) -> bool:
        if self.process and self.process.poll() is None:
            try:
                assert self.process.stdin is not None
                self.process.stdin.write(cmd + "\n")
                self.process.stdin.flush()
                return True
            except Exception:
                return False
        return False

    def read_output(self) -> None:
        try:
            assert self.process is not None
            assert self.process.stdout is not None
            for line in iter(self.process.stdout.readline, ""):
                sys.stdout.write(line)
                sys.stdout.flush()

                if self.log_file:
                    self.log_file.write(line)
                    self.log_file.flush()

                ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
                clean_line = ansi_escape.sub("", line)

                match = self.oauth_pattern.search(clean_line)
                if match:
                    oauth_url = match.group(0)
                    threading.Thread(target=self.auto_trigger_oauth, args=(oauth_url,), daemon=True).start()
        except Exception:
            pass
        finally:
            self.running = False
            if self.log_file:
                self.log_file.close()

    def read_input(self) -> None:
        shortcuts = {
            "/auth": "auth login browser",
            "/status": "auth status",
            "/help": "help",
            "/stop": "stop",
            "/list": "list",
        }

        print()
        print("=" * 70)
        print("[READY] Server is running! You can now type commands.")
        print()
        print("Available shortcuts:")
        print("  /auth   (or /Auth) - Authenticate with OAuth (same as: auth login browser)")
        print("  /status (or /Status) - Check authentication status")
        print("  /help   (or /Help) - Show server help")
        print("  /stop   (or /Stop) - Stop the server")
        print()
        print("Or type any server command directly (e.g., 'list', 'help')")
        print("Press Ctrl+C to force stop")
        print("=" * 70)
        print()

        while self.running:
            try:
                user_input = input("> ").strip()
                if not user_input:
                    continue
                shortcut_key = user_input.lower()
                if shortcut_key in shortcuts:
                    actual_command = shortcuts[shortcut_key]
                    print(f"[CMD] Sending: {actual_command}")
                    self.send_command(actual_command)
                else:
                    self.send_command(user_input)
            except EOFError:
                break
            except KeyboardInterrupt:
                print()
                print("[INPUT] Ctrl+C detected. Type /stop or press Ctrl+C again to exit.")
                print()
                time.sleep(0.5)

    def run(self) -> None:
        try:
            self.log_file = open(self.log_filename, "w", encoding="utf-8", buffering=1)
            print(f"Wrapper logging to: {self.log_filename}")
            print("")
        except Exception:
            self.log_file = None

        server_jar = self.server_dir / "HytaleServer.jar"
        assets_zip = self.game_dir / "Assets.zip"
        if not assets_zip.exists():
            # Allow drop-in layouts where Assets.zip lives inside Server/
            assets_zip = self.server_dir / "Assets.zip"
        aot_cache = self.server_dir / "HytaleServer.aot"

        if not server_jar.exists():
            print(f"[ERROR] HytaleServer.jar not found at {server_jar}")
            input("Press Enter to exit...")
            sys.exit(1)

        if not assets_zip.exists():
            print(f"[ERROR] Assets.zip not found at {assets_zip}")
            input("Press Enter to exit...")
            sys.exit(1)

        # Sync certs from emu/ (source of truth)
        self.sync_certs_from_emu()

        # Ensure truststore exists
        if not self.setup_certificate_trust():
            print()
            print("[ERROR] Failed to set up SSL certificate trust")
            print("[ERROR] Authentication will not work without this")
            print()
            input("Press Enter to exit...")
            sys.exit(1)

        cmd = [
            "java",
            f"-Djavax.net.ssl.trustStore={self.truststore_path}",
            "-Djavax.net.ssl.trustStorePassword=changeit",
            "-XX:AOTCache=HytaleServer.aot",
            "-jar",
            "HytaleServer.jar",
            "--assets",
            str(assets_zip),
        ]

        self.log_and_print("=" * 70)
        self.log_and_print("  Hytale Server (Interactive Mode)")
        self.log_and_print("=" * 70)
        self.log_and_print("")
        self.log_and_print(f"[INFO] Server Directory: {self.server_dir}")
        self.log_and_print(f"[INFO] Assets: {assets_zip.name}")
        self.log_and_print(f"[INFO] AOT Cache: {'Enabled' if aot_cache.exists() else 'Disabled'}")
        self.log_and_print(f"[INFO] Truststore: {self.truststore_path}")
        self.log_and_print("")
        self.log_and_print("[INFO] Features:")
        self.log_and_print("  ✓ Auto-trigger OAuth URLs")
        self.log_and_print("  ✓ Auto-configure SSL certificates")
        self.log_and_print("  ✓ Interactive command input with shortcuts")
        self.log_and_print("  ✓ Real-time output display")
        self.log_and_print("")
        self.log_and_print("[INFO] Starting server...")
        self.log_and_print("")
        self.log_and_print("=" * 70)
        self.log_and_print("")

        try:
            self.process = subprocess.Popen(
                cmd,
                cwd=str(self.server_dir),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True,
                encoding="utf-8",
                errors="replace",
            )
            self.running = True
        except Exception as e:
            print(f"[ERROR] Failed to start server: {e}")
            input("Press Enter to exit...")
            sys.exit(1)

        output_thread = threading.Thread(target=self.read_output, daemon=True)
        output_thread.start()

        time.sleep(2)

        input_thread = threading.Thread(target=self.read_input, daemon=True)
        input_thread.start()

        try:
            assert self.process is not None
            self.process.wait()
        except KeyboardInterrupt:
            print()
            print("[INFO] Stopping server...")
            self.send_command("stop")
            time.sleep(2)
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print("[INFO] Force killing server...")
                    self.process.kill()

        print()
        print("=" * 70)
        print(f"[INFO] Server stopped (exit code: {self.process.returncode if self.process else 'unknown'})")
        print("=" * 70)


if __name__ == "__main__":
    wrapper = ServerWrapper()
    wrapper.run()
