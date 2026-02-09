"""
Telemetry Route Handler
========================
Handles: POST /telemetry/client
Domain:  telemetry.SeedOfAnark.fr

Confirmed from Fiddler captures:
  #14: type "event", event_name "state_transition"
  #15: type "session_start" with full client/hardware/platform info

Response: {"success": true, "data": {"timestamp": "<ISO8601>"}}
"""

import json
import datetime


def handle_telemetry(method, path, request_body, headers, ctx):
    """POST /telemetry/client - accept, log, return success."""
    log = ctx["log"]
    
    log("TELEMETRY", f">>> {method} {path}")
    log("TELEMETRY", f"User-Agent: {headers.get('User-Agent', 'unknown')}")

    if request_body:
        try:
            body = json.loads(request_body)
            event_type = body.get("type", "unknown")
            sequence = body.get("sequence", "?")
            session_id = body.get("session_id", "?")
            
            log("TELEMETRY", f"Event type: {event_type} | seq: {sequence} | session: {session_id}")

            if event_type == "session_start":
                client = body.get("client", {})
                platform = body.get("platform", {})
                hardware = body.get("hardware", {})
                display = body.get("display", {})
                gpu = hardware.get("gpu", {})
                
                log("TELEMETRY", f"  Client: {client.get('version')} [{client.get('configuration')}/{client.get('patchline')}]")
                log("TELEMETRY", f"  OS: {platform.get('os')} {platform.get('os_version')}")
                log("TELEMETRY", f"  CPU: {hardware.get('cpu_cores')} cores | RAM: {hardware.get('system_memory_mb')}MB")
                log("TELEMETRY", f"  GPU: {gpu.get('renderer')} | VRAM: {gpu.get('vram_total_mb')}MB")
                log("TELEMETRY", f"  Display: {display.get('resolution_width')}x{display.get('resolution_height')} @ {display.get('refresh_rate_hz')}Hz")
                log("TELEMETRY", f"  Machine hash: {hardware.get('machine_id_hash', '?')[:16]}...")

            elif event_type == "event":
                log("TELEMETRY", f"  Event: {body.get('event_name', '?')}")
                log("TELEMETRY", f"  Data: {json.dumps(body.get('event_data', {}))}")
            else:
                log("TELEMETRY", f"  Body: {json.dumps(body, indent=2)}")

        except (json.JSONDecodeError, TypeError):
            log("TELEMETRY", f"  Raw ({len(request_body)}B): {request_body[:200]}")
    else:
        log("TELEMETRY", "  No body")

    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    return 200, {"success": True, "data": {"timestamp": now}}
