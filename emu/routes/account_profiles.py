"""
Account profile endpoints for HytaleServer.exe
Returns player profile and skin data
"""

import json
from datetime import datetime, timedelta


def handle_get_profiles(ctx):
    """
    GET /my-account/get-profiles - Get user profiles
    
    HytaleServer.exe calls this to get player skin/profile info.
    Returns array of profiles with skin customization data.
    """
    log = ctx["log"]
    users = ctx["data"].get("users", {}).get("users", [])

    log("ACCOUNT", "Get profiles request")

    if not users:
        return 200, {"owner": "", "profiles": []}

    now_iso = datetime.utcnow().isoformat() + "Z"
    next_name_change = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"

    profiles = []
    for user in users:
        skin_value = user.get("skin", {})
        skin_str = json.dumps(skin_value) if isinstance(skin_value, dict) else str(skin_value)
        profiles.append(
            {
                "createdAt": user.get("created") or now_iso,
                "entitlements": user.get("entitlements", ["game.base"]),
                "nextNameChangeAt": next_name_change,
                "skin": skin_str,
                "username": user.get("username", "Unknown"),
                "uuid": user.get("uuid", ""),
            }
        )

    owner = profiles[0].get("uuid", "") if profiles else ""
    log("ACCOUNT", f"Returning {len(profiles)} profile(s)", "OK")
    return 200, {"owner": owner, "profiles": profiles}
