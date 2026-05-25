import requests
import json

base_url = "https://agentapi.quanlymay.com"

print("--- Checking agent_release.json directly via static/storage if exposed, or through API ---")

# Let's try /api/agent/release
try:
    headers = {"X-Lead-Token": "test"} # just a dummy token to see if it responds
    params = {
        "lead": "test",
        "agent_uid": "test",
        "lan_uid": "test",
        "hostname": "test",
        "local_ip": "127.0.0.1",
        "current_version": "1.3.64",
        "current_sha256": ""
    }
    resp = requests.get(f"{base_url}/api/agent/release", params=params, headers=headers, timeout=10)
    print("API /api/agent/release status:", resp.status_code)
    try:
        print("API /api/agent/release response:", json.dumps(resp.json(), indent=2))
    except Exception:
        print("API /api/agent/release raw response:", resp.text[:500])
except Exception as e:
    print("API /api/agent/release request error:", e)

# Let's try /api/agent/core-release
try:
    headers = {"X-Lead-Token": "test"}
    params = {
        "lead": "test",
        "agent_uid": "test",
        "lan_uid": "test",
        "hostname": "test",
        "local_ip": "127.0.0.1",
        "current_version": "1.3.64",
        "current_sha256": ""
    }
    resp = requests.get(f"{base_url}/api/agent/core-release", params=params, headers=headers, timeout=10)
    print("\nAPI /api/agent/core-release status:", resp.status_code)
    try:
        print("API /api/agent/core-release response:", json.dumps(resp.json(), indent=2))
    except Exception:
        print("API /api/agent/core-release raw response:", resp.text[:500])
except Exception as e:
    print("API /api/agent/core-release request error:", e)
