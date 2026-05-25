import requests
import json

try:
    resp = requests.get("https://agentapi.quanlymay.com/api/lan-sites", timeout=10)
    print("Status code:", resp.status_code)
    data = resp.json()
    rows = data.get("rows", [])
    print("Total rows:", len(rows))
    for idx, r in enumerate(rows):
        print(f"\nRow {idx+1}:")
        print("  Lead:", r.get("lead"))
        print("  Lan UID:", r.get("lan_uid"))
        print("  Subnet:", r.get("subnet_cidr"))
        print("  Active Agents count:", r.get("active_agents"))
        print("  Agents:")
        for ag in r.get("agents", []):
            print(f"    - UID: {ag.get('agent_uid')} | IP: {ag.get('local_ip')} | Online: {ag.get('is_online')} | Master: {ag.get('is_master')}")
except Exception as e:
    print("Error:", e)
