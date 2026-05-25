import requests
import json

def main():
    headers = {
        "X-Lead-Token": "change-me"
    }
    
    # 1. Fetch LAN sites
    url = "https://agentapi.quanlymay.com/api/lan-sites?lead=default"
    print(f"GET {url}")
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        print(f"Status: {resp.status_code}")
        print("LAN Sites:")
        print(json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"Error fetching LAN sites: {e}")

    # 2. Fetch Agents
    url = "https://agentapi.quanlymay.com/api/agents?lead=default"
    print(f"\nGET {url}")
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        print(f"Status: {resp.status_code}")
        print("Agents:")
        print(json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"Error fetching agents: {e}")

if __name__ == '__main__':
    main()
