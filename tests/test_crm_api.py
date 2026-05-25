import requests
import time

def test_crm_api():
    # Configuration - Change these based on your local environment
    SERVER_URL = "http://localhost:5000"
    LEAD = "test-lead"
    TOKEN = "test-token" # Make sure this is in your config.yaml lead_keys
    
    print(f"Testing CRM API at {SERVER_URL} for lead '{LEAD}'...")
    
    # 1. Register Agent
    print("\n1. Registering Agent...")
    reg_payload = {
        "lead": LEAD,
        "agent_uid": "test-agent",
        "hostname": "test-host",
        "local_ip": "192.168.1.10"
    }
    resp = requests.post(f"{SERVER_URL}/api/agent/register", json=reg_payload, headers={"X-Lead-Token": TOKEN})
    if resp.status_code != 200:
        print(f"FAILED: Agent registration failed ({resp.status_code}): {resp.text}")
        return
    print("SUCCESS: Agent registered.")

    # 2. Post Polling Data
    print("\n2. Posting Polling Data...")
    polling_payload = {
        "lead": LEAD,
        "agent_uid": "test-agent",
        "hostname": "test-host",
        "local_ip": "192.168.1.10",
        "printer_name": "Test Printer Ricoh",
        "ip": "192.168.1.200",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "counter_data": {
            "total": "12345"
        },
        "status_data": {
            "system_status": "OK",
            "toner_black": "OK",
            "printer_alerts": "No alerts"
        }
    }
    resp = requests.post(f"{SERVER_URL}/api/polling", json=polling_payload, headers={"X-Lead-Token": TOKEN})
    if resp.status_code != 200:
        print(f"FAILED: Polling ingestion failed ({resp.status_code}): {resp.text}")
        return
    print("SUCCESS: Polling data ingested.")

    # 3. Call CRM API
    print("\n3. Calling CRM API...")
    resp = requests.get(f"{SERVER_URL}/api/public/crm/printers", params={"lead": LEAD}, headers={"X-Lead-Token": TOKEN})
    if resp.status_code != 200:
        print(f"FAILED: CRM API call failed ({resp.status_code}): {resp.text}")
        return
    
    data = resp.json()
    if not data.get("ok"):
        print(f"FAILED: CRM API returned ok: False: {data}")
        return
    
    printers = data.get("printers", [])
    if not printers:
        print("FAILED: CRM API returned no printers.")
        return
    
    # Verify first printer
    p = printers[0]
    print(f"Found printer: {p['printer_name']} ({p['ip']})")
    
    expected = {
        "printer_name": "Test Printer Ricoh",
        "ip": "192.168.1.200",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "total_bw": 0, # Since it's the first record, delta from baseline (itself) is 0
        "status": "OK",
        "toner_black": "OK"
    }
    
    all_ok = True
    for key, val in expected.items():
        if p.get(key) != val:
            print(f"MISMATCH: field '{key}' expected '{val}', got '{p.get(key)}'")
            all_ok = False
            
    if all_ok:
        print("\nSUCCESS: CRM API verification passed!")
    else:
        print("\nFAILED: CRM API verification failed due to mismatches.")

if __name__ == "__main__":
    test_crm_api()
