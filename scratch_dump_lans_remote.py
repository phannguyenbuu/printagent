import psycopg2

db_url = "postgresql://postgres:%40baoLong0511@localhost:5432/GoPrinx"
try:
    conn = psycopg2.connect(db_url)
    cursor = conn.cursor()
    
    print("=== LEADS ===")
    cursor.execute('SELECT id, name FROM "Lead"')
    for r in cursor.fetchall():
        print(f"Lead ID: {r[0]} | Name: {r[1]}")
        
    print("\n=== WORKSPACES ===")
    cursor.execute('SELECT id, name, address FROM "Workspace"')
    for r in cursor.fetchall():
        print(f"Workspace ID: {r[0]} | Name: {r[1]} | Address: {r[2]}")
        
    print("\n=== USER ACCOUNTS ===")
    cursor.execute('SELECT id, lead, username, email, role, user_type FROM "UserAccount"')
    for r in cursor.fetchall():
        print(f"User ID: {r[0]} | Lead: {r[1]} | Username: {r[2]} | Email: {r[3]} | Role: {r[4]} | Type: {r[5]}")
        
    print("\n=== LAN SITES ===")
    cursor.execute('SELECT lead, lan_uid, lan_name, subnet_cidr, gateway_ip, gateway_mac FROM "LanSite"')
    for r in cursor.fetchall():
        print(f"Lead: {r[0]} | LAN UID: {r[1]} | LAN Name: {r[2]} | Subnet: {r[3]} | Gateway IP: {r[4]} | Gateway MAC: {r[5]}")
        
    conn.close()
except Exception as e:
    print("Error:", e)
