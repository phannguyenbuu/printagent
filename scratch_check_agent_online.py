import psycopg2
from datetime import datetime, timezone

db_url = "postgresql://postgres:%40baoLong0511@localhost:5432/GoPrinx"
try:
    conn = psycopg2.connect(db_url)
    cursor = conn.cursor()
    cursor.execute('SELECT agent_uid, lan_uid, hostname, local_ip, is_online, last_seen_at FROM "AgentNode" WHERE agent_uid IN (%s, %s)', ("administrator", "admin-pc"))
    rows = cursor.fetchall()
    print("Now (UTC):", datetime.now(timezone.utc))
    for r in rows:
        print(f"UID: {r[0]} | LAN: {r[1]} | Host: {r[2]} | IP: {r[3]} | Online: {r[4]} | Last Seen: {r[5]}")
    conn.close()
except Exception as e:
    print("Error:", e)
