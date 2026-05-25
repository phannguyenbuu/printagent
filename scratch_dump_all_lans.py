import os
import psycopg2

db_url = "postgresql://postgres:%40baoLong0511@31.97.76.62:5432/GoPrinx"
try:
    conn = psycopg2.connect(db_url)
    cursor = conn.cursor()
    cursor.execute('SELECT lead, lan_uid, lan_name, subnet_cidr, gateway_mac FROM "LanSite"')
    rows = cursor.fetchall()
    print("Total LanSites:", len(rows))
    for r in rows:
        print(r)
    conn.close()
except Exception as e:
    print("Error:", e)
