import os
import psycopg2

try:
    conn = psycopg2.connect(host="localhost", user="postgres", password="@baoLong0511", database="GoPrinx")
    cursor = conn.cursor()
    cursor.execute('SELECT lead, lan_uid, lan_name, subnet_cidr FROM "LanSite"')
    print('Local LanSites:', cursor.fetchall())
    cursor.execute('SELECT lead, agent_uid, hostname, local_ip, is_online FROM "AgentNode"')
    print('Local Agents:', cursor.fetchall())
    conn.close()
except Exception as e:
    print("Error:", e)
