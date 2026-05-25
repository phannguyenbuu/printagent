import psycopg2

try:
    conn = psycopg2.connect('postgresql://postgres:myPass@localhost:5432/GoPrinx')
    cur = conn.cursor()
    cur.execute('select id, username, password, role, user_type from "UserAccount"')
    for r in cur.fetchall():
        print(r)
    conn.close()
except Exception as e:
    print("Error:", e)
