import sqlite3
import json

db_path = r"d:\Dropbox\_Documents\Goxprint\printagent_v2\dist\storage\data\agent_config.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("Tables:", tables)
    
    for t in tables:
        tname = t[0]
        print(f"\n=== Table: {tname} ===")
        cursor.execute(f"SELECT * FROM {tname};")
        rows = cursor.fetchall()
        for r in rows:
            print(r)
except Exception as e:
    print("Error:", e)
finally:
    conn.close()
