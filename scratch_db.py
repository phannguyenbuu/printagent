import sqlite3
import os

def check_db(db_path):
    if not os.path.exists(db_path):
        print(f"{db_path} does not exist!")
        return False
    print(f"\nFound DB at: {db_path}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables: {tables}")
        for t in tables:
            name = t[0]
            print(f"\n--- Table {name} ---")
            cursor.execute(f"SELECT * FROM {name};")
            for row in cursor.fetchall():
                print(row)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
    return True

def main():
    paths = [
        "storage/data/agent_config.db",
        "dist/storage/data/agent_config.db",
        "agent/storage/data/agent_config.db",
    ]
    for p in paths:
        if check_db(p):
            break

if __name__ == '__main__':
    main()
