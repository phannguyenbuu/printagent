import sqlite3
import os

def main():
    db_paths = [
        "dist/storage/data/agent_config.db",
        "storage/data/agent_config.db",
        "storage/data/local_storage.db"
    ]
    for db_path in db_paths:
        if os.path.exists(db_path):
            print(f"--- DB: {db_path} ---")
            try:
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                    print(f"Tables: {[t[0] for t in tables]}")
                    for table in tables:
                        tname = table[0]
                        print(f"  Table {tname}:")
                        try:
                            rows = cursor.execute(f"SELECT * FROM {tname} LIMIT 20").fetchall()
                            for r in rows:
                                print(f"    {r}")
                        except Exception as e:
                            print(f"    Error reading table {tname}: {e}")
            except Exception as e:
                print(f"  Error opening {db_path}: {e}")

if __name__ == '__main__':
    main()
