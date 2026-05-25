import sqlite3
from pathlib import Path

def main():
    db_path = Path("storage/data/agent_config.db")
    if not db_path.exists():
        print(f"Database {db_path} does not exist!")
        # Let's check dist/storage/data/agent_config.db as well!
        db_path = Path("dist/storage/data/agent_config.db")
        if not db_path.exists():
            print(f"Database {db_path} does not exist either!")
            return
    print(f"Querying database at: {db_path}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        print("Tables:", tables)
        for table in tables:
            print(f"\n--- Table {table} ---")
            cursor.execute(f"SELECT * FROM \"{table}\" LIMIT 50;")
            cols = [description[0] for description in cursor.description]
            print("Columns:", cols)
            rows = cursor.fetchall()
            for row in rows:
                print(row)
    except Exception as e:
        print(f"Error querying: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    main()
