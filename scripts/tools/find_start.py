def main():
    filepath = "backend/app.py"
    with open(filepath, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            if "_upsert_lan_and_agent" in line and "def " in line:
                print(f"Line {idx}: {line.strip()}")

if __name__ == '__main__':
    main()
