def main():
    filepath = "backend/app.py"
    print(f"Searching in {filepath}...")
    with open(filepath, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            if "@app." in line and ("/api/agent" in line or "/api/lan" in line):
                print(f"Line {idx}: {line.strip()}")

if __name__ == '__main__':
    main()
