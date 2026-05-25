import os

def main():
    for root, dirs, files in os.walk("backend"):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        for idx, line in enumerate(f, 1):
                            if "_upsert_lan_and_agent" in line:
                                print(f"{filepath} Line {idx}: {line.strip()}")
                except Exception:
                    pass

if __name__ == '__main__':
    main()
