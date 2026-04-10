import json
with open('toshiba_drivers.json') as f:
    data = json.load(f)
print(f'Total models with Windows drivers: {len(data)}')
for m in data[:5]:
    print(f"\nModel: {m['model']} ({m['category']})")
    for d in m['drivers']:
        print(f"  - {d['name']}: {d['filename']}")
        print(f"    URL: {d['download_url']}")
