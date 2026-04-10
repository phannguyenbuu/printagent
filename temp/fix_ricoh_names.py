import json

DRIVER_NAME_MAP = {
    'PCL6':      'PCL 6 Driver',
    'PCL6_Univ': 'PCL6 Driver for Universal Print',
    'PS3':       'PostScript3 Driver',
    'PS3_Univ':  'PostScript3 Driver for Universal Print',
    'PCL5':      'Generic PCL5 Driver',
}

with open('backend/storage/drivers/ricoh.json', encoding='utf-8') as f:
    data = json.load(f)

updated = 0
for m in data:
    old_drivers = m.get('drivers', {})
    if not old_drivers:
        continue
    new_drivers = {}
    for key, url in old_drivers.items():
        new_key = DRIVER_NAME_MAP.get(key, key)
        new_drivers[new_key] = url
        if new_key != key:
            updated += 1
    m['drivers'] = new_drivers

print(f'Updated {updated} driver name entries across {len(data)} models')

with open('backend/storage/drivers/ricoh.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

sample = next(m for m in data if m.get('drivers'))
print(f'\nSample [{sample["model"]}]:')
for k in sample['drivers']:
    print(f'  - {k}')
print('\nDONE')
