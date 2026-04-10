import sys, csv, json
sys.stdout.reconfigure(encoding='utf-8')

with open('ricoh_drivers_v3.csv', encoding='utf-8-sig') as f:
    rows = list(csv.DictReader(f))

result = []
for r in rows:
    # Bỏ qua nếu không có bất kỳ driver nào
    if not any(r.get(k) for k in ['PCL6', 'PCL6_Univ', 'PCL6_V4', 'PCL5', 'PS3', 'PS3_Univ']):
        continue

    # Parse all_exe thành list
    all_exe = [x.strip() for x in r.get('all_exe', '').split('|') if x.strip()]

    entry = {
        "id": int(r['stt']),
        "model": r['model'].strip(),
        "support_url": r.get('support_url', '').strip(),
        "drivers": {
            "PCL6":      r.get('PCL6', '').strip() or None,
            "PCL6_Univ": r.get('PCL6_Univ', '').strip() or None,
            "PCL6_V4":   r.get('PCL6_V4', '').strip() or None,
            "PCL5":      r.get('PCL5', '').strip() or None,
            "PS3":       r.get('PS3', '').strip() or None,
            "PS3_Univ":  r.get('PS3_Univ', '').strip() or None,
        },
        "all_exe": all_exe,
        "total_files": len(all_exe),
    }
    # Xóa key None trong drivers
    entry['drivers'] = {k: v for k, v in entry['drivers'].items() if v}
    result.append(entry)

with open('ricoh_drivers.json', 'w', encoding='utf-8') as f:
    json.dump(result, f, ensure_ascii=False, indent=2)

print(f"Done: {len(result)} models exported to ricoh_drivers.json")
