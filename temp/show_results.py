import sys, csv
sys.stdout.reconfigure(encoding='utf-8')
with open('ricoh_drivers_v3.csv', encoding='utf-8-sig') as f:
    rows = list(csv.DictReader(f))
ok = [r for r in rows if r['PCL6'] or r['PCL6_Univ']]
print(f'Models with PCL6 driver: {len(ok)}\n')
for r in ok:
    n = len(r['all_exe'].split(' | ')) if r['all_exe'] else 0
    pcl6_short = r['PCL6'].split('/')[-1] if r['PCL6'] else '-'
    print(f"{r['model']:35s} | {n:2d} exe | PCL6: {pcl6_short}")
