import sys, requests, re
sys.stdout.reconfigure(encoding='utf-8')

TARGET_OS_KEYWORDS = ['windows 10 (64', 'windows 11 (64']
SESSION = requests.Session()
SESSION.headers.update({'User-Agent': 'Mozilla/5.0'})

support_url = 'https://support.ricoh.com/bb/html/dr_ut_e/re2/model/imc320f/imc320fen.htm'
resp = SESSION.get(support_url, timeout=20)
html = resp.text

os_pos = -1
for kw in TARGET_OS_KEYWORDS:
    idx = html.lower().find(kw)
    if idx != -1:
        os_pos = idx
        break

search_html = html[os_pos:os_pos + 15000] if os_pos != -1 else html
print('os_pos:', os_pos, '| search_html len:', len(search_html))

def find_pcl6_exe(html_chunk, label_kw):
    chunk_lower = html_chunk.lower()
    pos = 0
    while True:
        idx = chunk_lower.find(label_kw.lower(), pos)
        if idx == -1:
            return ''
        window = html_chunk[idx:idx + 600]
        m = re.search(r'href=["\']?(https://support\.ricoh\.com/bb/pub_e/[^"\'>\s]+\.exe)', window, re.I)
        if m:
            return m.group(1)
        pos = idx + 1

link = find_pcl6_exe(search_html, 'PCL 6 Driver')
print('PCL6 link:', link or 'NOT FOUND')
