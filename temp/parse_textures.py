import re, json, html
from pathlib import Path
text = Path('sketch.html').read_text('utf8')
match = re.search(r'id=" js-dom-data-prefetched-data\[^>]*><!--(.*?)--><\/div>', text, re.S)
if not match:
 raise SystemExit('prefetched data not found')
payload = match.group(1)
payload = html.unescape(payload)
data = json.loads(payload)
models = {k: v for k, v in data.items() if k.startswith('/i/models/')}
print('models count', len(models))
for key, model in models.items():
 print('model key', key)
 print(' top keys', list(model.keys()))
 textures = []
 def walk(node, path=''):
 if isinstance(node, dict):
 for sub_key, value in node.items():
 if sub_key.lower() == 'textures' and isinstance(value, list):
 textures.append((path + '/' + sub_key, value))
 walk(value, path + '/' + sub_key)
 elif isinstance(node, list):
 for idx, value in enumerate(node):
 walk(value, path + f'[{idx}]')
 walk(model)
 print(' textures count', len(textures))
 if textures:
 for path, items in textures[:3]:
 print(' ', path, 'len', len(items))
