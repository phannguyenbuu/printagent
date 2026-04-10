import re

with open('app-gox/src/pages/AgentPage.tsx', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove the 'downloads', 'Tải Agent' tab item
content = content.replace(
    "['downloads', '📥 Tải Agent']",
    ""
)

# Fix empty array spot if there was a comma: [['agents', '🖥️ Máy tính'], ['copiers', '🖨️ Photocopy'], ]
content = content.replace(
    "['copiers', '🖨️ Photocopy'], ]",
    "['copiers', '🖨️ Photocopy']]"
)

with open('app-gox/src/pages/AgentPage.tsx', 'w', encoding='utf-8') as f:
    f.write(content)

print("Removed downloads tab.")
