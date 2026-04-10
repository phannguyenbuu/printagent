import re

with open('app-gox/src/api/mockApi.ts', 'r', encoding='utf-8') as f:
    content = f.read()

# Make fetchApi always include X-Lead-Token
content = content.replace("headers: {", "headers: {\n      'X-Lead-Token': 'change-me',")

# Inject 'lead' and 'agent_uid' into mockCreateRequest
content = re.sub(
    r"lead: 'default',\s*status: 'backlog'",
    "lead: 'default', agent_uid: 'frontend', status: 'backlog'",
    content
)

# Inject 'lead' into mockUpdateStatus
content = re.sub(
    r"status:\s*s_map\[newStatus\]\s*\|\|\s*newStatus,",
    "status: s_map[newStatus] || newStatus, lead: 'default',",
    content
)

# Inject lead into the URL
content = content.replace("fetchApi(`/api/tasks/${requestId}`", "fetchApi(`/api/tasks/${requestId}?lead=default`")

with open('app-gox/src/api/mockApi.ts', 'w', encoding='utf-8') as f:
    f.write(content)

print("Patch applied.")
