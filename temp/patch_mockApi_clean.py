import re

with open('app-gox/src/api/mockApi.ts', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. BASE_URL
text = text.replace(
    "const BASE_URL = 'https://agentapi.quanlymay.com';",
    "const BASE_URL = import.meta.env.VITE_API_URL || 'https://agentapi.quanlymay.com';"
)

# 2. Add X-Lead-Token to all fetch operations globally inside fetchApi block
text = text.replace(
    "'Content-Type': 'application/json',",
    "'Content-Type': 'application/json',\n      'X-Lead-Token': 'change-me',"
)

# 3. Inject lead + agent_uid into mockCreateRequest (the body status array)
text = text.replace(
    "status: 'backlog'",
    "status: 'backlog',\n      lead: 'default',\n      agent_uid: 'frontend'"
)

# 4 & 5. Inject lead into mockUpdateStatus URL and JSON payload
text = text.replace(
    "fetchApi(`/api/tasks/${requestId}`",
    "fetchApi(`/api/tasks/${requestId}?lead=default`"
)

text = re.sub(
    r"(status:\s*s_map\[newStatus\]\s*\|\|\s*newStatus,)",
    r"\1 lead: 'default',",
    text
)

with open('app-gox/src/api/mockApi.ts', 'w', encoding='utf-8') as f:
    f.write(text)

print("Patch applied to mockApi.ts fully.")
