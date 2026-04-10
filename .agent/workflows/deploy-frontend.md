---
description: Build và deploy frontend app-gox lên VPS
---
// turbo-all

1. Build frontend
```
cmd /c "cd app-gox && npm run build"
```

2. Deploy lên VPS
```
python deploy_frontend.py
```
