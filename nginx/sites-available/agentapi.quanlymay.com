server {
    listen 80;
    server_name agentapi.quanlymay.com;

    # Redirect all HTTP requests to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name agentapi.quanlymay.com;

    # SSL Configuration (Certbot will usually fill these paths)
    # ssl_certificate /etc/letsencrypt/live/agentapi.quanlymay.com/fullchain.pem; # managed by Certbot
    # ssl_certificate_key /etc/letsencrypt/live/agentapi.quanlymay.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

    # Main Site Page (Dashboard)
    location / {
        proxy_pass http://localhost:8005;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # API Endpoints
    location /api {
        proxy_pass http://localhost:8005/api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeout settings for long-running API requests
        proxy_read_timeout 60s;
        proxy_connect_timeout 60s;
    }

    # Static files (optional, if Flask doesn't serve them well)
    # location /static {
    #     alias /path/to/your/printagent/server/static;
    # }
}
