#!/bin/bash
set -e

echo "Updating system..."
apt-get update
apt-get install -y python3-pip python3-venv nginx postgresql postgresql-contrib libpq-dev certbot python3-certbot-nginx screen

echo "Configuring PostgreSQL..."
# Configure postgres to allow local connections without password for setup
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'myPass';" || true
sudo -u postgres psql -c "CREATE DATABASE \"GoPrinx\";" || true

echo "Setting up Python environment..."
mkdir -p /opt/printagent
cd /opt/printagent
python3 -m venv venv
source venv/bin/activate
pip install -r server/requirements.txt
pip install gunicorn psycopg2-binary

echo "Configuring Nginx..."
cp /tmp/agentapi.quanlymay.com /etc/nginx/sites-available/
ln -sf /etc/nginx/sites-available/agentapi.quanlymay.com /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

echo "Creating systemd service..."
cat <<EOF > /etc/systemd/system/printagent.service
[Unit]
Description=PrintAgent Central Server
After=network.target postgresql.service

[Service]
User=root
WorkingDirectory=/opt/printagent
Environment="DATABASE_URL=postgresql+psycopg2://postgres:myPass@localhost:5432/GoPrinx"
Environment="LEAD_KEYS=default:change-me"
ExecStart=/opt/printagent/venv/bin/gunicorn --workers 4 --bind 127.0.0.1:8005 "app:create_app()"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable printagent
systemctl restart printagent

echo "Deployment complete!"
