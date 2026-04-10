#!/bin/bash

# Script tự động cập nhật Database và restart Backend
echo "--- Bắt đầu cập nhật hệ thống ---"

# 1. Đi vào thư mục server
cd "$(dirname "$0")/server"

# 2. Kích hoạt môi trường ảo (nếu có)
if [ -d "../venv" ]; then
    source ../venv/bin/activate
elif [ -d "venv" ]; then
    source venv/bin/activate
fi

# 3. Cài đặt các thư viện mới nếu có
pip install -r requirements.txt

# 4. Chạy script khởi tạo/cập nhật DB
# Trong server/app.py của bạn đã có cơ chế "Self-heal schema drift" 
# bằng cách chạy Base.metadata.create_all() và các lệnh ALTER TABLE.
# Chúng ta sẽ chạy trực tiếp app để nó tự cập nhật.
echo "Đang kiểm tra và cập nhật cấu trúc Database..."
python -c "from app import create_app; app = create_app()"

echo "--- Cập nhật Database hoàn tất ---"

# 5. Restart service (Giả sử bạn dùng systemd với tên service là printagent-server)
# sudo systemctl restart printagent-server

echo "--- Hệ thống đã sẵn sàng ---"
