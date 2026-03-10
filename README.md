# PrintAgent: Ricoh Printer Management System

Hệ thống giám sát và quản lý máy in Ricoh tập trung. Thu thập chỉ số (counters), trạng thái (status), và điều khiển từ xa (lock/unlock) cho nhiều máy in tại nhiều chi nhánh (LAN sites).

## 🏗 Kiến trúc hệ thống

Dự án được chia làm 3 phần chính:

### 1. Agent (`agent/`) - Chạy tại Local Site (Máy trạm/Server nội bộ)
Dịch vụ Python duy trì kết nối trực tiếp với máy in trong mạng LAN.
- **Tính năng:** Quét thiết bị, lấy counter, cập nhật trạng thái, thực hiện lệnh khóa máy (Lock/Unlock).
- **Công nghệ:** Python 3.11+, Flask (Local UI), SQLAlchemy (SQLite).
- **File chính:**
    - `agent/main.py`: Entry point cho dịch vụ agent.
    - `agent/web.py`: Dashboard cục bộ (Port 5000).
    - `agent/modules/ricoh/`: Logic tương tác với máy in Ricoh.

### 2. Server Backend (`server/`) - Trung tâm điều hành (VPS)
Hệ thống xử lý trung tâm nhận dữ liệu từ hàng nghìn Agent.
- **Tính năng:** Ingestion API, Quản lý Database, Command Control (WebSocket/Polling), Analytics.
- **Công nghệ:** Flask, PostgreSQL/SQLite, SQLAlchemy.
- **File chính:**
    - `server/app.py`: API chính và quản lý Dashboard Backend.
    - `server/models.py`: Định nghĩa cấu trúc dữ liệu toàn hệ thống.
    - `server/utils.py` & `server/serializers.py`: Các hàm tiện ích và xử lý dữ liệu.

### 3. Frontend Web (`app-gox/`) - Giao diện hiện đại (React)
Trang quản trị dành cho người dùng và kỹ thuật viên.
- **Tính năng:** Theo dõi trực quan, quản lý Agent, máy photocopy, địa điểm, và yêu cầu sửa chữa.
- **Công nghệ:** React, TypeScript, Vite, Framer Motion.

## 🚀 Cài đặt nhanh

### Agent (Dành cho máy khách)
1. Tải bộ cài `GoPrinxAgent.exe` từ [app.goxprint.com/downloads](http://app.goxprint.com/downloads).
2. Chạy với quyền Admin và nhập **Agent ID** tương ứng.

### Server & Frontend (Dành cho Dev)
- Backend: `cd server && python app.py`
- Frontend: `cd app-gox && npm install && npm run dev`

## 📂 Sơ đồ thư mục
- `agent/`: Mã nguồn của phần mềm Agent chạy tại site.
- `server/`: Mã nguồn Flask Backend chạy trên VPS.
- `app-gox/`: Mã nguồn React Frontend.
- `dist/`: Chứa file `GoPrinxAgent.exe` đã build.
- `storage/`: Dữ liệu local, logs và cache.
