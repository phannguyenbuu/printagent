bạn có thể# PrintAgent: Ricoh Printer Management System

## 🎯 Core Objective
Hệ thống giám sát và quản lý máy in Ricoh tập trung. Thu thập chỉ số (counters), trạng thái (status), và điều khiển từ xa (lock/unlock) cho nhiều máy in tại nhiều chi nhánh (LAN sites).

## 🏗 Architecture Overview
Dự án được chia làm 2 phần độc lập nhưng kết nối chặt chẽ:

### 1. Agent (`app/`) - Chạy tại Local Site
Dịch vụ chạy tại máy trạm/server nội bộ để giao tiếp trực tiếp với máy in.
- **Ricoh Module (`app/modules/ricoh/`):** Chứa logic "cào" dữ liệu từ giao diện web của máy in Ricoh, xử lý đăng nhập, lấy counter và thực hiện lệnh khóa máy.
- **Services (`app/services/`):**
    - `api_client.py`: Gửi data lên server chính.
    - `ws_client.py`: Duy trì kết nối WebSocket để nhận lệnh realtime (như lệnh update hoặc lock).
    - `updater.py`: Tự động cập nhật code agent qua Git.
- **Local UI (`app/web.py`):** Dashboard Flask cục bộ (Port 5000) để cấu hình IP máy in và xem trạng thái tại chỗ.

### 2. Server (`server/`) - Central Management Hub
Server trung tâm quản lý hàng nghìn máy in từ nhiều Agent khác nhau.
- **Ingestion API:** Nhận dữ liệu polling từ các Agent gửi lên.
- **Database (`server/models.py`):** Lưu trữ lịch sử counter, trạng thái online/offline, và log điều khiển.
- **Analytics UI:** Dashboard tổng hợp biểu đồ xu hướng (trend), bản đồ nhiệt (heatmap), và quản lý danh sách thiết bị.
- **Command Control:** Gửi lệnh khóa/mở khóa máy in xuống Agent thông qua API/WebSocket.

## 🔄 Core Workflows
1. **Polling:** Agent quét máy in -> Lấy thông tin -> Gửi JSON về Server qua `/api/polling`.
2. **Counter Baseline:** Server tính toán số bản in dựa trên "Baseline" (điểm mốc) để xử lý trường hợp máy in bị reset counter vật lý.
3. **Remote Control:** User bấm "Lock" trên Server -> Server tạo lệnh `pending` -> Agent lấy lệnh qua Polling API hoặc WS -> Thực hiện gọi API Ricoh -> Trả kết quả về Server.

## 🛠 Tech Stack
- **Language:** Python 3.11+
- **Framework:** Flask (cho cả Agent và Server)
- **Database:** SQLAlchemy (Hỗ trợ SQLite cho Agent và PostgreSQL/SQLite cho Server)
- **Communication:** REST API & WebSocket
- **Config:** YAML (`config.yaml`) & `.env`

## 📂 Key File Map
- `app/main.py`: Điểm khởi đầu của Agent (chế độ: web, service, test).
- `server/app.py`: Điểm khởi đầu của Server trung tâm.
- `app/modules/ricoh/service.py`: Logic "xương sống" tương tác với máy in Ricoh.
- `server/models.py`: Định nghĩa cấu trúc dữ liệu toàn hệ thống.
