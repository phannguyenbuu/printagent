# GoPrinx Agent Documentation

Tài liệu chi tiết về thành phần Agent chạy tại mạng LAN nội bộ.

## 🛠 Chức năng chính
Agent là một service chạy ngầm (hoặc có giao diện) trên Windows, thực hiện:
1. **Auto-Discovery:** Quét mạng LAN để tìm máy in Ricoh (qua SNMP/HTTP).
2. **Data Polling:** Định kỳ truy cập Web UI của máy in để "cào" (scrape) dữ liệu:
    - Counters (Total, Copier, Printer, Scan).
    - Status (Online/Offline, Alerts, Toner levels).
3. **Remote Control:** Nhận lệnh từ Server để:
    - **Lock:** Vô hiệu hóa chức năng copy/print trên máy in.
    - **Unlock:** Kích hoạt lại máy in.
4. **Data Sync:** Gửi dữ liệu về Server trung tâm qua REST API.

## 📂 Cấu trúc thư mục `agent/`
- `main.py`: Khởi chạy Agent (chế độ CLI hoặc Service).
- `web.py`: Cung cấp giao diện cấu hình cục bộ (http://localhost:5000).
- `models.py`: Cấu trúc database SQLite lưu trữ cấu hình tại chỗ.
- `modules/ricoh/`:
    - `service.py`: Logic cốt lõi điều khiển máy in.
    - `collector.py`: Thu thập chỉ số counter.
    - `control.py`: Thực hiện lệnh Lock/Unlock.
- `services/`:
    - `api_client.py`: Giao tiếp HTTP với Server VPS.
    - `ws_client.py`: Duy trì kết nối WebSocket để nhận lệnh thời gian thực.
    - `polling_bridge.py`: Cầu nối điều phối giữa quét máy và gửi dữ liệu.

## ⚙️ Cấu hình
File cấu hình `config.yaml` chứa:
- `server_url`: Địa chỉ của VPS Backend.
- `lead_id`: Định danh khách hàng.
- `agent_id`: Định danh duy nhất cho máy trạm này.
- `polling_interval`: Tần suất gửi dữ liệu (mặc định 300 giây).
