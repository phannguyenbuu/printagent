# Kế hoạch Kiểm thử (Test Case)

Hệ thống GoPrinx Printer Management.

## 1. Kiểm thử Agent (Local)
- **TC-AG-01:** Khởi động Agent lần đầu, kiểm tra việc tạo file DB local và kết nối Server.
- **TC-AG-02:** Quét mạng (Scan LAN) tìm thấy máy in Ricoh đúng dải IP.
- **TC-AG-03:** Lấy dữ liệu Counter thành công từ máy in mẫu.
- **TC-AG-04:** Gửi dữ liệu Polling về Server (Backend) qua API.
- **TC-AG-05:** Thực hiện lệnh Lock/Unlock từ giao diện local.

## 2. Kiểm thử Server Backend (VPS)
- **TC-SV-01:** Nhận dữ liệu Ingestion từ Agent và lưu vào database PostgreSQL.
- **TC-SV-02:** Tính toán Counter Baseline khi máy in bị reset counter vật lý.
- **TC-SV-03:** Gửi lệnh điều khiển xuống Agent qua WebSocket/Polling.
- **TC-SV-04:** API cho CRM bên thứ 3 trả về đúng cấu trúc JSON.

## 3. Kiểm thử Frontend (User UI)
- **TC-FE-01:** Đăng nhập với các vai trò khác nhau (Admin, Kỹ thuật).
- **TC-FE-02:** Hiển thị danh sách Agent và trạng thái Online/Offline thực tế.
- **TC-FE-03:** Thêm/Sửa/Xóa (CRUD) Địa điểm thành công.
- **TC-FE-04:** Tải file `GoPrinxAgent.exe` từ trang Downloads thành công.
- **TC-FE-05:** Xem biểu đồ xu hướng (Heatmap) counter theo thời gian.

## 4. Kiểm thử Tích hợp (End-to-End)
- **TC-E2E-01:** Khóa máy photocopy từ Frontend -> Server -> Agent -> Máy in thực tế -> Trạng thái cập nhật lại trên Frontend.
