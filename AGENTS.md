tôi sẽ giải thích thêm, hiện giờ có 2 nhánh chính: 1 là agent chạy trên máy PC kết nối máy photo, 1 là server chạy trên vps, agent sẽ polling để gửi data và các lệnh điều khiển về vps


Vâng, tôi hiểu rồi. Mô hình của bạn gồm hai thành phần rõ ràng:

Agent (app/): Chạy tại các local site (như trên máy PC của bạn), làm nhiệm vụ quét mạng, kết nối trực tiếp với các máy in Ricoh trong mạng LAN đó, lấy thông tin theo lịch (polling) và gửi dữ liệu thu được lên Server trung tâm qua API /api/polling. Nó cũng nhận chỉ thị từ server thông qua WebSocket hoặc kết quả trả về của Polling.
Server (server/): Chạy trên VPS, đóng vai trò là Central Management Hub để tiếp nhận dữ liệu từ các Agent, lưu trữ vào Database, hiển thị Dashboard tổng quát và phát lệnh điều khiển remote trở lại các Agent.
Hiện tại, việc sửa lỗi báo văng 500 Internal Server Error từ kết nối offline/máy IP nhầm lẫn cho 

service.py
 đã giải quyết vấn đề sập tiến trình, để công việc Polling của Agent diễn ra trơn tru dù gặp máy "chết" hoặc bị trễ mạng (timeout). Đồng thời, nguyên do máy Agent liên tục cố quét IP 192.168.1.222 là do ở PC đó đang cài cục bộ (local) một máy in trỏ đến port/IP đó.

Bạn đang cần giải quyết tiếp vấn đề gì liên quan tới kiến trúc này, hay gặp lỗi gì khác khi Agent giao tiếp với Server (vps) không? (Ví dụ: dữ liệu counter gửi lên không đúng, lệnh điều khiển (Lock/Unlock) từ server đánh xuống Agent không thực thi được,...?)

hiện giờ data khi polling sẽ được save lại tại database, bạn tạo cho tôi ở server các api công khai để 1 CRM có thể đọc là nhận thông tin bao gồm: list số máy photo kết nối máy PC đó (nhớ có các key để lưu tên mạng lan, tên máy theo finger), Mac address, tổng counter đã in đen trắng, ip, status, alert, toner




Tạo bộ API công khai cho CRM trên Server
CRM cần đọc thông tin máy photo của một Agent. Cần tạo 1 public API trên HTTP Server để xuất dữ liệu counter, status, ip, mac, toner. Đang đọc server/models.py để hiểu database schema.

Progress Updates
1
Đang kiểm tra CSDL Server để thiết kế Public API trả về dữ liệu Polling cho bên thứ 3 (CRM)

2
Tìm hiểu nơi lưu MAC address trên Server