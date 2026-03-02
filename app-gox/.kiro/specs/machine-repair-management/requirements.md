# Tài liệu Yêu cầu: Quản lý Sửa chữa Máy móc

## Giới thiệu

Ứng dụng mobile React.js để tiếp nhận và quản lý thông tin sửa chữa, bảo trì máy móc tại nhiều địa điểm. Ứng dụng phục vụ hai nhóm người dùng chính: nhà cung cấp máy và nhân viên kỹ thuật. Giao diện được thiết kế theo phong cách AI Neuralink với hiệu ứng animation đẹp mắt, theme tối, hiệu ứng phát sáng và hạt particle.

## Thuật ngữ

- **Hệ_thống**: Ứng dụng mobile React.js quản lý sửa chữa máy móc
- **Nhà_cung_cấp**: Người dùng có vai trò nhà cung cấp máy, có quyền tạo và theo dõi yêu cầu sửa chữa
- **Kỹ_thuật_viên**: Người dùng có vai trò nhân viên kỹ thuật, có quyền nhận và xử lý yêu cầu sửa chữa
- **Yêu_cầu_sửa_chữa**: Một phiếu yêu cầu sửa chữa/bảo trì máy móc, chứa thông tin máy, vị trí, mô tả lỗi và trạng thái
- **Địa_điểm**: Một vị trí/chi nhánh nơi máy móc được lắp đặt và cần sửa chữa
- **Trạng_thái**: Tình trạng hiện tại của yêu cầu sửa chữa (Mới tạo, Đã tiếp nhận, Đang xử lý, Hoàn thành, Đã hủy)
- **Dashboard**: Bảng điều khiển tổng quan hiển thị thống kê và danh sách yêu cầu sửa chữa
- **Bộ_xác_thực**: Module xác thực danh tính và phân quyền người dùng
- **Vật_tư**: Phụ tùng, linh kiện thay thế được sử dụng trong quá trình sửa chữa, bao gồm tên, số lượng và đơn giá
- **Lịch_sử_sửa_chữa**: Bản ghi toàn bộ các lần sửa chữa đã thực hiện trên một máy móc, bao gồm thời gian, nội dung và chi phí

## Yêu cầu

### Yêu cầu 1: Xác thực và Phân quyền Người dùng

**User Story:** Là một người dùng, tôi muốn đăng nhập vào hệ thống với vai trò phù hợp, để tôi có thể truy cập các chức năng tương ứng với quyền hạn của mình.

#### Tiêu chí chấp nhận

1. WHEN một người dùng nhập thông tin đăng nhập hợp lệ, THE Bộ_xác_thực SHALL xác thực danh tính và chuyển hướng đến Dashboard tương ứng với vai trò (Nhà_cung_cấp hoặc Kỹ_thuật_viên)
2. WHEN một người dùng nhập thông tin đăng nhập không hợp lệ, THE Bộ_xác_thực SHALL hiển thị thông báo lỗi cụ thể và giữ nguyên trang đăng nhập
3. WHILE một Nhà_cung_cấp đã đăng nhập, THE Hệ_thống SHALL chỉ hiển thị các chức năng dành cho Nhà_cung_cấp (tạo yêu cầu, theo dõi trạng thái, xem lịch sử)
4. WHILE một Kỹ_thuật_viên đã đăng nhập, THE Hệ_thống SHALL chỉ hiển thị các chức năng dành cho Kỹ_thuật_viên (nhận yêu cầu, cập nhật tiến độ, báo cáo hoàn thành)
5. WHEN phiên đăng nhập hết hạn, THE Bộ_xác_thực SHALL tự động chuyển hướng về trang đăng nhập và thông báo cho người dùng

### Yêu cầu 2: Quản lý Yêu cầu Sửa chữa (Nhà cung cấp)

**User Story:** Là một Nhà_cung_cấp, tôi muốn tạo và quản lý yêu cầu sửa chữa máy móc, để tôi có thể thông báo cho đội kỹ thuật về các sự cố cần xử lý.

#### Tiêu chí chấp nhận

1. WHEN một Nhà_cung_cấp tạo yêu cầu sửa chữa mới với đầy đủ thông tin (tên máy, Địa_điểm, mô tả lỗi, mức độ ưu tiên), THE Hệ_thống SHALL lưu Yêu_cầu_sửa_chữa với Trạng_thái "Mới tạo" và gán mã định danh duy nhất
2. WHEN một Nhà_cung_cấp tạo yêu cầu sửa chữa thiếu thông tin bắt buộc, THE Hệ_thống SHALL hiển thị thông báo lỗi chỉ rõ các trường còn thiếu và không lưu yêu cầu
3. WHEN một Nhà_cung_cấp đính kèm hình ảnh hoặc video vào yêu cầu sửa chữa, THE Hệ_thống SHALL tải lên và liên kết tệp đính kèm với Yêu_cầu_sửa_chữa tương ứng
4. WHEN một Nhà_cung_cấp xem danh sách yêu cầu sửa chữa, THE Hệ_thống SHALL hiển thị danh sách được sắp xếp theo thời gian tạo (mới nhất trước) và cho phép lọc theo Trạng_thái, Địa_điểm
5. WHEN Trạng_thái của một Yêu_cầu_sửa_chữa thay đổi, THE Hệ_thống SHALL gửi thông báo cho Nhà_cung_cấp đã tạo yêu cầu đó

### Yêu cầu 3: Xử lý Yêu cầu Sửa chữa (Kỹ thuật viên)

**User Story:** Là một Kỹ_thuật_viên, tôi muốn nhận và xử lý các yêu cầu sửa chữa, để tôi có thể thực hiện công việc bảo trì máy móc hiệu quả.

#### Tiêu chí chấp nhận

1. WHEN một Kỹ_thuật_viên xem danh sách yêu cầu sửa chữa được phân công, THE Hệ_thống SHALL hiển thị danh sách được sắp xếp theo mức độ ưu tiên và cho phép lọc theo Địa_điểm, Trạng_thái
2. WHEN một Kỹ_thuật_viên tiếp nhận một Yêu_cầu_sửa_chữa, THE Hệ_thống SHALL cập nhật Trạng_thái thành "Đã tiếp nhận" và ghi nhận thời gian tiếp nhận
3. WHEN một Kỹ_thuật_viên cập nhật tiến độ sửa chữa, THE Hệ_thống SHALL cập nhật Trạng_thái thành "Đang xử lý" và lưu ghi chú tiến độ kèm thời gian
4. WHEN một Kỹ_thuật_viên hoàn thành sửa chữa và gửi báo cáo (mô tả công việc đã thực hiện, phụ tùng thay thế, hình ảnh sau sửa chữa), THE Hệ_thống SHALL cập nhật Trạng_thái thành "Hoàn thành" và lưu báo cáo hoàn thành
5. WHEN một Kỹ_thuật_viên cập nhật tiến độ mà thiếu ghi chú mô tả, THE Hệ_thống SHALL hiển thị thông báo yêu cầu nhập ghi chú và không lưu cập nhật

### Yêu cầu 4: Quản lý Đa Địa điểm

**User Story:** Là một người dùng, tôi muốn quản lý thông tin sửa chữa theo từng địa điểm, để tôi có thể theo dõi tình trạng máy móc tại mỗi chi nhánh.

#### Tiêu chí chấp nhận

1. THE Hệ_thống SHALL hiển thị danh sách tất cả Địa_điểm mà người dùng có quyền truy cập
2. WHEN một người dùng chọn một Địa_điểm, THE Hệ_thống SHALL lọc và hiển thị chỉ các Yêu_cầu_sửa_chữa thuộc Địa_điểm đó
3. WHEN một người dùng xem Dashboard, THE Hệ_thống SHALL hiển thị thống kê tổng hợp (số yêu cầu theo Trạng_thái) cho tất cả Địa_điểm mà người dùng có quyền truy cập
4. WHEN một người dùng chuyển đổi giữa các Địa_điểm, THE Hệ_thống SHALL cập nhật dữ liệu hiển thị trong vòng 1 giây

### Yêu cầu 5: Dashboard và Thống kê

**User Story:** Là một người dùng, tôi muốn xem tổng quan về tình trạng sửa chữa, để tôi có thể nắm bắt nhanh tình hình và đưa ra quyết định kịp thời.

#### Tiêu chí chấp nhận

1. WHEN một người dùng truy cập Dashboard, THE Hệ_thống SHALL hiển thị số lượng Yêu_cầu_sửa_chữa theo từng Trạng_thái dưới dạng biểu đồ trực quan
2. WHEN một người dùng truy cập Dashboard, THE Hệ_thống SHALL hiển thị danh sách các Yêu_cầu_sửa_chữa gần đây (tối đa 10 yêu cầu mới nhất)
3. WHEN dữ liệu trên Dashboard thay đổi, THE Hệ_thống SHALL cập nhật biểu đồ và danh sách theo thời gian thực
4. WHEN một người dùng nhấn vào một Yêu_cầu_sửa_chữa trên Dashboard, THE Hệ_thống SHALL chuyển đến trang chi tiết của yêu cầu đó

### Yêu cầu 6: Giao diện AI Neuralink

**User Story:** Là một người dùng, tôi muốn sử dụng ứng dụng với giao diện hiện đại theo phong cách AI Neuralink, để tôi có trải nghiệm sử dụng hấp dẫn và chuyên nghiệp.

#### Tiêu chí chấp nhận

1. THE Hệ_thống SHALL sử dụng theme tối (dark theme) làm giao diện mặc định với bảng màu chủ đạo gồm đen, xanh dương neon và tím
2. WHEN các thành phần giao diện được tải, THE Hệ_thống SHALL hiển thị hiệu ứng animation mượt mà (fade-in, slide-in, scale) với thời gian chuyển đổi từ 200ms đến 500ms
3. THE Hệ_thống SHALL hiển thị hiệu ứng particle animation trên nền trang Dashboard mô phỏng mạng neural
4. WHEN người dùng tương tác với các nút bấm và thẻ thông tin, THE Hệ_thống SHALL hiển thị hiệu ứng phát sáng (glow effect) và ripple animation
5. THE Hệ_thống SHALL đảm bảo tất cả animation chạy mượt mà ở tốc độ tối thiểu 60 khung hình/giây trên thiết bị di động
6. WHEN hiển thị biểu đồ thống kê, THE Hệ_thống SHALL sử dụng hiệu ứng animation vẽ dần (draw animation) cho các đường và cột biểu đồ

### Yêu cầu 7: Quản lý Vật tư Thay thế

**User Story:** Là một Kỹ_thuật_viên, tôi muốn ghi nhận vật tư thay thế kèm đơn giá khi sửa chữa, để tôi có thể theo dõi chi phí và quản lý phụ tùng chính xác.

#### Tiêu chí chấp nhận

1. WHEN một Kỹ_thuật_viên thêm Vật_tư vào Yêu_cầu_sửa_chữa, THE Hệ_thống SHALL lưu thông tin vật tư bao gồm tên vật tư, số lượng và đơn giá
2. WHEN một Kỹ_thuật_viên thêm nhiều Vật_tư vào một Yêu_cầu_sửa_chữa, THE Hệ_thống SHALL tính tổng chi phí vật tư bằng tổng của (số lượng nhân đơn giá) cho mỗi Vật_tư
3. WHEN một Kỹ_thuật_viên nhập đơn giá hoặc số lượng không hợp lệ (số âm, bằng 0, hoặc không phải số), THE Hệ_thống SHALL hiển thị thông báo lỗi và không lưu Vật_tư
4. WHEN một người dùng xem chi tiết Yêu_cầu_sửa_chữa đã hoàn thành, THE Hệ_thống SHALL hiển thị danh sách Vật_tư đã sử dụng kèm đơn giá, số lượng và tổng chi phí
5. WHEN một Kỹ_thuật_viên chỉnh sửa hoặc xóa Vật_tư đã thêm, THE Hệ_thống SHALL cập nhật lại tổng chi phí vật tư tương ứng

### Yêu cầu 8: Lịch sử Sửa chữa

**User Story:** Là một người dùng, tôi muốn xem lịch sử sửa chữa của từng máy móc, để tôi có thể theo dõi tình trạng bảo trì và đưa ra quyết định thay thế thiết bị khi cần.

#### Tiêu chí chấp nhận

1. WHEN một người dùng chọn xem lịch sử sửa chữa của một máy, THE Hệ_thống SHALL hiển thị danh sách tất cả Yêu_cầu_sửa_chữa đã hoàn thành của máy đó, sắp xếp theo thời gian (mới nhất trước)
2. WHEN một người dùng xem chi tiết một lần sửa chữa trong lịch sử, THE Hệ_thống SHALL hiển thị đầy đủ thông tin bao gồm: ngày sửa, Kỹ_thuật_viên thực hiện, mô tả công việc, danh sách Vật_tư đã dùng và tổng chi phí
3. WHEN một người dùng tìm kiếm trong lịch sử sửa chữa, THE Hệ_thống SHALL cho phép lọc theo khoảng thời gian, Địa_điểm và tên máy
4. THE Hệ_thống SHALL tính và hiển thị tổng chi phí sửa chữa tích lũy cho mỗi máy dựa trên Lịch_sử_sửa_chữa

### Yêu cầu 9: Thiết kế Mobile-First và Responsive

**User Story:** Là một người dùng, tôi muốn sử dụng ứng dụng trên thiết bị di động một cách thuận tiện, để tôi có thể quản lý công việc sửa chữa mọi lúc mọi nơi.

#### Tiêu chí chấp nhận

1. THE Hệ_thống SHALL hiển thị giao diện tối ưu cho màn hình di động với chiều rộng từ 320px đến 428px
2. WHEN người dùng vuốt (swipe) trên danh sách yêu cầu sửa chữa, THE Hệ_thống SHALL hỗ trợ thao tác vuốt để thực hiện hành động nhanh (vuốt trái để xem chi tiết, vuốt phải để cập nhật trạng thái)
3. THE Hệ_thống SHALL sử dụng thanh điều hướng dưới cùng (bottom navigation bar) với các mục: Dashboard, Yêu cầu, Địa điểm, Tài khoản
4. WHEN người dùng kéo xuống (pull-to-refresh) trên danh sách, THE Hệ_thống SHALL tải lại dữ liệu mới nhất và hiển thị animation loading theo phong cách neural
