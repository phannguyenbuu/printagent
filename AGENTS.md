@RTK.md

# Frontend Component Reuse Rule

Khi sinh code UI mới trong `app-gox/`, bắt buộc ưu tiên component cũ trước khi tạo component mới.

## Required Order

1. Kiểm tra component sẵn có trong:
   - `app-gox/src/components/requests/`
   - `app-gox/src/components/ui/`
   - `app-gox/src/components/layout/`
2. Ưu tiên mở rộng component cũ bằng props nhỏ, `children`, hoặc tách phần dùng chung ra từ component cũ.
3. Chỉ tạo component mới khi component hiện có không đáp ứng được mà không làm API của nó méo hoặc khó hiểu.

## Hard Rules

- Không copy-paste markup từ component đã tồn tại để dựng component mới gần giống.
- Không tạo badge/status/priority/request card/page state mới nếu có thể dùng lại:
  - `StatusBadge`
  - `PriorityBadge`
  - `RequestCard`
  - `RequestLocationBlock`
  - `StatusStatCard`
  - `PageLoading`
  - `EmptyState`
- Nếu cần tạo component mới, phải nêu ngắn gọn vì sao component cũ không đủ phù hợp.
- Nếu UI chỉ dùng ở một page, ưu tiên page-local subcomponent trước; chỉ promote thành shared component khi có ít nhất 2 chỗ dùng hoặc có khả năng reuse rõ ràng.
- Ưu tiên composition hơn duplication.

## Checklist Before Adding A New Component

- Đã tìm trong `app-gox/src/components/**`
- Đã kiểm tra có thể thêm prop vào component cũ chưa
- Đã kiểm tra có thể tách phần chung ra khỏi page hiện tại chưa
- Đã xác định component mới thực sự có reuse value

