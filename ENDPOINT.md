# PrintAgent Public CRM API

API này dùng để xuất dữ liệu máy in cho hệ thống CRM.

## Public CRM API
Kết nối bảo mật qua HTTP Server để lấy dữ liệu: counter, status, ip, mac, toner.

- **Endpoint:** `GET /api/public/crm/printers`
- **Xác thực:** 
    - Header: `X-Lead-Token: <token_của_lead>`
    - Query Param: `lead=<tên_lead>`

### Cấu trúc dữ liệu trả về (JSON):
```json
{
  "ok": true,
  "printers": [
    {
      "lan_uid": "...",
      "agent_uid": "...",
      "lan_name": "...",
      "hostname": "...",
      "printer_name": "...",
      "ip": "...",
      "mac": "...",
      "counter": 12345,
      "status": "...",
      "alerts": "...",
      "toner": "...",
      "last_seen_at": "..."
    }
  ]
}
```

*Ghi chú: Các API nội bộ khác dành cho Agent và Dashboard không được liệt kê ở đây để tránh nhầm lẫn.*
