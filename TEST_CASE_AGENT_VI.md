# TEST CASE AGENT (TIENG VIET)

Tai lieu nay mo ta cac test case cho Agent chay tren PC ket noi may photo Ricoh, thuc hien polling ve server trung tam.

## 1) Cau hinh va khoi dong

| ID | Muc tieu | Tien dieu kien | Buoc test | Ket qua mong doi |
|---|---|---|---|---|
| AG-001 | Agent doc `config.yaml` hop le | Co file `config.yaml` dung format | Chay `python -m app.main --mode service` | Agent khoi dong thanh cong, khong loi parse config |
| AG-002 | Agent xu ly thieu config | Doi ten `config.yaml` | Chay agent | Bao loi ro rang `Config file not found` |
| AG-003 | Override bang `.env` | Co ca `.env` va `config.yaml` | Set `POLLING_URL` trong `.env`, chay agent | Agent dung gia tri tu `.env` thay vi config |
| AG-004 | Chay web mode | Port chua bi chiem | Chay `--mode web` | Truy cap duoc dashboard local |
| AG-005 | Chay exe khong can Python | Build `dist/printagent.exe` | Chay `printagent.exe --mode service` tren may khong cai Python | Agent chay binh thuong |

## 2) Polling server

| ID | Muc tieu | Tien dieu kien | Buoc test | Ket qua mong doi |
|---|---|---|---|---|
| AG-006 | Gui polling thanh cong | Server online, token dung | Chay agent service, cho 1 chu ky | Server nhan ban ghi `counter/status`, HTTP 200 |
| AG-007 | Token sai | Token sai trong config | Cho polling | Agent khong crash, log loi 401 ro rang |
| AG-008 | Server tam offline | Tat server | Cho polling 2-3 chu ky | Agent tiep tuc chay, retry o chu ky sau |
| AG-009 | Mang chap chon/timeout | Gia lap timeout | Cho polling | Agent khong vang tien trinh, co log timeout |
| AG-010 | Du lieu thieu mot phan | Printer tra thieu field | Polling | Agent van gui payload hop le, khong exception |

## 3) Parser Ricoh (counter/status)

| ID | Muc tieu | Tien dieu kien | Buoc test | Ket qua mong doi |
|---|---|---|---|---|
| AG-011 | Parse counter may trang den | HTML counter mau BW | Goi parse counter | Tra dung `total`, `copier_bw`, `printer_bw` |
| AG-012 | Parse counter may mau | HTML counter mau | Goi parse counter | Co du field mau: `*_full_color`, `*_single_color`, `*_two_color`, coverage mau |
| AG-013 | Parse status toner/tray | HTML status mau | Goi parse status | Trich dung `system_status`, `toner_black`, `tray_*` |
| AG-014 | HTML la/thieu marker | HTML bi thay doi nhe | Parse | Khong crash, tra object rong hoac partial co kiem soat |
| AG-015 | Thiet bi offline | IP khong truy cap duoc | Poll printer | Agent bat loi va tiep tuc may tiep theo |

## 4) Device discovery va mapping

| ID | Muc tieu | Tien dieu kien | Buoc test | Ket qua mong doi |
|---|---|---|---|---|
| AG-016 | Nhan MAC tu thiet bi | Co may trong LAN | Scan + poll | Luu dung `mac_id/mac_address` |
| AG-017 | Fallback MAC tu ARP neighbor | Khong doc duoc MAC truc tiep | Poll | Agent lay MAC tu bang neighbor neu co |
| AG-018 | Tranh ten may loi (IP lam name) | Printer name bi loi | Poll | Name chuan hoa thanh `unknown` khi can |

## 5) WebSocket va update

| ID | Muc tieu | Tien dieu kien | Buoc test | Ket qua mong doi |
|---|---|---|---|---|
| AG-019 | WS connect thanh cong | WS URL dung | `POST /api/ws/connect` | Trang thai WS = connected |
| AG-020 | Nhan lenh update | WS gui message update | Quan sat updater | Agent ghi nhan signal update dung |
| AG-021 | Auto update tat | `UPDATE_AUTO_APPLY=false` | Gui lenh update | Chi ghi nhan, khong thuc thi command |
| AG-022 | Auto update bat + command hop le | `UPDATE_AUTO_APPLY=true` | Gui command allowlist | Agent thuc thi command thanh cong |

## 6) Scan upload (neu bat scan)

| ID | Muc tieu | Tien dieu kien | Buoc test | Ket qua mong doi |
|---|---|---|---|---|
| AG-023 | Upload file scan moi | Co file moi trong scan dir | Cho scan cycle | File duoc upload, server tra 200 |
| AG-024 | Khong upload trung | Co fingerprint state | Dat lai file cu | Agent bo qua file da upload |
| AG-025 | Upload loi tam thoi | Server scan endpoint loi | Cho cycle | Agent log loi, retry chu ky sau |

## 7) On dinh va hieu nang

| ID | Muc tieu | Tien dieu kien | Buoc test | Ket qua mong doi |
|---|---|---|---|---|
| AG-026 | Chay lien tuc 24h | Moi truong that | Chay service 24h | Khong memory leak ro ret, khong crash |
| AG-027 | Nhieu may in cung luc | >=20 printers | Polling lien tuc | Agent van phan hoi dung chu ky, khong treo |
| AG-028 | Khoi dong lai dot ngot | Kill process | Chay lai agent | Agent recover binh thuong, khong mat config |

## Ghi chu thuc thi

- Nen ghi lai ket qua theo cot: `Actual Result`, `Pass/Fail`, `Bug ID`.
- Nen uu tien chay AG-006 -> AG-015 truoc khi release.
- Neu co thay doi parser, bat buoc retest AG-011, AG-012, AG-013, AG-014.
