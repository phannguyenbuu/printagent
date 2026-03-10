# Test Plan (Test Cases)

GoPrinx Printer Management System.

## 1. Agent Testing (Local)
- **TC-AG-01:** First-time Agent startup, verify local DB file creation and Server connection.
- **TC-AG-02:** Network Scan (Scan LAN) successfully finds Ricoh printers in the correct IP range.
- **TC-AG-03:** Successfully retrieve Counter data from a sample printer.
- **TC-AG-04:** Send Polling data to the Server (Backend) via API.
- **TC-AG-05:** Execute Lock/Unlock commands from the local interface.

## 2. Server Backend Testing (VPS)
- **TC-SV-01:** Receive Ingestion data from Agent and store it in the PostgreSQL database.
- **TC-SV-02:** Calculate Counter Baseline when a printer's physical counter is reset.
- **TC-SV-03:** Send control commands to the Agent via WebSocket/Polling.
- **TC-SV-04:** API for 3rd-party CRM returns the correct JSON structure.

## 3. Frontend Testing (User UI)
- **TC-FE-01:** Login with different roles (Admin, Technician).
- **TC-FE-02:** Display Agent list and actual Online/Offline status.
- **TC-FE-03:** Add/Edit/Delete (CRUD) Locations successfully.
- **TC-FE-04:** Download `GoPrinxAgent.exe` from the Downloads page successfully.
- **TC-FE-05:** View counter trend charts (Heatmap) over time.

## 4. Integration Testing (End-to-End)
- **TC-E2E-01:** Lock a photocopier from Frontend -> Server -> Agent -> Actual Printer -> Status updated back on the Frontend.
