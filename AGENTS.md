# GoPrinx Agent Documentation

Detailed documentation for the Agent component running within the local LAN.

## 🛠 Main Functions
The Agent is a background service (with an optional UI) on Windows that performs:
1. **Auto-Discovery:** Scans the LAN to find Ricoh printers (via SNMP/HTTP).
2. **Data Polling:** Periodically accesses the printer's Web UI to "scrape" data:
    - Counters (Total, Copier, Printer, Scan).
    - Status (Online/Offline, Alerts, Toner levels).
3. **Remote Control:** Receives commands from the Server to:
    - **Lock:** Disable copy/print functions on the printer.
    - **Unlock:** Re-enable the printer.
4. **Data Sync:** Sends data to the central Server via REST API.

## 📂 `agent/` Directory Structure
- `main.py`: Launches the Agent (CLI or Service mode).
- `web.py`: Provides a local configuration interface (http://localhost:5000).
- `models.py`: SQLite database structure for storing local configurations.
- `modules/ricoh/`:
    - `service.py`: Core logic for printer control.
    - `collector.py`: Counter index collection.
    - `control.py`: Execution of Lock/Unlock commands.
- `services/`:
    - `api_client.py`: HTTP communication with the VPS Server.
    - `ws_client.py`: Maintains a WebSocket connection for real-time commands.
    - `polling_bridge.py`: Coordination bridge between scanning and data submission.

## ⚙️ Configuration
The `config.yaml` configuration file contains:
- `server_url`: Address of the Backend VPS.
- `lead_id`: Customer identifier.
- `agent_id`: Unique identifier for this workstation.
- `polling_interval`: Data submission frequency (default 300 seconds).
