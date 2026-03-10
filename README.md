# PrintAgent: Ricoh Printer Management System

A centralized monitoring and management system for Ricoh printers. Collects counters, status, and provides remote control (lock/unlock) for multiple printers across various branches (LAN sites).

## 🏗 Architecture Overview

The project is divided into 3 main parts:

### 1. Agent (`agent/`) - Runs at Local Site (Workstation/Internal Server)
A Python service that maintains a direct connection with printers in the LAN.
- **Features:** Device scanning, counter collection, status updates, remote command execution (Lock/Unlock).
- **Technology:** Python 3.11+, Flask (Local UI), SQLAlchemy (SQLite).
- **Key Files:**
    - `agent/main.py`: Entry point for the agent service.
    - `agent/web.py`: Local Dashboard (Port 5000).
    - `agent/modules/ricoh/`: Logic for interacting with Ricoh printers.

### 2. Server Backend (`server/`) - Operation Center (VPS)
The central management hub that receives data from thousands of Agents.
- **Features:** Ingestion API, Database Management, Command Control (WebSocket/Polling), Analytics.
- **Technology:** Flask, PostgreSQL/SQLite, SQLAlchemy.
- **Key Files:**
    - `server/app.py`: Main API and Backend Dashboard management.
    - `server/models.py`: Defines the system-wide data structure.
    - `server/utils.py` & `server/serializers.py`: Utility functions and data processing.

### 3. Frontend Web (`app-gox/`) - Modern UI (React)
Administrative dashboard for users and technicians.
- **Features:** Visual monitoring, Agent management, photocopier management, locations, and repair requests.
- **Technology:** React, TypeScript, Vite, Framer Motion.

## 🚀 Quick Setup

### Agent (For Clients)
1. Download the `GoPrinxAgent.exe` installer from [app.goxprint.com/downloads](http://app.goxprint.com/downloads).
2. Run with Administrator privileges and enter the corresponding **Agent ID**.

### Server & Frontend (For Developers)
- Backend: `cd server && python app.py`
- Frontend: `cd app-gox && npm install && npm run dev`

## 📂 Directory Structure
- `agent/`: Source code for the Agent software running on-site.
- `server/`: Flask Backend source code running on the VPS.
- `app-gox/`: React Frontend source code.
- `dist/`: Contains the built `GoPrinxAgent.exe` file.
- `storage/`: Local data, logs, and cache.
