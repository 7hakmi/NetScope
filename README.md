# NetScope — Infrastructure Monitor

NetScope is a web-based Network & IT Infrastructure Monitoring Dashboard built with Python and Flask.

## Features

- Real-time device Online / Offline monitoring
- Latency and Packet Loss monitoring
- Network Discovery
- Interactive Network Topology
- Alerts & Event Log
- Incident Management
- Analytics and monitoring history
- Reports & Export
- Network Traffic monitoring
- SNMPv2c monitoring
- Live network interface information
- Device Details
- Login / Logout authentication

## Technologies

- Python
- Flask
- SQLite
- psutil
- PySNMP
- HTML
- CSS
- JavaScript
- Chart.js

## Run the Project

Install dependencies:

```bash
pip install -r requirements.txt
```

Start NetScope:

```bash
python app.py
```

Start the SNMP Agent in another terminal:

```bash
python snmp_agent.py
```

Open:

```text
http://127.0.0.1:5000
```

## Project Status

NetScope V1.0 — Completed ✅
