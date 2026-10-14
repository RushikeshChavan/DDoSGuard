# DDoSGuard

DDoSGuard is a Windows-friendly, rule-based traffic monitoring demonstration. It collects synthetic traffic (or, optionally, local packet metadata), calculates packet and byte rates, and raises explainable alerts for selected traffic anomalies. It is intended for learning and demonstration, not production mitigation or proof of an attack.

## Problem statement

Traffic floods and unusual source/protocol patterns can make a network service unavailable. DDoSGuard demonstrates how a small monitoring pipeline can summarize traffic and identify indicators such as elevated packet rates, sudden changes, sustained overload, source concentration, and high TCP SYN ratios. These heuristics can produce false positives and must be corroborated; the application never blocks traffic or changes firewall settings.

## Architecture and technology

- **Python 3.11+** implements the simulation, detection, capture, and persistence layers.
- **Streamlit** renders the dashboard and refreshes it periodically while monitoring is active.
- **Pandas** prepares chart and alert-table data.
- **Scapy** optionally captures local packet metadata through Windows interfaces.
- **SQLite** stores alert history in the local `ddosguard.db` file.

Traffic flows from the selected source to the detector once per measurement window. Simulation windows are generated locally and do not transmit packets. Live capture stores only short-lived Scapy packet objects in a one-second capture batch, summarizes packet size, source IP, protocol, and TCP SYN/ACK flags, and passes summary counts to detection. The dashboard shows rates, protocols, source counts, recent alerts, charts, and filtered/exportable persistent alerts.

## Install on Windows PowerShell

From the project directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If script activation is restricted, open a PowerShell session that permits local virtual-environment activation or invoke `.venv\Scripts\python.exe` and `.venv\Scripts\streamlit.exe` directly.

Start the application:

```powershell
streamlit run app.py
```

The dashboard opens in a browser. Simulation mode needs no administrator privileges or packet-capture driver.

Scapy is optional for the simulation-only installation. For live capture, install it separately with `python -m pip install "scapy>=2.5,<3.0"` and install/configure Npcap as described below.

## Demonstrate the simulation

In the sidebar, select **Simulation**, set a duration and thresholds, then select a scenario and press **Start**. Windows update automatically while monitoring is active.

1. **Normal:** choose `normal`. The generated traffic stays near its lower baseline and normally remains below the default packet-rate threshold.
2. **Traffic spike:** choose `spike`. The simulator first warms a normal baseline, then generates an eight-window burst followed by lower traffic. The sudden-spike and configured rate rules can flag the burst.
3. **DDoS-like:** choose `ddos`. The simulator produces sustained high packet volume from multiple synthetic sources with elevated SYN counts; overload and applicable anomaly rules may alert.

Use **Stop** to end monitoring and **Reset** to clear the current simulation run and detector baseline. **Clear persistent alert history** is separate and deletes saved alert records.

The dashboard labels all findings as possible anomalies, not confirmed attacks. Rates are calculated from each window’s packet/byte totals divided by its measured elapsed time. Alerts include the triggering rule, observed value, and threshold.

## Optional live packet capture

Live capture is optional and is not needed for the primary demonstration. Install Scapy with `python -m pip install "scapy>=2.5,<3.0"`, install Npcap with its packet-capture compatibility support, select **Live Capture**, choose an interface, and grant the account the permissions required by the driver.

Live capture uses short packet batches to build metadata summaries; raw packet payloads are not persisted. Capture availability depends on the Windows driver, interface, and permissions. If capture is unavailable, the dashboard reports the error and Simulation remains usable. Live capture has not been verified on every Windows/Npcap configuration.

## Tests

Run the complete isolated test suite from PowerShell:

```powershell
python -m pytest -q
```

The storage test redirects the database path to a temporary test directory; it does not clear or modify the application database. Tests cover simulation scenarios, detection rules and cooldown, duplicate-window protection, rate calculation, SQLite persistence, and packet-batch collection. For a separate local database, set `DDOSGUARD_DB_PATH` to the desired SQLite file path before starting the application.

## Limitations and safety

- This is a small demonstration, not a production traffic-analysis or mitigation system.
- Simulated values are synthetic and cannot establish that real network traffic behaves the same way.
- Rule thresholds are configurable heuristics. Source concentration and SYN ratios are not sufficient to confirm a DDoS attack.
- Live capture is optional and may not work until Npcap and permissions are correctly configured.
- No attack traffic is transmitted, and the application does not block IP addresses or alter firewall rules.
- The local SQLite database is ignored by Git and may contain private alert history; do not commit it.
