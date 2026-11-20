# Network Security and Firewall Monitoring System

**Course:** CSA0712 – Network Security and Firewalls  
**Assignment:** Common Assignment

## Student Details

| Details | Information |
|---|---|
| Name | S. Thanishka |
| Register Number | 192521457 |
| Department | B.Tech Information Technology |
| Institution | SIMATS Engineering |

## About the Project

A Python-based simulation of a packet-filtering firewall with network traffic monitoring. It examines incoming and outgoing packets using administrator-defined rules and classifies them as Allowed or Blocked.

The system also detects suspicious activities such as port scanning, repeated unauthorized access attempts and DoS-style flooding. All decisions are recorded in security logs, and an HTML dashboard displays network traffic statistics.

## Features

- Firewall rules based on source IP, destination IP, port number and protocol.
- First-match rule evaluation with default deny policy.
- Packet classification as Allowed or Blocked.
- Traffic identification (HTTP, HTTPS, DNS, SSH, Telnet and RDP).
- Port scanning detection.
- Repeated blocked access detection.
- DoS and flooding detection.
- Security alerts with Medium, High and Critical severity levels.
- CSV security logs and text alert files.
- HTML network traffic dashboard.

## Requirements

- Python 3.8 or above.
- Windows 10/11, Linux or macOS.
- Minimum 2 GB RAM.
- No additional Python libraries required.

## How to Run

1. Download or clone this repository.
2. Open the project folder in VS Code.
3. Open the terminal.
4. Execute the following command:

```bash
python firewall_monitor.py
```

5. Open `sample_output/dashboard.html` in your browser to view the dashboard.

## Project Structure

```text
Network-Security-Firewall-Monitoring-System/
│
├── firewall_monitor.py
├── rules.json
├── sample_output/
│   ├── security_log.csv
│   ├── security_alerts.txt
│   └── dashboard.html
├── images/
├── CSA0712_Network_Security_Firewall_Report.docx
└── README.md
```

## Firewall Rules

Firewall rules are stored in the `rules.json` file. Each rule contains an action, source IP address, destination IP address, port number, protocol and description.

Rules are checked from top to bottom. If a packet does not match any permitted rule, it is blocked by the default deny policy.

## Sample Results

| Measure | Result |
|---|---:|
| Total Packets Monitored | 110 |
| Allowed Packets | 65 |
| Blocked Packets | 45 |
| Security Alerts | 4 |
| Critical Flood Alerts | 1 |

## Concepts Demonstrated

1. Packet Filtering
2. Access Control
3. Firewall Rule Management
4. Default Deny Policy
5. IP Address Filtering
6. Intrusion Detection
7. Port Scan Detection
8. DoS Prevention
9. Security Logging
10. Network Traffic Monitoring

## Output Files

- `security_log.csv` – Stores packet details and firewall decisions.
- `security_alerts.txt` – Stores suspicious activity alerts.
- `dashboard.html` – Displays network traffic statistics.

## Conclusion

This project demonstrates how a firewall protects a network through packet filtering, access control and suspicious activity detection. It provides a practical understanding of network security using Python simulation.

---
**Submitted By:** S. Thanishka  
**Register Number:** 192521457  
**Department:** B.Tech Information Technology  
**Institution:** SIMATS Engineering
