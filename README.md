# IDS Mini - Intrusion Detection System

A mini Intrusion Detection System (IDS) built with Python, Scapy, and Tkinter.

## Features

- **Packet Capture**: Captures network packets in real-time using Scapy.
- **Port Scan Detection**: Detects SYN-based port scanning attacks.
- **Payload Detection**: Scans packet payloads for suspicious patterns.
- **GUI Dashboard**: User-friendly interface with packet viewer and alerts panel.
- **Alerts**: Popup notifications and log for detected threats.

## Requirements

- Python 3.x
- Scapy
- Tkinter (usually included with Python)

## Installation

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python main.py
   ```

## Usage

1. Start the application with `python main.py`.
2. Click "Capture" > "Start Capture" to begin monitoring packets.
3. View captured packets in the Packet Viewer.
4. Alerts will appear in the Alerts panel and as popups.
5. Use "File" > "Export Logs" to save alerts to a file.

## Modules

- `packet_capture.py`: Handles packet sniffing.
- `port_scan_detector.py`: Detects port scanning.
- `payload_detector.py`: Detects malicious payloads.
- `gui.py`: Main GUI application.
- `main.py`: Entry point.

## Note

This is a mini IDS for educational purposes. For production use, consider professional IDS solutions.
