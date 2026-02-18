# PyPortScanner-SOC
Python-based network scanning utility supporting parallel port scanning, basic fingerprinting, and exportable reports.
## Features

- Scans a target IP address or domain name
- Allows custom port range scanning
- Uses multi-threading for faster results
- Detects service names on open ports
- Attempts banner grabbing
- Generates a scan report in a text file

## Requirements

- Python 3.x
- No external libraries required

Built-in modules used:

- socket
- datetime
- concurrent.futures

## Project Structure

port-scanner/

- port_scanner.py
- README.md
- report.txt (generated after scanning)

## Usage

Run the script:

```bash
python portscan.py

