# Python Port Scanner

A simple Python-based port scanner inspired by Nmap, with limited features. This tool allows you to scan common ports on a target host, fetch service banners, and identify running services.

## Features

- **Port Scanning:** Scan a filtered list of common ports or use provided top-N port lists.
- **Service Detection:** Fetch service banners and version information from open ports.
- **Multi-threaded Scanning:** Faster scans using Python threading.
- **Custom Port Lists:** Use included `top-nmap-ports` directory for top-500 or top-1000 ports (TXT files).

## Requirements

- Python 3.x
- [IPy](https://pypi.org/project/IPy/) (`pip3 install IPy`)

## Python Libraries Used

- `IPy` — IP address manipulation
- `socket` — TCP socket connections
- `threading` — Multi-threaded scanning
- `sys` — System exit handling

## Usage

1. **Install dependencies:**
    ```bash
    pip3 install IPy
    ```
2. **Run the scanner:**
    ```bash
    python3 port_scanner.py
    ```
3. **Optional:** Use custom port lists from the `top-nmap-ports` directory.

## Notes

- Scanning large port ranges can consume significant system resources.
- The script uses a filtered list of common ports for efficiency.
- For larger scans, use the provided port lists and file I/O operations.

## Disclaimer

Use this tool responsibly and only on hosts you own or have permission to scan.
