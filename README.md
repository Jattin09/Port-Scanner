
# Advanced Multithreaded TCP Port Scanner

A Python-based TCP port scanner that identifies open ports on a target IP address or hostname using socket programming and multithreading.

## Features

- TCP port scanning using Python sockets
- Multithreaded scanning using ThreadPoolExecutor
- Configurable port range
- Adjustable connection timeout
- Customizable number of threads
- Basic service identification
- Hostname-to-IP resolution

## Technologies Used

- Python
- Socket Programming
- TCP/IP
- ThreadPoolExecutor
- Argparse

## Requirements

- Python 3.10 or later

No external Python packages are required.

## Usage

Run the scanner from the terminal:

```bash
python "Port Scanner.py" 127.0.0.1 --start-port 1 --end-port 1000 --threads 100 --timeout 0.5
```

Replace `127.0.0.1` with a target you are authorized to scan.

## Learning Outcomes

- Understanding TCP connections and port states
- Working with Python socket programming
- Implementing concurrent execution
- Learning basic network reconnaissance

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Scan only systems for which you have permission.
