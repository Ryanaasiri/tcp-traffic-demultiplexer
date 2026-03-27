# TCP Traffic Demultiplexer

A Python-based network traffic analysis project that reads packets from a PCAP file or live capture, identifies valid TCP/IP packets, extracts key packet information, and separates traffic into individual TCP connection files for easier analysis.

## Overview

This project was built to practice PCAP processing, TCP packet analysis, and connection-based traffic separation using Python and Scapy.

The tool processes TCP traffic and saves each unique TCP connection into its own output file based on:

- Source IP
- Source Port
- Destination IP
- Destination Port

It also attempts simple protocol-aware output handling:
- Text-based protocols on common ports are written as readable text
- Other traffic is stored as hexadecimal output

## Features

- Reads packets from a saved PCAP file
- Supports optional live capture from a network interface
- Detects valid TCP/IP packets
- Extracts:
  - Source IP
  - Destination IP
  - Source Port
  - Destination Port
  - Payload
  - Timestamp
  - Packet direction
- Groups traffic by TCP connection
- Creates a separate output file for each connection
- Writes readable text for common clear-text protocols when possible
- Writes raw payload in hex format for other traffic

## Project Files

- `main.py` — program entry point and argument handling
- `demux.py` — packet processing and TCP connection demultiplexing
- `parser.py` — TCP packet validation and metadata extraction
- `utils.py` — helper functions for logging, timestamps, filenames, and directories
- `tests.py` — basic unit tests for selected helper functionality

## How It Works

1. The program reads packets from either:
   - a saved PCAP file, or
   - a live network interface
2. Each packet is checked to confirm it contains both IP and TCP layers
3. TCP packet metadata is extracted
4. A unique connection key is built using:
   - source IP
   - source port
   - destination IP
   - destination port
5. Packets belonging to the same TCP connection are written into the same output file

## Usage

### Process a PCAP file

~~~bash
python main.py -p sample.pcap
~~~

### Live capture

~~~bash
python main.py -i "Wi-Fi"
~~~

### Optional arguments

~~~bash
python main.py -i "Wi-Fi" -d 30 -o output
~~~

## Output

The program creates an `output/` directory automatically.

Each TCP connection is saved as a separate text file using a name similar to:

~~~text
[2025_11_27_12_30_15] 192.168.1.10.54321-93.184.216.34.80.txt
~~~

Each file contains:
- packet timestamp
- packet direction
- payload size
- decoded text payload when possible
- or hexadecimal payload for non-text traffic

## Requirements

- Python 3
- Scapy

Install Scapy with:

~~~bash
pip install scapy
~~~

## Notes

- This version focuses on TCP traffic only
- It does not fully reconstruct TCP streams
- It is intended as a simple and practical TCP traffic analysis project

## Learning Goals

This project helped me practice:

- PCAP processing
- TCP/IP packet analysis
- Python scripting for network traffic handling
- Connection-based traffic separation
- Working with Scapy for offline and live packet capture
