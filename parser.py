"""
parser.py
Provides helper functions to:
- Identify valid TCP/IP packets
- Extract source/destination IPs and ports
- Extract payload bytes
- Build a structured TCPPacketInfo dataclass
"""

from dataclasses import dataclass                  # For clean data structure representation
from scapy.layers.inet import IP, TCP              # To access IP and TCP layers
from scapy.packet import Packet                    # Generic Scapy packet type
from utils import current_timestamp_str            # Timestamp generator


@dataclass
class TCPPacketInfo:
    """
    A structured container holding all relevant information
    extracted from a TCP packet.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes
    timestamp: str
    direction: str    # Example: "192.168.1.5:3456 -> 142.250.190.78:443"


def is_tcp_packet(pkt: Packet) -> bool:
    """
    Check if the packet contains both IP and TCP layers.
    Returns True only if it is a valid TCP/IP packet.
    """
    return IP in pkt and TCP in pkt


def extract_tcp_info(pkt: Packet) -> TCPPacketInfo | None:
    """
    Extract key information from a TCP packet:
    - Source IP
    - Destination IP
    - Source Port
    - Destination Port
    - TCP Payload (raw bytes)
    - Timestamp
    - Direction string

    Returns a TCPPacketInfo instance if successful.
    Returns None if the packet is not TCP or missing expected fields.
    """
    if not is_tcp_packet(pkt):                      # Reject non-TCP packets
        return None

    ip_layer = pkt[IP]                              # Extract IP layer
    tcp_layer = pkt[TCP]                            # Extract TCP layer

    src_ip = ip_layer.src                           # Source IP address
    dst_ip = ip_layer.dst                           # Destination IP address
    src_port = tcp_layer.sport                      # Source TCP port
    dst_port = tcp_layer.dport                      # Destination TCP port
    payload = bytes(tcp_layer.payload)              # Raw TCP payload bytes

    timestamp = current_timestamp_str()             # Current timestamp for logging/file naming
    direction = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"  # Human-readable direction

    # Create and return structured packet information
    return TCPPacketInfo(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
        timestamp=timestamp,
        direction=direction,
    )
