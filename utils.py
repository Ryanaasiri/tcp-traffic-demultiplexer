"""
utils.py
General utility functions used across the project:
- Timestamp formatting
- Directory handling
- Filename construction
- Logging helpers
"""

import os                      # File system operations
from datetime import datetime  # For timestamp formatting
import logging                 # For logging packet activity


def setup_logging():
    """
    Configure the logging module to display timestamped INFO-level messages.
    """
    logging.basicConfig(
        level=logging.INFO,                        # Log INFO and above
        format="%(asctime)s [%(levelname)s] %(message)s",  # Timestamp + Level + Message
    )


def current_timestamp_str() -> str:
    """
    Generate a timestamp string in the format: YYYY_MM_DD_HH_MM_SS
    Used for naming output files and logging packet times.
    """
    return datetime.now().strftime("%Y_%m_%d_%H_%M_%S")


def ensure_output_dir(path: str):
    """
    Ensure the output directory exists.
    If the directory does not exist, it will be created.
    """
    os.makedirs(path, exist_ok=True)               # Avoids errors if directory already exists


def build_connection_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> tuple:
    """
    Build and return a tuple that uniquely identifies a TCP connection.
    A connection is defined by:
    (source IP, source port, destination IP, destination port)
    """
    return (src_ip, src_port, dst_ip, dst_port)


def build_filename(
    output_dir: str,
    timestamp: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> str:
    """
    Construct an output filename following the required format:
        [timestamp] srcip.srcport-dstip.dstport.txt

    IP addresses are sanitized by replacing ":" with "_"
    to avoid file naming issues (especially with IPv6).
    """
    safe_src_ip = src_ip.replace(":", "_")         # Avoid invalid filename characters
    safe_dst_ip = dst_ip.replace(":", "_")

    # Create readable filename structure
    name = f"[{timestamp}] {safe_src_ip}.{src_port}-{safe_dst_ip}.{dst_port}.txt"

    # Return full path (directory + filename)
    return os.path.join(output_dir, name)


def open_connection_file_safely(path: str):
    """
    Open a file in append mode using UTF-8 encoding.
    If the file does not exist, it will be created.
    """
    return open(path, "a", encoding="utf-8")


def log_packet_info(info):
    """
    Log basic information about a processed TCP packet.
    Useful for monitoring and debugging.
    """
    logging.info(
        "Packet %s:%d -> %s:%d (%d bytes)",
        info.src_ip,
        info.src_port,
        info.dst_ip,
        info.dst_port,
        len(info.payload),
    )
