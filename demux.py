"""
demux.py
Implements the TCPDemultiplexer class:
- Handles packet capture callbacks
- Demultiplexes TCP packets by (src_ip, src_port, dst_ip, dst_port)
- Manages per-connection output files
"""

from scapy.all import sniff, rdpcap      # For live capture and reading PCAP files
from parser import extract_tcp_info, is_tcp_packet    # Parsing helpers
from utils import (
    build_connection_key,
    build_filename,
    open_connection_file_safely,
    log_packet_info,
)


class TCPDemultiplexer:
    """
    A class responsible for:
    - Capturing TCP packets (live or offline)
    - Identifying each unique TCP connection
    - Saving packets to separate files based on connection tuple
    """

    def __init__(self, output_dir: str):
        self.output_dir = output_dir          # Directory where output files will be stored
        self.open_files = {}                  # Dictionary: connection_key → file handle

    # ---------- Live Capture ----------

    def start_live_capture(self, interface: str, duration: int | None = None):
        """
        Start live packet capture on a specific network interface.
        Only TCP packets will be processed.
        """
        sniff(
            iface=interface,                  # Network interface (e.g., eth0, wlan0)
            prn=self._packet_handler,         # Callback for each captured packet
            store=False,                      # Do not keep packets in memory
            filter="tcp",                     # Capture TCP packets only
            timeout=duration,                 # Optional capture duration (seconds)
        )

    # ---------- PCAP File Processing ----------

    def process_pcap_file(self, pcap_path: str):
        """
        Process packets from a saved PCAP file.
        """
        packets = rdpcap(pcap_path)           # Load all packets from the file
        for pkt in packets:                   # Iterate through packets
            self._packet_handler(pkt)         # Process each one using the same handler

    # ---------- Internal Packet Logic ----------

    def _packet_handler(self, packet):
        """
        Handle a single packet:
        - Validate it's TCP
        - Extract info
        - Determine its connection key
        - Write payload to the correct output file
        """
        if not is_tcp_packet(packet):         # Ignore non-TCP packets
            return

        info = extract_tcp_info(packet)       # Extract IPs, ports, payload, timestamp
        if info is None:                      # Safety check
            return

        # Build a unique identifier for this TCP connection
        conn_key = build_connection_key(
            info.src_ip, info.src_port, info.dst_ip, info.dst_port
        )

        # If this is the first packet of this connection → create/open file
        if conn_key not in self.open_files:
            filename = build_filename(
                self.output_dir,
                info.timestamp,
                info.src_ip,
                info.src_port,
                info.dst_ip,
                info.dst_port,
            )
            self.open_files[conn_key] = open_connection_file_safely(filename)

        f = self.open_files[conn_key]         # Get the file handle for this connection

        # Write a header for the packet (timestamp, direction, payload size)
        f.write(f"[{info.timestamp}] {info.direction} {len(info.payload)} bytes\n")

        """
        SMART PROTOCOL DETECTION
        -------------------------
        Recognize common clear-text TCP protocols by port number:
        21 = FTP
        23 = Telnet
        80 = HTTP
        25 = SMTP
        110 = POP3
        143 = IMAP

        If the port corresponds to a text-based protocol:
            → attempt UTF-8 decoding
        Otherwise:
            → store raw payload in hex format
        """
        text_ports = {21, 23, 80, 25, 110, 143}

        # If either source or destination port is a known text-protocol port
        if (info.src_port in text_ports) or (info.dst_port in text_ports):

            try:
                # Try to decode payload as text (UTF-8)
                text_data = info.payload.decode("utf-8", errors="replace")
                f.write(text_data)

            except Exception:
                # Fallback: if decoding fails, write raw hex
                f.write(f"[Decode Error - Raw Hex]: {info.payload.hex()}")

        else:
            # Non-text / encrypted protocols (HTTPS/443 etc.) → write hex bytes
            f.write(info.payload.hex())

        f.write("\n\n")                       # Blank line separating packets

        log_packet_info(info)                 # Log packet info to console

    # ---------- Cleanup ----------

    def close_all(self):
        """
        Close all open output files at the end of the program.
        """
        for f in self.open_files.values():
            try:
                f.close()
            except Exception:
                pass
        self.open_files.clear()               # Reset dictionary after closing
