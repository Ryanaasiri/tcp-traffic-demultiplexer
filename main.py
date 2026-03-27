"""
main.py
Entry point for the TCP/IP Packet Demultiplexer project.

Responsibilities:
- Parse command-line arguments
- Initialize logging and output directory
- Create the TCPDemultiplexer instance
- Run live capture OR offline PCAP processing
"""

import argparse                             # For parsing CLI arguments
from demux import TCPDemultiplexer          # Main demultiplexer class
from utils import ensure_output_dir, setup_logging   # Utility functions


def parse_args():
    """
    Define and parse all command-line arguments for the program.
    """
    parser = argparse.ArgumentParser(
        description="TCP/IP Packet Demultiplexer (CPCS-371 Project)"
    )

    # Optional network interface for live capture
    parser.add_argument(
        "--interface", "-i",
        help="Network interface to capture from (e.g., eth0, wlan0)",
        required=False
    )

    # Optional PCAP file for offline packet processing
    parser.add_argument(
        "--pcap", "-p",
        help="Optional: read packets from a PCAP file instead of live capture",
        required=False
    )

    # Output directory where generated connection files will be stored
    parser.add_argument(
        "--output-dir", "-o",
        help="Directory to store output connection files",
        default="output"
    )

    # Optional capture duration (in seconds) for live mode
    parser.add_argument(
        "--duration", "-d",
        type=int,
        help="Optional: capture duration in seconds (live capture only)",
        required=False
    )

    return parser.parse_args()               # Return parsed arguments


def main():
    """
    Main execution function.
    Determines whether to run live capture or PCAP processing based on arguments.
    """
    args = parse_args()                      # Get command-line arguments

    setup_logging()                          # Enable logging (INFO level)
    ensure_output_dir(args.output_dir)       # Create output directory if needed

    # Create demultiplexer instance
    demux = TCPDemultiplexer(output_dir=args.output_dir)

    # If a PCAP file was provided → process it offline
    if args.pcap:
        demux.process_pcap_file(args.pcap)
    else:
        # Live capture requires an interface
        if not args.interface:
            raise SystemExit("Error: you must specify --interface for live capture.")

        # Start live packet capture on the specified interface
        demux.start_live_capture(
            interface=args.interface,
            duration=args.duration
        )

    # Ensure all output files are properly closed
    demux.close_all()

    print("Capture finished. All files closed.")  # User-friendly completion message


# Run main() only when executed directly 
if __name__ == "__main__":
    main()
