#!/usr/bin/env python3
"""
packet_sniffer.py
Educational packet sniffer & pcap analyzer using Scapy.

Usage examples:
  # Live capture 50 packets on interface eth0, save to out.pcap:
  sudo python3 packet_sniffer.py --mode live --iface eth0 --count 50 --outfile out.pcap

  # Analyze an existing pcap:
  python3 packet_sniffer.py --mode analyze --pcapfile out.pcap
"""

import argparse
import datetime
import os
import sys
from binascii import hexlify

try:
    from scapy.all import sniff, PcapWriter, rdpcap, Raw, IP, IPv6, TCP, UDP, ICMP
except Exception as e:
    print("Error importing scapy. Install with: pip install scapy")
    raise

# Helper to make bytes printable (show small ascii preview)
def printable_ascii_preview(b, max_len=64):
    if not b:
        return ""
    preview = b[:max_len]
    # hex and ascii versions
    hex_preview = hexlify(preview).decode('ascii')
    ascii_preview = ''.join((chr(c) if 32 <= c < 127 else '.') for c in preview)
    return f"HEX:{hex_preview}  ASCII:{ascii_preview}"

# Pretty print a packet summary line
def summarize_packet(pkt, show_payload=True):
    ts = datetime.datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    proto = "OTHER"
    src = dst = "-"
    length = len(pkt)

    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        # Map common proto numbers
        if TCP in pkt:
            proto = "TCP"
        elif UDP in pkt:
            proto = "UDP"
        elif ICMP in pkt:
            proto = "ICMP"
        else:
            try:
                proto = {6:"TCP", 17:"UDP", 1:"ICMP"}.get(pkt[IP].proto, str(pkt[IP].proto))
            except Exception:
                proto = str(pkt[IP].proto)

    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        proto = "IPv6"
        if TCP in pkt:
            proto = "TCP"
        elif UDP in pkt:
            proto = "UDP"

    # payload preview
    payload_preview = ""
    if show_payload and Raw in pkt:
        raw_bytes = bytes(pkt[Raw])
        payload_preview = printable_ascii_preview(raw_bytes, max_len=80)
    else:
        payload_preview = ""

    return {
        "timestamp": ts,
        "src": src,
        "dst": dst,
        "proto": proto,
        "len": length,
        "payload": payload_preview
    }

# Live capture callback
def live_callback(pkt, writer=None, index=[0]):
    idx = index[0] + 1
    index[0] = idx
    info = summarize_packet(pkt, show_payload=True)
    print(f"[{idx:04d}] {info['timestamp']} {info['src']:>21} -> {info['dst']:<21} {info['proto']:6} len={info['len']:4} {info['payload']}")
    if writer:
        writer.write(pkt)

def run_live_capture(interface, bpf_filter, count, timeout, outfile):
    # Must be run with root/admin privileges to capture interfaces.
    print(f"Starting live capture on interface '{interface}'  filter='{bpf_filter}'  count={count} timeout={timeout}")
    writer = None
    if outfile:
        # PcapWriter appends by default, set sync=True to flush immediately
        writer = PcapWriter(outfile, append=False, sync=True)
        print(f"Saving capture to: {outfile}")

    try:
        sniff_kwargs = dict(iface=interface if interface else None,
                            filter=bpf_filter if bpf_filter else None,
                            prn=lambda pkt: live_callback(pkt, writer),
                            store=False)

        if count:
            sniff_kwargs['count'] = count
        if timeout:
            sniff_kwargs['timeout'] = timeout

        sniff(**sniff_kwargs)

    except PermissionError:
        print("PermissionError: you need to run this script as root/administrator to sniff live traffic.")
    except Exception as e:
        print(f"Error during sniffing: {e}")
    finally:
        if writer:
            writer.close()
            print("Finished capture and closed pcap writer.")

def analyze_pcap_file(pcapfile, show_payload=True, max_packets=None):
    if not os.path.exists(pcapfile):
        print(f"File not found: {pcapfile}")
        return
    print(f"Reading pcap file: {pcapfile}")
    try:
        packets = rdpcap(pcapfile)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    total = len(packets)
    print(f"Total packets in file: {total}")
    limit = max_packets if max_packets else total
    for i, pkt in enumerate(packets[:limit], start=1):
        info = summarize_packet(pkt, show_payload=show_payload)
        print(f"[{i:04d}] {info['timestamp']} {info['src']:>21} -> {info['dst']:<21} {info['proto']:6} len={info['len']:4} {info['payload']}")

# Simple CLI
def main():
    parser = argparse.ArgumentParser(description="Educational Packet Sniffer & Pcap Analyzer (use ethically!)")
    parser.add_argument("--mode", choices=["live","analyze"], default="analyze", help="live capture or analyze existing pcap")
    parser.add_argument("--iface", help="Interface for live capture (e.g. eth0, wlan0). If empty, default OS interface used.")
    parser.add_argument("--filter", dest="bpf", help="BPF filter for live capture (e.g. 'tcp port 80')")
    parser.add_argument("--count", type=int, help="Number of packets to capture (live mode)")
    parser.add_argument("--timeout", type=int, help="Timeout in seconds for live capture")
    parser.add_argument("--outfile", help="Save live capture to pcap file")
    parser.add_argument("--pcapfile", help="Pcap file to analyze (analyze mode)")
    parser.add_argument("--max", type=int, help="Max packets to show when analyzing a pcap")
    args = parser.parse_args()

    if args.mode == "live":
        # Warn the user
        print("WARNING: Live capture requires root/admin privileges and should be run only on networks you own or have permission to analyze.")
        run_live_capture(args.iface, args.bpf, args.count, args.timeout, args.outfile)

    else:
        if not args.pcapfile:
            print("In analyze mode you must pass --pcapfile <file.pcap>")
            sys.exit(1)
        analyze_pcap_file(args.pcapfile, show_payload=True, max_packets=args.max)


if __name__ == "__main__":
    main()