import argparse
import json
from datetime import datetime, timezone

import requests
from scapy.all import rdpcap


def parse_packet(packet):
    """Translate a Scapy packet into the threat JSON payload your API expects."""

    ip_layer = packet.getlayer("IP") or packet.getlayer("IPv6")
    if ip_layer is None:
        return None  # skip non-IP packets

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    transport = packet.getlayer("TCP") or packet.getlayer("UDP")
    dst_port = transport.dport if transport and hasattr(transport, "dport") else None

    # naïve heuristics – customize for your signatures
    payload_bytes = bytes(packet.payload)
    payload = payload_bytes[:256].decode(errors="replace")

    details = f"Traffic from {src_ip} to {dst_ip}"
    if dst_port:
        details += f" on port {dst_port}"
    details += f" – sample payload: {payload}"

    return {
        "threat_type": f"Observed traffic from {src_ip}",
        "severity": "medium",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "destination_port": dst_port,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details,
        "action_taken": "Logged for triage",
        "confidence": 75,
    }


def stream_packets_to_api(pcap_path, api_url, dry_run=False):
    packets = rdpcap(pcap_path)
    sent = 0
    for pkt in packets:
        payload = parse_packet(pkt)
        if payload is None:
            continue

        if dry_run:
            print(json.dumps(payload, indent=2))
        else:
            response = requests.post(api_url, json=payload, timeout=5)
            response.raise_for_status()
        sent += 1

    return sent


def main():
    parser = argparse.ArgumentParser(description="Convert PCAP traffic into threat alerts.")
    parser.add_argument("pcap", help="Path to PCAP/PCAPNG file from Wireshark/tshark")
    parser.add_argument("--api", default="http://127.0.0.1:5000/api/alerts/send",
                        help="Alert ingestion endpoint (default: http://127.0.0.1:5000/api/alerts/send)")
    parser.add_argument("--dry-run", action="store_true", help="Print payloads instead of sending to API")
    args = parser.parse_args()

    count = stream_packets_to_api(args.pcap, args.api, dry_run=args.dry_run)
    print(f"Processed {count} packets from {args.pcap}")


if __name__ == "__main__":
    main()
