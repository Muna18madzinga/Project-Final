import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

def _coerce_timestamp(value: Any) -> str:
    if not value:
        return datetime.utcnow().isoformat()
    if isinstance(value, (int, float)):
        return datetime.utcfromtimestamp(value).isoformat()
    return str(value)

def load_threat_events(path: Path) -> List[Dict[str, Any]]:
    """Load threat events from a JSON or JSONL file."""
    if not path.exists():
        return []

    events: List[Dict[str, Any]] = []

    def _normalize(entry: Dict[str, Any], index: int) -> Dict[str, Any]:
        timestamp = _coerce_timestamp(entry.get("timestamp"))
        event_id = entry.get("event_id") or entry.get("id") or f"FILE-{index}-{timestamp}"
        tactics = entry.get("tactics")
        if isinstance(tactics, str):
            tactics = [tactics]
        elif tactics is None:
            tactics = []

        threat_data = {
            "threat_type": entry.get("threat_type") or entry.get("signature") or "Unknown Threat",
            "severity": (entry.get("severity") or "medium").lower(),
            "source_ip": entry.get("source_ip") or entry.get("src_ip") or entry.get("source"),
            "destination_ip": entry.get("destination_ip") or entry.get("dest_ip"),
            "destination_port": entry.get("destination_port") or entry.get("dest_port"),
            "protocol": entry.get("protocol"),
            "vector": entry.get("vector"),
            "timestamp": timestamp,
            "details": entry.get("details") or entry.get("description"),
            "action_taken": entry.get("action_taken") or "Threat recorded for analysis",
            "confidence": entry.get("confidence", 80),
            "category": entry.get("category"),
            "tactics": tactics,
        }

        return {
            "alert_id": event_id,
            "timestamp": timestamp,
            "threat_data": threat_data,
        }

    suffix = path.suffix.lower()
    raw_entries: Iterable[Dict[str, Any]]

    if suffix == ".jsonl":
        with path.open("r", encoding="utf-8") as handle:
            raw_entries = (json.loads(line) for line in handle if line.strip())
            for index, entry in enumerate(raw_entries, start=1):
                events.append(_normalize(entry, index))
    else:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
            if isinstance(payload, list):
                iterable = payload
            elif isinstance(payload, dict) and "events" in payload:
                iterable = payload["events"]
            else:
                iterable = [payload]
            for index, entry in enumerate(iterable, start=1):
                events.append(_normalize(entry, index))

    return events


def load_network_devices(path: Path) -> List[Dict[str, Any]]:
    """Load network devices discovered on the network."""
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict) and "devices" in payload:
        device_iterable = payload["devices"]
    elif isinstance(payload, list):
        device_iterable = payload
    else:
        device_iterable = [payload]

    devices: List[Dict[str, Any]] = []
    for index, raw in enumerate(device_iterable, start=1):
        last_seen = _coerce_timestamp(raw.get("last_seen"))
        device = {
            "id": raw.get("id") or f"DEV-{index}",
            "name": raw.get("name") or raw.get("hostname") or raw.get("ip"),
            "ip": raw.get("ip"),
            "mac": raw.get("mac"),
            "vendor": raw.get("vendor"),
            "type": raw.get("type") or raw.get("device_type") or "Unknown",
            "os": raw.get("os") or "Unknown",
            "status": raw.get("status") or "unknown",
            "risk_level": raw.get("risk_level") or "low",
            "last_seen": last_seen,
            "open_ports": raw.get("open_ports") or [],
            "traffic": raw.get("traffic", 0),
            "firewall_enabled": raw.get("firewall_enabled", False),
            "interface": raw.get("interface"),
        }
        devices.append(device)

    return devices
