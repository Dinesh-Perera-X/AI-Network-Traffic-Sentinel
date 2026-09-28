import json
import os
from typing import List, Dict, Any

class SIEMExporter:
    DEFAULT_EXPORT_PATH = "data/siem_alerts.json"

    @classmethod
    def export_alerts(cls, flows: List[Dict[str, Any]], filepath: str = DEFAULT_EXPORT_PATH) -> int:
        alerts = []
        for flow in flows:
            if flow.get("threat_level") in ["HIGH", "CRITICAL"] or flow.get("statistical_anomaly") or flow.get("quarantine_action") != "NONE":
                alert = {
                    "flow_id": flow.get("flow_id"),
                    "source_ip": flow.get("source_ip"),
                    "destination_ip": flow.get("destination_ip"),
                    "destination_port": flow.get("destination_port"),
                    "threat_level": flow.get("threat_level"),
                    "detected_behavior": flow.get("detected_behavior", "Standard Traffic"),
                    "statistical_anomaly": flow.get("statistical_anomaly", False),
                    "quarantine_action": flow.get("quarantine_action", "NONE"),
                }
                alerts.append(alert)

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=4)

        return len(alerts)
