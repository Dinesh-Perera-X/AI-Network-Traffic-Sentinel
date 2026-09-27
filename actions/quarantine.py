from typing import Dict, Any, List

class QuarantineGenerator:
    """
    Generates automated security responses, such as IP quarantine rules
    and firewall block lists based on heuristic and anomaly detections.
    """

    @classmethod
    def process_quarantine_actions(cls, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        processed_flows = []
        for flow in flows:
            flow_copy = dict(flow)
            threat_level = flow_copy.get("threat_level", "NORMAL")
            is_anomaly = flow_copy.get("statistical_anomaly", False)

            quarantine_action = "NONE"
            if threat_level == "CRITICAL" or is_anomaly:
                quarantine_action = "BLOCK & ISOLATE"
            elif threat_level == "HIGH":
                quarantine_action = "FLAG FOR REVIEW"

            flow_copy["quarantine_action"] = quarantine_action
            processed_flows.append(flow_copy)

        return processed_flows
