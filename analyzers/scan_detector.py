from typing import Dict, Any, List

class ScanDetector:
    """
    Analyzes network flow logs for heuristic indicators of port scanning,
    reconnaissance, and unauthorized access attempts.
    """

    SENSITIVE_PORTS = [22, 3306, 5432, 3389]

    @classmethod
    def analyze_flow(cls, flow: Dict[str, Any]) -> Dict[str, Any]:
        dest_port = flow.get("destination_port", 0)
        source_ip = flow.get("source_ip", "")
        
        is_external = not (source_ip.startswith("192.168.") or source_ip.startswith("10."))
        
        threat_level = "NORMAL"
        detected_behavior = "Standard Traffic"

        if dest_port in cls.SENSITIVE_PORTS and is_external:
            threat_level = "HIGH"
            detected_behavior = f"External Probing on Sensitive Port ({dest_port})"
        elif dest_port == 22 and is_external:
            threat_level = "CRITICAL"
            detected_behavior = "Potential Brute-Force SSH Attack"

        analyzed_flow = dict(flow)
        analyzed_flow.update({
            "threat_level": threat_level,
            "detected_behavior": detected_behavior
        })
        return analyzed_flow

    @classmethod
    def evaluate_flows(cls, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [cls.analyze_flow(flow) for flow in flows]
