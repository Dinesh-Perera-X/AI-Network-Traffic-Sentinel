import statistics
from typing import Dict, Any, List

class AnomalyDetector:
    """
    Applies statistical anomaly detection and outlier identification
    on network traffic volume (bytes transferred) to flag potential data exfiltration.
    """

    BYTE_THRESHOLD_MULTIPLIER = 2.5

    @classmethod
    def evaluate_traffic_anomalies(cls, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not flows:
            return flows

        bytes_list = [f.get("bytes_transferred", 0) for f in flows]
        
        try:
            mean_bytes = statistics.mean(bytes_list)
            stdev_bytes = statistics.stdev(bytes_list) if len(bytes_list) > 1 else 0
        except Exception:
            mean_bytes = 0
            stdev_bytes = 0

        # Dynamic threshold calculation (Mean + 2.5 * Standard Deviation)
        anomaly_threshold = mean_bytes + (cls.BYTE_THRESHOLD_MULTIPLIER * stdev_bytes) if stdev_bytes > 0 else mean_bytes * 2

        analyzed_flows = []
        for flow in flows:
            flow_copy = dict(flow)
            bytes_transferred = flow_copy.get("bytes_transferred", 0)
            
            is_volume_anomaly = bytes_transferred > anomaly_threshold and bytes_transferred > 10000000 # Minimum 10MB filter
            
            flow_copy.update({
                "statistical_anomaly": is_volume_anomaly,
                "anomaly_score": round(bytes_transferred / (anomaly_threshold or 1), 2)
            })
            analyzed_flows.append(flow_copy)

        return analyzed_flows
