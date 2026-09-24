import json
import os
from typing import List, Dict, Any

class FlowParser:
    """
    Ingests VPC network flow logs for security analysis and anomaly monitoring.
    """

    DEFAULT_LOG_PATH = "data/vpc_flow_logs.json"

    @classmethod
    def load_flows(cls, filepath: str = DEFAULT_LOG_PATH) -> List[Dict[str, Any]]:
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("flows", [])
        except Exception:
            return []
