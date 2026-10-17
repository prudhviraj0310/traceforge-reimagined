"""
TRACEFORGE Graph Schema & Data Model
Defines node labels, relationship types, classifications, and property contracts.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

class NodeLabel(str, Enum):
    ALERT = "Alert"
    WORKLOAD = "Workload"
    IDENTITY = "Identity"
    IAM_ROLE = "IAMRole"
    POLICY = "Policy"
    SECRET = "Secret"
    DATA_STORE = "DataStore"

class RelationType(str, Enum):
    DETECTED_ON = "DETECTED_ON"
    AUTHENTICATES_AS = "AUTHENTICATES_AS"
    CAN_ASSUME = "CAN_ASSUME"
    HAS_POLICY = "HAS_POLICY"
    PERMITS_ACCESS = "PERMITS_ACCESS"
    DECRYPTS_RESOURCE = "DECRYPTS_RESOURCE"
    CAN_NETWORK_REACH = "CAN_NETWORK_REACH"

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class Classification(str, Enum):
    CROWN_JEWEL = "CrownJewel"
    CONFIDENTIAL = "Confidential"
    INTERNAL = "Internal"
    PUBLIC = "Public"

class GraphNode(BaseModel):
    id: str
    label: NodeLabel
    name: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    status: str = "active"  # active | compromised | quarantined | isolated

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: RelationType
    properties: Dict[str, Any] = Field(default_factory=dict)
    status: str = "active"  # active | severed | denied

class AttackPathHop(BaseModel):
    from_node: str
    to_node: str
    relation: str
    reasoning: str

class AttackPath(BaseModel):
    path_id: str
    start_node: str
    target_crown_jewel: str
    hop_count: int
    nodes: List[Dict[str, Any]]
    relationships: List[Dict[str, Any]]
    choke_point_node_id: Optional[str] = None
    risk_score: float = 0.0
    summary: str = ""
