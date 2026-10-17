"""
TRACEFORGE Scenario Seeder
Seeds a realistic multi-cloud infrastructure & IAM privilege graph into FalkorDB.
Demonstrates multi-hop privilege escalation to crown jewels with reproducible precision.
"""

import logging
from traceforge.engine.db import db_engine

logger = logging.getLogger("traceforge.seed")

def seed_enterprise_environment():
    """Seeds the full enterprise infrastructure and attack graph."""
    logger.info("Initializing enterprise graph environment in FalkorDB...")
    db_engine.clear()

    # ==========================================
    # 1. SECURITY ALERTS
    # ==========================================
    alerts = [
        {
            "id": "ALERT-2026-9812",
            "label": "Alert",
            "name": "GuardDuty: Backdoor:EC2/C&CActivity.B!DNS",
            "properties": {
                "rule": "CVE-2026-2241 (Remote Code Execution in Ingress Gateway)",
                "severity": "CRITICAL",
                "timestamp": "2026-10-10T21:00:00Z",
                "detector": "AWS GuardDuty + Falco Runtime",
                "target_workload_id": "wl-payment-ingress",
                "description": "Outbound C2 beaconing to known malicious IP 198.51.100.24 detected from pod container.",
                "status": "unresolved"
            }
        },
        {
            "id": "ALERT-2026-9815",
            "label": "Alert",
            "name": "Falco: Sensitive File Read in /etc/shadow",
            "properties": {
                "rule": "Privilege Escalation Probe",
                "severity": "HIGH",
                "timestamp": "2026-10-10T20:45:00Z",
                "detector": "K8s Falco Engine",
                "target_workload_id": "wl-auth-service",
                "description": "Unauthorized access attempt to system credentials directory.",
                "status": "investigating"
            }
        },
        {
            "id": "ALERT-2026-9820",
            "label": "Alert",
            "name": "CloudTrail: Excessive S3 ListObjects Calls",
            "properties": {
                "rule": "Data Enumeration Reconnaissance",
                "severity": "MEDIUM",
                "timestamp": "2026-10-10T19:30:00Z",
                "detector": "AWS CloudTrail Anomaly Detector",
                "target_workload_id": "wl-analytics-worker",
                "description": "High volume of enumeration requests across multiple regional buckets.",
                "status": "resolved"
            }
        }
    ]
    for a in alerts:
        db_engine.add_node(a["id"], a["label"], a["name"], a["properties"])

    # ==========================================
    # 2. COMPUTE WORKLOADS (Kubernetes Pods & Services)
    # ==========================================
    workloads = [
        {
            "id": "wl-payment-ingress",
            "label": "Workload",
            "name": "payment-ingress-api",
            "properties": {
                "type": "KubernetesPod",
                "namespace": "payments-prod",
                "ip": "10.244.3.42",
                "internet_exposed": True,
                "cluster": "eks-prod-eu-west-1",
                "image": "docker.io/fintech/payment-gateway:v2.14.2",
                "status": "compromised"  # Flagged by active incident
            }
        },
        {
            "id": "wl-auth-service",
            "label": "Workload",
            "name": "auth-identity-svc",
            "properties": {
                "type": "KubernetesPod",
                "namespace": "auth-prod",
                "ip": "10.244.5.19",
                "internet_exposed": False,
                "cluster": "eks-prod-eu-west-1",
                "image": "docker.io/fintech/auth-server:v1.9.0",
                "status": "active"
            }
        },
        {
            "id": "wl-analytics-worker",
            "label": "Workload",
            "name": "analytics-worker-batch",
            "properties": {
                "type": "KubernetesPod",
                "namespace": "data-platform",
                "ip": "10.244.8.88",
                "internet_exposed": False,
                "cluster": "eks-analytics-prod",
                "image": "docker.io/fintech/spark-worker:v3.5.0",
                "status": "active"
            }
        }
    ]
    for w in workloads:
        db_engine.add_node(w["id"], w["label"], w["name"], w["properties"])

    # Link Alert to Compromised Workload
    db_engine.add_edge("ALERT-2026-9812", "wl-payment-ingress", "DETECTED_ON", {"severity": "CRITICAL"})
    db_engine.add_edge("ALERT-2026-9815", "wl-auth-service", "DETECTED_ON", {"severity": "HIGH"})
    db_engine.add_edge("ALERT-2026-9820", "wl-analytics-worker", "DETECTED_ON", {"severity": "MEDIUM"})

    # ==========================================
    # 3. KUBERNETES IDENTITIES (ServiceAccounts)
    # ==========================================
    identities = [
        {
            "id": "id-k8s-payment-sa",
            "label": "Identity",
            "name": "sa-payment-frontend",
            "properties": {
                "type": "K8sServiceAccount",
                "namespace": "payments-prod",
                "iam_role_arn": "arn:aws:iam::112233445566:role/PaymentAppRole"
            }
        },
        {
            "id": "id-k8s-auth-sa",
            "label": "Identity",
            "name": "sa-auth-service",
            "properties": {
                "type": "K8sServiceAccount",
                "namespace": "auth-prod",
                "iam_role_arn": "arn:aws:iam::112233445566:role/CloudAdminEmergencyRole"
            }
        },
        {
            "id": "id-k8s-analytics-sa",
            "label": "Identity",
            "name": "sa-analytics-batch",
            "properties": {
                "type": "K8sServiceAccount",
                "namespace": "data-platform",
                "iam_role_arn": "arn:aws:iam::112233445566:role/AnalyticsReadOnlyRole"
            }
        }
    ]
    for i in identities:
        db_engine.add_node(i["id"], i["label"], i["name"], i["properties"])

    db_engine.add_edge("wl-payment-ingress", "id-k8s-payment-sa", "AUTHENTICATES_AS")
    db_engine.add_edge("wl-auth-service", "id-k8s-auth-sa", "AUTHENTICATES_AS")
    db_engine.add_edge("wl-analytics-worker", "id-k8s-analytics-sa", "AUTHENTICATES_AS")

    # ==========================================
    # 4. CLOUD IAM ROLES
    # ==========================================
    roles = [
        {
            "id": "role-payment-app",
            "label": "IAMRole",
            "name": "PaymentAppRole",
            "properties": {
                "arn": "arn:aws:iam::112233445566:role/PaymentAppRole",
                "trusted_entity": "oidc.eks.eu-west-1.amazonaws.com/id/payment-cluster",
                "risk_rating": "Critical"
            }
        },
        {
            "id": "role-super-admin",
            "label": "IAMRole",
            "name": "CloudAdminEmergencyRole",
            "properties": {
                "arn": "arn:aws:iam::112233445566:role/CloudAdminEmergencyRole",
                "trusted_entity": "oidc.eks.eu-west-1.amazonaws.com/id/auth-cluster",
                "risk_rating": "Extreme"
            }
        },
        {
            "id": "role-analytics-read",
            "label": "IAMRole",
            "name": "AnalyticsReadOnlyRole",
            "properties": {
                "arn": "arn:aws:iam::112233445566:role/AnalyticsReadOnlyRole",
                "trusted_entity": "oidc.eks.eu-west-1.amazonaws.com/id/analytics-cluster",
                "risk_rating": "Low"
            }
        }
    ]
    for r in roles:
        db_engine.add_node(r["id"], r["label"], r["name"], r["properties"])

    db_engine.add_edge("id-k8s-payment-sa", "role-payment-app", "CAN_ASSUME", {"mechanism": "IRSA / OIDC AssumeRoleWithWebIdentity"})
    db_engine.add_edge("id-k8s-auth-sa", "role-super-admin", "CAN_ASSUME", {"mechanism": "IRSA / OIDC AssumeRoleWithWebIdentity"})
    db_engine.add_edge("id-k8s-analytics-sa", "role-analytics-read", "CAN_ASSUME", {"mechanism": "IRSA / OIDC AssumeRoleWithWebIdentity"})

    # ==========================================
    # 5. IAM POLICIES (Permissions Boundary / Over-scoped Grants)
    # ==========================================
    policies = [
        {
            "id": "pol-legacy-payments",
            "label": "Policy",
            "name": "Policy-LegacyPayments-Overprivileged",
            "properties": {
                "effect": "Allow",
                "actions": ["kms:*", "s3:GetObject", "s3:ListBucket", "secretsmanager:GetSecretValue"],
                "resources": ["*"],
                "flaw": "Wildcard kms:* grant allows decrypting ANY KMS-managed S3 bucket",
                "severity": "CRITICAL"
            }
        },
        {
            "id": "pol-full-admin",
            "label": "Policy",
            "name": "Policy-AdministratorAccess-Emergency",
            "properties": {
                "effect": "Allow",
                "actions": ["*"],
                "resources": ["*"],
                "flaw": "Full cloud wildcard permissions",
                "severity": "CRITICAL"
            }
        },
        {
            "id": "pol-analytics-readonly",
            "label": "Policy",
            "name": "Policy-Analytics-S3Read",
            "properties": {
                "effect": "Allow",
                "actions": ["s3:GetObject", "s3:ListBucket"],
                "resources": ["arn:aws:s3:::static-assets-cdn/*"],
                "flaw": "None (Proper least privilege)",
                "severity": "LOW"
            }
        }
    ]
    for p in policies:
        db_engine.add_node(p["id"], p["label"], p["name"], p["properties"])

    db_engine.add_edge("role-payment-app", "pol-legacy-payments", "HAS_POLICY")
    db_engine.add_edge("role-super-admin", "pol-full-admin", "HAS_POLICY")
    db_engine.add_edge("role-analytics-read", "pol-analytics-readonly", "HAS_POLICY")

    # ==========================================
    # 6. SECRETS & CRYPTOGRAPHIC KEYS
    # ==========================================
    secrets = [
        {
            "id": "sec-master-kms",
            "label": "Secret",
            "name": "key-vault-master-eu-west",
            "properties": {
                "type": "AWS-KMS-CMK",
                "arn": "arn:aws:kms:eu-west-1:112233445566:key/mrk-849202a-9921",
                "algorithm": "AES-256-GCM",
                "status": "enabled",
                "key_usage": "ENCRYPT_DECRYPT"
            }
        },
        {
            "id": "sec-disaster-recovery-kms",
            "label": "Secret",
            "name": "key-backup-dr-global",
            "properties": {
                "type": "AWS-KMS-CMK",
                "arn": "arn:aws:kms:us-east-1:112233445566:key/dr-vault-9921",
                "algorithm": "AES-256-GCM",
                "status": "enabled"
            }
        }
    ]
    for s in secrets:
        db_engine.add_node(s["id"], s["label"], s["name"], s["properties"])

    db_engine.add_edge("pol-legacy-payments", "sec-master-kms", "PERMITS_ACCESS", {"action": "kms:Decrypt"})
    db_engine.add_edge("pol-full-admin", "sec-disaster-recovery-kms", "PERMITS_ACCESS", {"action": "kms:*"})

    # ==========================================
    # 7. TARGET CROWN JEWELS & SENSITIVE DATASTORES
    # ==========================================
    datastores = [
        {
            "id": "ds-customer-vault",
            "label": "DataStore",
            "name": "fintech-pci-cardholder-vault",
            "properties": {
                "type": "S3Bucket",
                "arn": "arn:aws:s3:::fintech-pci-cardholder-vault",
                "classification": "CrownJewel",
                "compliance_scope": "PCI-DSS Level 1 / GDPR",
                "records_count": 4500000,
                "encryption": "SSE-KMS (key-vault-master-eu-west)",
                "financial_liability_usd": "$45,000,000"
            }
        },
        {
            "id": "ds-corp-backup",
            "label": "DataStore",
            "name": "global-disaster-recovery-vault",
            "properties": {
                "type": "S3Bucket",
                "arn": "arn:aws:s3:::global-disaster-recovery-vault",
                "classification": "CrownJewel",
                "compliance_scope": "SOX / SOC2",
                "records_count": 12000000,
                "financial_liability_usd": "$120,000,000"
            }
        },
        {
            "id": "ds-auth-redis",
            "label": "DataStore",
            "name": "redis-session-cluster",
            "properties": {
                "type": "ElastiCache-Redis",
                "classification": "Confidential",
                "active_sessions": 340000,
                "encryption": "TLS In-Transit"
            }
        },
        {
            "id": "ds-public-assets",
            "label": "DataStore",
            "name": "static-assets-cdn",
            "properties": {
                "type": "S3Bucket",
                "classification": "Public",
                "records_count": 12500,
                "encryption": "SSE-S3"
            }
        }
    ]
    for ds in datastores:
        db_engine.add_node(ds["id"], ds["label"], ds["name"], ds["properties"])

    db_engine.add_edge("sec-master-kms", "ds-customer-vault", "DECRYPTS_RESOURCE", {"encrypted_at_rest": True})
    db_engine.add_edge("sec-disaster-recovery-kms", "ds-corp-backup", "DECRYPTS_RESOURCE", {"encrypted_at_rest": True})
    db_engine.add_edge("pol-analytics-readonly", "ds-public-assets", "PERMITS_ACCESS", {"action": "s3:GetObject"})

    # ==========================================
    # 8. LATERAL MOVEMENT NETWORK CONNECTIONS
    # ==========================================
    # The compromised payment pod can also reach the internal redis session cluster
    db_engine.add_edge("wl-payment-ingress", "ds-auth-redis", "CAN_NETWORK_REACH", {"port": 6379, "protocol": "TCP"})
    db_engine.add_edge("wl-auth-service", "ds-auth-redis", "CAN_NETWORK_REACH", {"port": 6379, "protocol": "TCP"})

    logger.info(
        f"Seeding completed successfully! Total Nodes: {len(db_engine.node_store)}, Total Relationships: {len(db_engine.edge_store)}"
    )
    return {
        "status": "success",
        "nodes_seeded": len(db_engine.node_store),
        "edges_seeded": len(db_engine.edge_store)
    }

if __name__ == "__main__":
    seed_enterprise_environment()
