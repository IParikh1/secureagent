"""Cloud resource graph extension for SecureAgent."""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .models import CapabilityGraph, Node, Edge, NodeType, EdgeType


class CloudNodeType:
    """Cloud-specific node type constants."""

    S3_BUCKET = "s3_bucket"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    EC2_INSTANCE = "ec2_instance"
    SECURITY_GROUP = "security_group"
    RDS_INSTANCE = "rds_instance"
    LAMBDA_FUNCTION = "lambda_function"
    VPC = "vpc"
    SUBNET = "subnet"
    KMS_KEY = "kms_key"


@dataclass
class CloudResource:
    """Cloud resource representation."""

    id: str
    type: str
    name: str
    region: str
    account_id: Optional[str] = None
    properties: Dict[str, Any] = None
    tags: Dict[str, str] = None

    def __post_init__(self):
        self.properties = self.properties or {}
        self.tags = self.tags or {}


class CloudGraphExtension:
    """Extend capability graph with cloud resources."""

    def __init__(self, graph: CapabilityGraph):
        """Initialize with base graph."""
        self.graph = graph

    def add_cloud_resource(self, resource: CloudResource) -> Node:
        """Add a cloud resource as a node."""
        node = Node(
            id=f"cloud:{resource.type}:{resource.id}",
            type=NodeType.RESOURCE,
            name=resource.name,
            properties={
                "cloud_type": resource.type,
                "region": resource.region,
                "account_id": resource.account_id,
                **resource.properties,
            },
            metadata={"tags": resource.tags},
        )
        self.graph.add_node(node)
        return node

    def add_iam_relationship(
        self,
        principal_id: str,
        resource_id: str,
        actions: List[str],
    ) -> Edge:
        """Add IAM relationship between principal and resource."""
        edge = Edge(
            source_id=principal_id,
            target_id=resource_id,
            type=EdgeType.GRANTS,
            properties={"actions": actions},
        )
        self.graph.add_edge(edge)
        return edge

    def add_network_relationship(
        self,
        source_id: str,
        target_id: str,
        ports: List[int],
        protocol: str = "tcp",
    ) -> Edge:
        """Add network relationship between resources."""
        edge = Edge(
            source_id=source_id,
            target_id=target_id,
            type=EdgeType.ACCESSES,
            properties={"ports": ports, "protocol": protocol},
        )
        self.graph.add_edge(edge)
        return edge

    def add_encryption_relationship(
        self,
        resource_id: str,
        kms_key_id: str,
    ) -> Edge:
        """Add encryption relationship."""
        edge = Edge(
            source_id=kms_key_id,
            target_id=resource_id,
            type=EdgeType.PROTECTS,
            properties={"protection_type": "encryption"},
        )
        self.graph.add_edge(edge)
        return edge

    def import_aws_resources(
        self,
        resources: List[Dict[str, Any]],
    ) -> List[Node]:
        """Import AWS resources into the graph."""
        nodes = []

        for resource in resources:
            cloud_resource = CloudResource(
                id=resource.get("id", resource.get("arn", "")),
                type=resource.get("type", "unknown"),
                name=resource.get("name", ""),
                region=resource.get("region", ""),
                account_id=resource.get("account_id"),
                properties=resource.get("properties", {}),
                tags=resource.get("tags", {}),
            )
            node = self.add_cloud_resource(cloud_resource)
            nodes.append(node)

            # Auto-detect relationships
            self._detect_relationships(resource, node)

        return nodes

    def _detect_relationships(
        self,
        resource: Dict[str, Any],
        node: Node,
    ) -> None:
        """Detect and add relationships for a resource."""
        resource_type = resource.get("type", "")
        properties = resource.get("properties", {})

        # IAM role attached to Lambda/EC2
        if "role_arn" in properties or "iam_role" in properties:
            role_arn = properties.get("role_arn") or properties.get("iam_role")
            role_id = f"cloud:iam_role:{role_arn}"
            if role_id in self.graph.nodes:
                self.graph.add_edge(
                    Edge(
                        source_id=role_id,
                        target_id=node.id,
                        type=EdgeType.GRANTS,
                    )
                )

        # Security group associations
        if "security_groups" in properties:
            for sg in properties["security_groups"]:
                sg_id = f"cloud:security_group:{sg}"
                if sg_id in self.graph.nodes:
                    self.graph.add_edge(
                        Edge(
                            source_id=sg_id,
                            target_id=node.id,
                            type=EdgeType.PROTECTS,
                        )
                    )

        # KMS encryption
        if "kms_key_id" in properties:
            kms_id = f"cloud:kms_key:{properties['kms_key_id']}"
            if kms_id in self.graph.nodes:
                self.add_encryption_relationship(node.id, kms_id)

        # VPC/Subnet associations
        if "vpc_id" in properties:
            vpc_id = f"cloud:vpc:{properties['vpc_id']}"
            if vpc_id in self.graph.nodes:
                self.graph.add_edge(
                    Edge(
                        source_id=node.id,
                        target_id=vpc_id,
                        type=EdgeType.DEPENDS_ON,
                    )
                )

    def find_public_resources(self) -> List[Node]:
        """Find publicly accessible cloud resources."""
        public = []

        for node in self.graph.nodes.values():
            if node.type != NodeType.RESOURCE:
                continue

            properties = node.properties

            # Check for public access indicators
            is_public = False

            if properties.get("cloud_type") == CloudNodeType.S3_BUCKET:
                if properties.get("public_access") or properties.get("acl") == "public-read":
                    is_public = True

            if properties.get("cloud_type") == CloudNodeType.SECURITY_GROUP:
                if "0.0.0.0/0" in str(properties.get("ingress_rules", "")):
                    is_public = True

            if properties.get("cloud_type") == CloudNodeType.RDS_INSTANCE:
                if properties.get("publicly_accessible"):
                    is_public = True

            if is_public:
                public.append(node)

        return public

    def find_unencrypted_resources(self) -> List[Node]:
        """Find resources without encryption."""
        unencrypted = []

        encryption_types = [
            CloudNodeType.S3_BUCKET,
            CloudNodeType.RDS_INSTANCE,
            CloudNodeType.EC2_INSTANCE,
        ]

        for node in self.graph.nodes.values():
            if node.type != NodeType.RESOURCE:
                continue

            cloud_type = node.properties.get("cloud_type")
            if cloud_type not in encryption_types:
                continue

            # Check for encryption
            has_encryption = False

            # Check for KMS relationship
            for edge in self.graph.get_edges_to(node.id):
                if (
                    edge.type == EdgeType.PROTECTS
                    and edge.properties.get("protection_type") == "encryption"
                ):
                    has_encryption = True
                    break

            # Check properties
            if node.properties.get("encrypted") or node.properties.get("kms_key_id"):
                has_encryption = True

            if not has_encryption:
                unencrypted.append(node)

        return unencrypted

    def find_overprivileged_roles(self) -> List[Node]:
        """Find IAM roles with excessive permissions."""
        overprivileged = []

        for node in self.graph.nodes.values():
            if node.properties.get("cloud_type") != CloudNodeType.IAM_ROLE:
                continue

            # Check edges for wildcard permissions
            edges = self.graph.get_edges_from(node.id)
            for edge in edges:
                if edge.type == EdgeType.GRANTS:
                    actions = edge.properties.get("actions", [])
                    if "*" in actions or any("*" in a for a in actions):
                        overprivileged.append(node)
                        break

            # Check attached policies
            policies = node.properties.get("attached_policies", [])
            admin_policies = ["AdministratorAccess", "PowerUserAccess"]
            if any(p in str(policies) for p in admin_policies):
                if node not in overprivileged:
                    overprivileged.append(node)

        return overprivileged

    def calculate_cloud_risk_score(self, node_id: str) -> float:
        """Calculate risk score for a cloud resource."""
        node = self.graph.get_node(node_id)
        if not node or node.type != NodeType.RESOURCE:
            return 0.0

        risk = 0.0

        # Public access risk
        if node in self.find_public_resources():
            risk += 0.4

        # Encryption risk
        if node in self.find_unencrypted_resources():
            risk += 0.3

        # Permission risk
        if node.properties.get("cloud_type") == CloudNodeType.IAM_ROLE:
            if node in self.find_overprivileged_roles():
                risk += 0.4

        # Network exposure
        sg_edges = [
            e
            for e in self.graph.get_edges_to(node_id)
            if self.graph.nodes.get(e.source_id, Node("", NodeType.RESOURCE, "")).properties.get(
                "cloud_type"
            )
            == CloudNodeType.SECURITY_GROUP
        ]
        if not sg_edges:
            risk += 0.2  # No security group

        return min(risk, 1.0)
