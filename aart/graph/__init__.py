# Notes from Ahsan
# This is for building a graph representation of the app's routes and middleware.
# The graph can then be analyzed to find routes that are unprotected or have privilege gaps.

from dataclasses import dataclass, field
from ingestion.extractor import Route

@dataclass
class Node:
    id: str
    node_type: str      # 'route', 'middleware', 'role'
    label: str
    metadata: dict = field(default_factory=dict)

@dataclass
class Edge:
    from_id: str
    to_id: str
    edge_type: str      # 'protected_by', 'requires_role', 'accesses'

class AppGraph:
    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def add_node(self, node: Node):
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge):
        self.edges.append(edge)

    def get_neighbors(self, node_id: str, edge_type: str = None) -> list[Node]:
        result = []
        for edge in self.edges:
            if edge.from_id == node_id:
                if edge_type is None or edge.edge_type == edge_type:
                    if edge.to_id in self.nodes:
                        result.append(self.nodes[edge.to_id])
        return result

    def find_unprotected_paths(self) -> list[Node]:
        """
        Return all route nodes that have no 'protected_by' edge —
        i.e. routes reachable without passing through any middleware.
        """
        route_nodes = [n for n in self.nodes.values() if n.node_type == 'route']
        protected_ids = {e.from_id for e in self.edges if e.edge_type == 'protected_by'}
        return [r for r in route_nodes if r.id not in protected_ids]

    def find_privilege_gaps(self) -> list[tuple[Node, Node]]:
        """
        Find pairs of route nodes on the same resource where one requires
        a role and the other doesn't.
        """
        gaps = []
        route_nodes = [n for n in self.nodes.values() if n.node_type == 'route']

        # Group by resource
        from collections import defaultdict
        by_resource = defaultdict(list)
        for node in route_nodes:
            resource = node.metadata.get('resource', '')
            by_resource[resource].append(node)

        for resource, group in by_resource.items():
            elevated = [n for n in group if n.metadata.get('requires_elevated')]
            normal   = [n for n in group if not n.metadata.get('requires_elevated')]
            if elevated and normal:
                for e in elevated:
                    for n in normal:
                        gaps.append((e, n))

        return gaps

    def summary(self):
        print(f"[Graph] {len(self.nodes)} nodes, {len(self.edges)} edges")
        for node in self.nodes.values():
            neighbors = self.get_neighbors(node.id)
            neighbor_labels = [n.label for n in neighbors]
            print(f"  {node.node_type.upper()} '{node.label}' → {neighbor_labels}")


def build_graph(routes: list[Route]) -> AppGraph:
    graph = AppGraph()

    ELEVATED_MW = {'isadmin', 'admin', 'requireadmin', 'superuser', 'isstaff'}

    for route in routes:
        # Determine resource name from path
        parts = [p for p in route.path.split('/') if p and not p.startswith(':')]
        resource = parts[0] if parts else route.path
        requires_elevated = any(m.lower() in ELEVATED_MW for m in route.middleware)

        # Create route node
        route_id = f"route:{route.method}:{route.path}"
        graph.add_node(Node(
            id=route_id,
            node_type='route',
            label=f"{route.method} {route.path}",
            metadata={
                'handler': route.handler,
                'resource': resource,
                'requires_elevated': requires_elevated,
                'has_dynamic_segment': ':' in route.path,
            }
        ))

        # Create middleware nodes + edges
        for mw in route.middleware:
            mw_id = f"middleware:{mw}"
            if mw_id not in graph.nodes:
                graph.add_node(Node(
                    id=mw_id,
                    node_type='middleware',
                    label=mw,
                    metadata={'is_elevated': mw.lower() in ELEVATED_MW}
                ))
            graph.add_edge(Edge(
                from_id=route_id,
                to_id=mw_id,
                edge_type='protected_by'
            ))

        # Create role nodes for elevated middleware
        for mw in route.middleware:
            if mw.lower() in ELEVATED_MW:
                role_id = f"role:{mw}"
                if role_id not in graph.nodes:
                    graph.add_node(Node(
                        id=role_id,
                        node_type='role',
                        label=mw,
                    ))
                graph.add_edge(Edge(
                    from_id=route_id,
                    to_id=role_id,
                    edge_type='requires_role'
                ))

    return graph