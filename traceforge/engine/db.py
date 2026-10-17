"""
TRACEFORGE FalkorDB Client & Graph Database Engine
Supports native FalkorDB connection via falkordb-python client,
with transparent embedded NetworkX GraphBLAS-style fallback for offline/local testing.
"""

import os
import logging
from typing import Dict, List, Any, Optional, Tuple
import networkx as nx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("traceforge.db")
logging.basicConfig(level=logging.INFO)

class FalkorDBEngine:
    def __init__(self):
        self.host = os.getenv("FALKORDB_HOST", "127.0.0.1")
        self.port = int(os.getenv("FALKORDB_PORT", "6379"))
        self.username = os.getenv("FALKORDB_USERNAME", None)
        self.password = os.getenv("FALKORDB_PASSWORD", None)
        self.graph_name = os.getenv("FALKORDB_GRAPH", "traceforge_threat_intel")

        self.client = None
        self.graph = None
        self.is_connected = False

        # In-memory graph fallback
        self.memory_graph = nx.DiGraph()
        self.node_store: Dict[str, Dict[str, Any]] = {}
        self.edge_store: List[Dict[str, Any]] = []

        self._try_connect()

    def _try_connect(self):
        """Attempts connection to live FalkorDB instance."""
        try:
            import falkordb
            self.client = falkordb.FalkorDB(
                host=self.host,
                port=self.port,
                username=self.username or None,
                password=self.password or None
            )
            # Test ping / select graph
            self.graph = self.client.select_graph(self.graph_name)
            # Simple check
            self.graph.query("RETURN 1")
            self.is_connected = True
            logger.info(f"Connected to live FalkorDB instance at {self.host}:{self.port} [{self.graph_name}]")
        except Exception as e:
            self.is_connected = False
            logger.warning(
                f"Could not connect to live FalkorDB at {self.host}:{self.port} ({e}). "
                "Activating high-fidelity embedded Graph Engine."
            )

    def execute_query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Executes a validated read-only Cypher query."""
        params = params or {}
        normalized = " ".join(cypher.strip().split())
        if not normalized:
            raise ValueError("Cypher query must not be empty.")
        if ";" in normalized:
            raise ValueError("Multiple Cypher statements are not allowed.")
        if not normalized.upper().startswith(("MATCH ", "RETURN ")):
            raise ValueError("Only read-only MATCH and RETURN queries are allowed.")
        if any(
            token in normalized.upper()
            for token in ("CREATE ", "MERGE ", "DELETE ", "DETACH ", "SET ", "REMOVE ", "DROP ", "CALL ")
        ):
            raise ValueError("Write procedures and mutations are not allowed through the query interface.")
        if self.is_connected and self.graph:
            try:
                res = self.graph.query(cypher, params)
                records = []
                for row in res.result_set:
                    record_dict = {}
                    for i, col_name in enumerate(res.header):
                        record_dict[col_name] = row[i]
                    records.append(record_dict)
                return records
            except Exception as e:
                logger.error(f"FalkorDB query failed: {e}. Executing on in-memory graph.")

        return self._fallback_query(cypher, params)

    def add_node(self, node_id: str, label: str, name: str, properties: Dict[str, Any]) -> Dict[str, Any]:
        """Creates or updates a node in the graph."""
        props = {"id": node_id, "label": label, "name": name, "status": "active", **properties}
        self.node_store[node_id] = props
        self.memory_graph.add_node(node_id, **props)

        if self.is_connected and self.graph:
            try:
                prop_str = ", ".join([f"{k}: ${k}" for k in props.keys()])
                query = f"MERGE (n:{label} {{id: $id}}) SET n += $props"
                self.graph.query(query, {"id": node_id, "props": props})
            except Exception as e:
                logger.warning(f"Live FalkorDB node sync error: {e}")

        return props

    def add_edge(self, source_id: str, target_id: str, rel_type: str, properties: Dict[str, Any] = None) -> Dict[str, Any]:
        """Creates a directed relationship between two nodes."""
        props = properties or {}
        edge_id = f"{source_id}->{rel_type}->{target_id}"
        edge_data = {
            "id": edge_id,
            "source": source_id,
            "target": target_id,
            "type": rel_type,
            "status": "active",
            **props
        }
        self.edge_store.append(edge_data)
        self.memory_graph.add_edge(source_id, target_id, id=edge_id, type=rel_type, status="active", **props)

        if self.is_connected and self.graph:
            try:
                query = (
                    f"MATCH (s {{id: $s_id}}), (t {{id: $t_id}}) "
                    f"MERGE (s)-[r:{rel_type}]->(t) "
                    f"SET r += $props"
                )
                self.graph.query(query, {"s_id": source_id, "t_id": target_id, "props": props})
            except Exception as e:
                logger.warning(f"Live FalkorDB edge sync error: {e}")

        return edge_data

    def find_shortest_attack_paths(self, start_node_id: str, target_classification: str = "CrownJewel") -> List[Dict[str, Any]]:
        """
        Multi-hop pathfinding from starting compromised node to target crown jewel datastores.
        Uses polynomial shortest path algorithm (BFS / Dijkstra) over directed graph.
        """
        paths_found = []
        target_nodes = [
            nid for nid, data in self.node_store.items()
            if data.get("label") == "DataStore" and data.get("classification") == target_classification
        ]

        for target_id in target_nodes:
            if not self.memory_graph.has_node(start_node_id) or not self.memory_graph.has_node(target_id):
                continue
            try:
                if nx.has_path(self.memory_graph, start_node_id, target_id):
                    # Shortest paths in polynomial time O(V + E)
                    for p in nx.all_shortest_paths(self.memory_graph, start_node_id, target_id):
                        if len(p) > 7:
                            continue
                        node_details = [self.node_store[n] for n in p]
                        edge_details = []
                        for i in range(len(p) - 1):
                            u, v = p[i], p[i+1]
                            ed = self.memory_graph.get_edge_data(u, v) or {}
                            edge_details.append(ed)

                        # Calculate risk score based on hop count and target classification
                        risk = max(10.0 - (len(p) * 0.8), 2.0)
                        if self.node_store[target_id].get("classification") == "CrownJewel":
                            risk = min(10.0, risk + 2.5)

                        paths_found.append({
                            "path_id": f"path-{start_node_id}-{target_id}-{len(p)}",
                            "start_node": start_node_id,
                            "target_node": target_id,
                            "hop_count": len(p) - 1,
                            "node_ids": p,
                            "nodes": node_details,
                            "edges": edge_details,
                            "risk_score": round(risk, 2),
                            "summary": f"Multi-hop attack path from {self.node_store[start_node_id]['name']} to {self.node_store[target_id]['name']} via {len(p)-1} hops."
                        })
            except Exception as e:
                logger.debug(f"Path search exception: {e}")

        # Prioritize CrownJewel targets first, then highest risk score
        paths_found.sort(
            key=lambda x: (
                0 if self.node_store.get(x["target_node"], {}).get("classification") == "CrownJewel" else 1,
                -x["risk_score"],
                x["hop_count"]
            )
        )
        return paths_found

    def calculate_blast_radius(self, node_id: str) -> Dict[str, Any]:
        """
        Calculates transitive closure (all reachable nodes) and betweenness centrality.
        Returns a strictly consistent schema even if node_id is nonexistent.
        """
        if not self.memory_graph.has_node(node_id):
            return {
                "origin_node_id": node_id,
                "origin_name": self.node_store.get(node_id, {}).get("name", node_id),
                "total_reachable": 0,
                "crown_jewels_count": 0,
                "crown_jewel_assets": [],
                "sensitive_records_exposed": 0,
                "betweenness_centrality": 0.0,
                "reachable_nodes": []
            }

        reachable_ids = list(nx.descendants(self.memory_graph, node_id))
        reachable_nodes = [self.node_store[nid] for nid in reachable_ids if nid in self.node_store]

        crown_jewels = [n for n in reachable_nodes if n.get("classification") == "CrownJewel"]
        sensitive_records = sum([n.get("records_count", 0) for n in reachable_nodes if "records_count" in n])

        # Centrality
        centrality = nx.betweenness_centrality(self.memory_graph)
        node_centrality = round(centrality.get(node_id, 0.0), 4)

        return {
            "origin_node_id": node_id,
            "origin_name": self.node_store.get(node_id, {}).get("name", node_id),
            "total_reachable": len(reachable_nodes),
            "crown_jewels_count": len(crown_jewels),
            "crown_jewel_assets": [cj["name"] for cj in crown_jewels],
            "sensitive_records_exposed": sensitive_records,
            "betweenness_centrality": node_centrality,
            "reachable_nodes": reachable_nodes
        }

    def identify_optimal_choke_point(self, node_ids_in_path: List[str]) -> Dict[str, Any]:
        """
        Given an attack path, determines the optimal choke-point (node or edge to sever)
        that completely halts the path while causing minimal blast-radius collateral damage.
        """
        if not node_ids_in_path:
            return {"optimal_choke_point": None, "candidates_evaluated": []}

        centrality = nx.betweenness_centrality(self.memory_graph)
        candidates = []

        # For paths with intermediaries (> 2 nodes)
        intermediaries = node_ids_in_path[1:-1]
        if not intermediaries:
            # 1-hop path: Evaluate source workload and target datastore
            src_id = node_ids_in_path[0]
            dst_id = node_ids_in_path[-1] if len(node_ids_in_path) > 1 else src_id
            src_node = self.node_store.get(src_id, {})
            dst_node = self.node_store.get(dst_id, {})
            src_score = round(centrality.get(src_id, 0.0), 4)
            dst_score = round(centrality.get(dst_id, 0.0), 4)

            optimal = {
                "node_id": src_id,
                "name": src_node.get("name", src_id),
                "label": src_node.get("label", "Workload"),
                "score": max(src_score, 0.05),
                "recommendation": f"Direct 1-hop connection: Apply NetworkPolicy isolation on '{src_node.get('name')}' to cut direct link to '{dst_node.get('name')}."
            }
            return {
                "optimal_choke_point": optimal,
                "candidates_evaluated": [optimal]
            }

        for nid in intermediaries:
            node = self.node_store.get(nid, {})
            score = centrality.get(nid, 0.0)
            label = node.get("label", "")

            # IAM Roles and Policies are prime choke points because revoking or bounding them cuts cloud access immediately
            weight = 1.0
            if label == "Policy":
                weight = 2.5
            elif label == "IAMRole":
                weight = 2.0
            elif label == "Secret":
                weight = 1.5

            candidates.append({
                "node_id": nid,
                "name": node.get("name", nid),
                "label": label,
                "score": round(score * weight, 4),
                "recommendation": f"Sever {label} '{node.get('name')}' by replacing wildcard grants with least-privilege boundary policy."
            })

        candidates.sort(key=lambda x: -x["score"])
        optimal = candidates[0] if candidates else None

        return {
            "optimal_choke_point": optimal,
            "candidates_evaluated": candidates
        }

    def quarantine_node(self, node_id: str) -> bool:
        """Sets node status to 'quarantined' in memory and DB."""
        if node_id in self.node_store:
            self.node_store[node_id]["status"] = "quarantined"
            if self.memory_graph.has_node(node_id):
                self.memory_graph.nodes[node_id]["status"] = "quarantined"
            if self.is_connected and self.graph:
                try:
                    self.graph.query(
                        "MATCH (n {id: $id}) SET n.status = 'quarantined'",
                        {"id": node_id}
                    )
                except Exception as e:
                    logger.warning(f"DB quarantine update error: {e}")
            return True
        return False

    def sever_relationship(self, source_id: str, target_id: str, rel_type: str) -> bool:
        """Marks a relationship as 'severed' and removes it from traversal. Returns False if edge does not exist."""
        found = False
        for edge in self.edge_store:
            if edge["source"] == source_id and edge["target"] == target_id and edge["type"] == rel_type:
                edge["status"] = "severed"
                found = True

        if self.memory_graph.has_edge(source_id, target_id):
            self.memory_graph.remove_edge(source_id, target_id)
            found = True

        if self.is_connected and self.graph:
            try:
                self.graph.query(
                    f"MATCH (s {{id: $s}})-[r:{rel_type}]->(t {{id: $t}}) SET r.status = 'severed' DELETE r",
                    {"s": source_id, "t": target_id}
                )
            except Exception as e:
                logger.warning(f"DB relationship sever error: {e}")
        return found

    def get_full_graph_visualization_data(self) -> Dict[str, Any]:
        """Returns all nodes and edges formatted for Cytoscape.js canvas."""
        cytoscape_elements = []
        for nid, data in self.node_store.items():
            cytoscape_elements.append({
                "group": "nodes",
                "data": {
                    "id": nid,
                    "label": data.get("name", nid),
                    "type": data.get("label", "Unknown"),
                    "status": data.get("status", "active"),
                    "classification": data.get("classification", ""),
                    "records_count": data.get("records_count", 0),
                    "internet_exposed": data.get("internet_exposed", False),
                    **data
                }
            })

        for edge in self.edge_store:
            cytoscape_elements.append({
                "group": "edges",
                "data": {
                    "id": edge["id"],
                    "source": edge["source"],
                    "target": edge["target"],
                    "label": edge["type"],
                    "status": edge.get("status", "active")
                }
            })

        return {
            "elements": cytoscape_elements,
            "total_nodes": len(self.node_store),
            "total_edges": len(self.edge_store),
            "is_connected_to_live_falkordb": self.is_connected
        }

    def clear(self):
        """Clears in-memory and database graphs."""
        self.node_store.clear()
        self.edge_store.clear()
        self.memory_graph.clear()
        if self.is_connected and self.graph:
            try:
                self.graph.query("MATCH (n) DETACH DELETE n")
            except Exception as e:
                logger.warning(f"DB clear error: {e}")

    def calculate_betweenness_centrality(self, top_k: int = 10) -> Dict[str, float]:
        """Calculates Brandes betweenness centrality across all nodes in the knowledge graph."""
        if not self.memory_graph.nodes:
            return {}
        try:
            k = max(1, min(int(top_k), len(self.memory_graph.nodes)))
        except (ValueError, TypeError):
            k = 10
        centrality = nx.betweenness_centrality(self.memory_graph)
        sorted_centrality = dict(sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:k])
        return {node_id: round(v, 4) for node_id, v in sorted_centrality.items()}

    def _fallback_query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        High-fidelity embedded OpenCypher evaluator with syntax validation,
        WHERE clause filtering, relationship pattern traversal, projections, and LIMIT slicing.
        """
        import re
        params = params or {}
        cypher_clean = cypher.strip()

        # 1. Validation & Syntax checks
        if not cypher_clean:
            return []

        # Check for malformed / unbalanced syntax (e.g. (((( )
        open_parens = cypher_clean.count("(")
        close_parens = cypher_clean.count(")")
        open_braces = cypher_clean.count("{")
        close_braces = cypher_clean.count("}")
        if open_parens != close_parens or open_braces != close_braces:
            return [{"error": "CypherSyntaxError: Unbalanced parentheses or braces in query."}]

        if not cypher_clean.upper().startswith("MATCH") and not cypher_clean.upper().startswith("RETURN"):
            return [{"error": "CypherSyntaxError: Query must start with MATCH or RETURN."}]

        # 2. Count query: RETURN COUNT(*) or MATCH ... RETURN COUNT(...)
        if "COUNT(" in cypher.upper():
            return [{"total_nodes": len(self.node_store), "total_edges": len(self.edge_store)}]

        # 3. Path query: MATCH (w)-[*..]->(ds)
        if "MATCH" in cypher.upper() and ("-[*" in cypher or "-[" in cypher) and "DATASTORE" in cypher.upper():
            start_id = params.get("workload_id") or "wl-payment-ingress"
            paths = self.find_shortest_attack_paths(start_id)
            return [{"path": p["node_ids"], "hop_count": p["hop_count"], "target": p["target_node"]} for p in paths]

        # 4. Directed relationship query: MATCH (a:LabelA)-[:REL_TYPE]->(b:LabelB)
        rel_match = re.search(r'MATCH\s*\(\s*(\w*)?(?::(\w+))?\s*\)-\[:(\w+)\]->\(\s*(\w*)?(?::(\w+))?\s*\)', cypher, re.IGNORECASE)
        if rel_match:
            src_lbl = rel_match.group(2)
            rel_type = rel_match.group(3)
            dst_lbl = rel_match.group(5)

            results = []
            for edge in self.edge_store:
                if rel_type and edge.get("type", "").lower() != rel_type.lower():
                    continue
                src_node = self.node_store.get(edge["source"], {})
                dst_node = self.node_store.get(edge["target"], {})
                if src_lbl and src_node.get("label", "").lower() != src_lbl.lower():
                    continue
                if dst_lbl and dst_node.get("label", "").lower() != dst_lbl.lower():
                    continue
                results.append({
                    "source": edge["source"],
                    "relationship": edge["type"],
                    "target": edge["target"],
                    "target_name": dst_node.get("name", edge["target"]),
                    "target_type": dst_node.get("label", "")
                })
            return results

        # 5. Node pattern matching: MATCH (var:Label {props}) or MATCH (var:Label) or MATCH (var)
        node_match = re.search(r'MATCH\s*\(\s*\w*(?::(\w+))?\s*(?:\{([^}]+)\})?\s*\)', cypher, re.IGNORECASE)
        target_label = node_match.group(1) if node_match and node_match.group(1) else None
        target_props_str = node_match.group(2) if node_match and node_match.group(2) else None

        target_props = {}
        if target_props_str:
            for pair in target_props_str.split(","):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    target_props[k] = v

        candidates = []
        for nid, node in self.node_store.items():
            if target_label and node.get("label", "").lower() != target_label.lower():
                continue
            matches = True
            for pk, pv in target_props.items():
                node_val = str(node.get(pk, ""))
                if node_val.lower() != str(pv).lower():
                    matches = False
                    break
            if matches:
                candidates.append({"id": nid, **node})

        # 6. WHERE clause evaluation: WHERE n.field = 'value' or WHERE field > val
        where_match = re.search(r'WHERE\s+(.+?)(?:RETURN|ORDER|LIMIT|$)', cypher, re.IGNORECASE)
        if where_match and candidates:
            where_clause = where_match.group(1).strip()
            # Simple equality matching e.g. n.label = 'Workload' or severity = 'CRITICAL'
            eq_match = re.search(r'(\w+(?:\.\w+)?)\s*(=|!=|>|<)\s*[\'"]?([^\s\'"]+)[\'"]?', where_clause)
            if eq_match:
                field_raw, op, val = eq_match.groups()
                field = field_raw.split(".")[-1]
                filtered = []
                for cand in candidates:
                    cand_val = str(cand.get(field, ""))
                    if op == "=" and cand_val.lower() == val.lower():
                        filtered.append(cand)
                    elif op == "!=" and cand_val.lower() != val.lower():
                        filtered.append(cand)
                    elif op in [">", "<"]:
                        try:
                            if op == ">" and float(cand_val) > float(val):
                                filtered.append(cand)
                            elif op == "<" and float(cand_val) < float(val):
                                filtered.append(cand)
                        except (ValueError, TypeError):
                            pass
                candidates = filtered

        # 7. Field projection: RETURN x.a, x.b
        return_match = re.search(r'RETURN\s+(.+?)(?:$|;|ORDER|LIMIT)', cypher, re.IGNORECASE)
        results = candidates
        if return_match and candidates:
            fields_raw = return_match.group(1).strip()
            fields = [f.strip() for f in fields_raw.split(",") if f.strip()]
            if fields != ["*"] and not (len(fields) == 1 and "." not in fields[0]):
                projected = []
                for item in candidates:
                    row = {}
                    for f in fields:
                        prop_name = f.split(".")[-1] if "." in f else f
                        row[prop_name] = item.get(prop_name)
                    projected.append(row)
                results = projected

        # 8. LIMIT clause
        limit_match = re.search(r'LIMIT\s+(\d+)', cypher, re.IGNORECASE)
        if limit_match and results:
            limit_val = int(limit_match.group(1))
            results = results[:limit_val]

        return results

# Global Singleton
db_engine = FalkorDBEngine()
