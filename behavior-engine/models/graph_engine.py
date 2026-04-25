"""
Graph-Based Botnet Detection Engine
Models traffic as a directed multigraph, runs community detection
to find coordinated bot clusters invisible to per-request analysis.

Nodes: IP addresses, browser fingerprints, sessions, endpoints
Edges: IP→Fingerprint, IP→Session, Session→Endpoint, Fingerprint→Fingerprint

Community detection via Louvain algorithm finds tightly-connected clusters.
High-homogeneity communities with shared fingerprints = bot farms.
"""
import networkx as nx
import community as community_louvain  # python-louvain
import numpy as np
import logging
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Minimum community size to flag
MIN_COMMUNITY_SIZE = 4
# Homogeneity threshold: fraction of nodes sharing same fingerprint type
HOMOGENEITY_THRESHOLD = 0.75
# Max graph size before pruning old edges
MAX_NODES = 50_000
EDGE_TTL_SECONDS = 3600  # prune edges older than 1 hour


@dataclass
class Community:
    id: int
    nodes: list
    size: int
    ips: list
    fingerprint_hashes: list
    homogeneity: float
    is_botnet: bool
    confidence: float
    detected_at: float = field(default_factory=time.time)


class GraphEngine:
    def __init__(self):
        self.G = nx.MultiDiGraph()
        self.communities: list[Community] = []
        self.known_botnet_fps: set = set()  # confirmed bot fingerprint hashes
        self.edge_timestamps: dict = {}  # (u, v) -> timestamp
        self._last_prune = time.time()

    def add_edge(
        self,
        ip: str,
        fingerprint_hash: Optional[str],
        session_id: Optional[str],
        endpoint: Optional[str],
    ):
        """Add a request event as edges in the graph."""
        now = time.time()
        ip_node = f"ip:{ip}"

        self.G.add_node(ip_node, type="ip", ip=ip)

        if fingerprint_hash:
            fp_node = f"fp:{fingerprint_hash}"
            self.G.add_node(fp_node, type="fingerprint", hash=fingerprint_hash)
            self.G.add_edge(ip_node, fp_node, ts=now, type="used_fp")
            self.edge_timestamps[(ip_node, fp_node)] = now

        if session_id:
            sess_node = f"sess:{session_id[:16]}"
            self.G.add_node(sess_node, type="session")
            self.G.add_edge(ip_node, sess_node, ts=now, type="created_session")
            self.edge_timestamps[(ip_node, sess_node)] = now

            if endpoint:
                ep_node = f"ep:{endpoint}"
                self.G.add_node(ep_node, type="endpoint")
                self.G.add_edge(sess_node, ep_node, ts=now, type="requested")
                self.edge_timestamps[(sess_node, ep_node)] = now

        # Periodic pruning
        if now - self._last_prune > 300:
            self._prune_old_edges(now)

    def _prune_old_edges(self, now: float):
        """Remove edges older than TTL to prevent memory explosion."""
        cutoff = now - EDGE_TTL_SECONDS
        to_remove = []

        for (u, v), ts in self.edge_timestamps.items():
            if ts < cutoff:
                to_remove.append((u, v))

        for (u, v) in to_remove:
            # MultiDiGraph can hold multiple parallel edges between the same pair.
            # remove_edge() only removes one; loop until all are gone.
            while self.G.has_edge(u, v):
                self.G.remove_edge(u, v)
            del self.edge_timestamps[(u, v)]

        # Remove isolated nodes
        isolated = list(nx.isolates(self.G))
        self.G.remove_nodes_from(isolated)

        self._last_prune = now
        logger.debug(f"Graph pruned: {len(to_remove)} edges, {len(isolated)} nodes removed. "
                     f"Now: {self.G.number_of_nodes()} nodes, {self.G.number_of_edges()} edges")

    def run_community_detection(self):
        """
        Run Louvain community detection on the undirected projection.
        Identifies clusters of IPs sharing fingerprints = potential bot farms.
        """
        if self.G.number_of_nodes() < MIN_COMMUNITY_SIZE:
            return

        # Work on undirected subgraph of IP and fingerprint nodes only
        ip_fp_nodes = [n for n, d in self.G.nodes(data=True)
                      if d.get("type") in ("ip", "fingerprint")]

        if len(ip_fp_nodes) < MIN_COMMUNITY_SIZE:
            return

        subG = self.G.subgraph(ip_fp_nodes).to_undirected()

        if subG.number_of_edges() == 0:
            return

        try:
            partition = community_louvain.best_partition(subG, resolution=1.2)
        except Exception as e:
            logger.error(f"Community detection failed: {e}")
            return

        # Group nodes by community
        groups = defaultdict(list)
        for node, comm_id in partition.items():
            groups[comm_id].append(node)

        self.communities = []
        for comm_id, nodes in groups.items():
            if len(nodes) < MIN_COMMUNITY_SIZE:
                continue

            ips = [n.replace("ip:", "") for n in nodes if n.startswith("ip:")]
            fps = [n.replace("fp:", "") for n in nodes if n.startswith("fp:")]

            if not ips or not fps:
                continue

            # Compute homogeneity: how many IPs share same fingerprint hash
            homogeneity = self._compute_homogeneity(nodes)
            is_botnet = homogeneity >= HOMOGENEITY_THRESHOLD and len(ips) >= MIN_COMMUNITY_SIZE

            confidence = min(1.0, homogeneity * (len(ips) / 10.0))

            community = Community(
                id=comm_id,
                nodes=nodes,
                size=len(nodes),
                ips=ips,
                fingerprint_hashes=fps,
                homogeneity=homogeneity,
                is_botnet=is_botnet,
                confidence=confidence,
            )
            self.communities.append(community)

            if is_botnet:
                logger.warning(
                    f"BOTNET CLUSTER DETECTED: community={comm_id}, "
                    f"ips={len(ips)}, fps={len(fps)}, "
                    f"homogeneity={homogeneity:.2f}, confidence={confidence:.2f}"
                )
                for fp in fps:
                    self.known_botnet_fps.add(fp)

        logger.info(f"Community detection: {len(self.communities)} communities, "
                    f"{sum(1 for c in self.communities if c.is_botnet)} botnets")

    def _compute_homogeneity(self, nodes: list) -> float:
        """
        Fraction of IPs sharing the most common fingerprint.
        High homogeneity = IPs using identical browser fingerprints = bot farm.
        """
        ip_to_fps = defaultdict(set)
        for node in nodes:
            if node.startswith("ip:"):
                ip = node
                for neighbor in self.G.neighbors(ip):
                    if neighbor.startswith("fp:"):
                        ip_to_fps[ip].add(neighbor)

        if not ip_to_fps:
            return 0.0

        # Find most common fingerprint across all IPs
        fp_counts = Counter()
        for fps in ip_to_fps.values():
            fp_counts.update(fps)

        if not fp_counts:
            return 0.0

        most_common_fp, most_common_count = fp_counts.most_common(1)[0]
        return most_common_count / len(ip_to_fps)

    def is_in_botnet_cluster(self, ip: str = None, fp_hash: str = None) -> bool:
        """Check if an IP or fingerprint is part of a known botnet cluster."""
        if fp_hash and fp_hash in self.known_botnet_fps:
            return True

        if ip:
            ip_node = f"ip:{ip}"
            for community in self.communities:
                if community.is_botnet and ip_node in community.nodes:
                    return True

        return False

    def get_communities(self) -> list[dict]:
        return [
            {
                "id": c.id,
                "size": c.size,
                "ip_count": len(c.ips),
                "fp_count": len(c.fingerprint_hashes),
                "homogeneity": round(c.homogeneity, 3),
                "is_botnet": c.is_botnet,
                "confidence": round(c.confidence, 3),
                "detected_at": c.detected_at,
                "sample_ips": c.ips[:5],
            }
            for c in self.communities
        ]

    def graph_stats(self) -> dict:
        return {
            "nodes": self.G.number_of_nodes(),
            "edges": self.G.number_of_edges(),
            "communities": len(self.communities),
            "botnet_communities": sum(1 for c in self.communities if c.is_botnet),
            "known_botnet_fps": len(self.known_botnet_fps),
        }
