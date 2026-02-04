#!/usr/bin/env python3
"""
Malicious verifier that exploits the bug in server.py to extract the graph coloring.

The bug: The prover responds to unlimited queries (while True loop), allowing us
to query the same edges multiple times with different permutations.

Attack strategy:
1. For each edge, query it multiple times (e.g., 20 times)
2. Record all (color_u, color_v) pairs seen for that edge
3. Use consistency constraints to deduce the original coloring
"""

import json
import socket
import networkx as nx
from networkx.readwrite import json_graph
from utils import verify_commitment
from collections import defaultdict


class MaliciousVerifier:
    def __init__(self, host='localhost', port=1337):
        self.host = host
        self.port = port
        self.sock = None
        self.G = None
        self.observations = defaultdict(list)  # edge -> list of (color_u, color_v) tuples
        
    def connect(self):
        """Connect to the prover server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        # Receive initial message with the graph
        msg = self.recv_msg()
        print(f"[+] Connected to prover")
        print(f"[+] Statement: {msg['statement']}")
        self.G = json_graph.adjacency_graph(msg['graph'])
        print(f"[+] Graph has {self.G.number_of_nodes()} nodes and {self.G.number_of_edges()} edges")
        
    def send_msg(self, m: dict):
        """Send a JSON message to the prover"""
        self.sock.sendall(json.dumps(m).encode('utf-8') + b'\n')
        
    def recv_msg(self) -> dict:
        """Receive a JSON message from the prover"""
        data = b''
        while b'\n' not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return json.loads(data.decode('utf-8'))
    
    def query_edge(self, u: int, v: int) -> tuple:
        """
        Query an edge and return the revealed colors.
        
        Returns:
            (color_u, color_v): The permuted colors revealed by the prover
        """
        # Receive commitments
        msg = self.recv_msg()
        commitments = [bytes.fromhex(c) for c in msg['commitments']]
        
        # Send challenge
        self.send_msg({'query': {'u': u, 'v': v}})
        
        # Receive opening
        msg = self.recv_msg()
        color_u = msg['opening']['u'][0]
        random_u = bytes.fromhex(msg['opening']['u'][1])
        color_v = msg['opening']['v'][0]
        random_v = bytes.fromhex(msg['opening']['v'][1])
        
        # Verify commitments
        assert verify_commitment(commitments[u], color_u.to_bytes(1), random_u), "Invalid commitment for u"
        assert verify_commitment(commitments[v], color_v.to_bytes(1), random_v), "Invalid commitment for v"
        
        # Verify colors are different
        assert color_u != color_v, "Colors must be different"
        assert color_u in [0, 1, 2] and color_v in [0, 1, 2], "Invalid colors"
        
        return (color_u, color_v)
    
    def collect_observations(self, queries_per_edge=20):
        """
        Query each edge multiple times to collect observations.
        """
        print(f"[+] Collecting observations ({queries_per_edge} queries per edge)...")
        edges = list(self.G.edges())
        
        for edge_idx, (u, v) in enumerate(edges):
            if edge_idx % 50 == 0:
                print(f"    Progress: {edge_idx}/{len(edges)} edges")
            
            for _ in range(queries_per_edge):
                color_u, color_v = self.query_edge(u, v)
                self.observations[(u, v)].append((color_u, color_v))
        
        print(f"[+] Collected observations for {len(edges)} edges")
    
    def deduce_coloring(self) -> list:
        """
        Deduce the original coloring from observations.
        
        Strategy:
        - For each edge (u,v), we observe pairs (π(c(u)), π(v(v))) for different π
        - If c(u) = 0 and c(v) = 1, we'll see pairs like:
          - π={0→0,1→1,2→2}: (0,1)
          - π={0→1,1→2,2→0}: (1,2)
          - π={0→2,1→0,2→1}: (2,0)
        - The key insight: the PATTERN of pairs identifies the original (c(u), c(v))
        
        We'll use a constraint satisfaction approach:
        1. Try all possible colorings
        2. Check if each is consistent with observations
        """
        print("[+] Deducing original coloring...")
        n = self.G.number_of_nodes()
        
        # We'll use a graph coloring approach: assign colors and check consistency
        coloring = [-1] * n  # -1 means unassigned
        
        # Start by assigning color 0 to node 0 (arbitrary choice)
        coloring[0] = 0
        queue = [0]
        
        while queue:
            u = queue.pop(0)
            
            for v in self.G.neighbors(u):
                if coloring[v] != -1:
                    continue  # Already colored
                
                # Find edge in observations (might be (u,v) or (v,u))
                if (u, v) in self.observations:
                    obs = self.observations[(u, v)]
                    # Deduce c(v) from c(u) and observations
                    coloring[v] = self.deduce_neighbor_color(coloring[u], obs, is_first=True)
                elif (v, u) in self.observations:
                    obs = self.observations[(v, u)]
                    # Deduce c(v) from c(u) and observations
                    coloring[v] = self.deduce_neighbor_color(coloring[u], obs, is_first=False)
                else:
                    raise ValueError(f"No observations for edge ({u}, {v})")
                
                queue.append(v)
        
        return coloring
    
    def deduce_neighbor_color(self, known_color: int, observations: list, is_first: bool) -> int:
        """
        Given the color of one node and observations of an edge, deduce the other node's color.
        
        Args:
            known_color: The color (0, 1, or 2) of the known node
            observations: List of (color_u, color_v) pairs seen
            is_first: True if known_color is for the first node in the pair
        
        Returns:
            The deduced color for the unknown node
        """
        # Count which pairs we see
        pair_counts = defaultdict(int)
        for pair in observations:
            pair_counts[pair] += 1
        
        # Try each possible color for the unknown node
        for candidate_color in [0, 1, 2]:
            if candidate_color == known_color:
                continue  # Must be different
            
            # Check if this candidate is consistent with observations
            # If known_color=0 and candidate=1, we expect to see pairs that come from
            # permuting (0,1) in different ways
            expected_pairs = self.generate_expected_pairs(known_color, candidate_color, is_first)
            
            # Check if observed pairs match expected pairs
            observed_pairs = set(pair_counts.keys())
            if observed_pairs == expected_pairs:
                return candidate_color
        
        # If we can't deduce uniquely, use a heuristic
        # The most common pattern should correspond to the right answer
        if is_first:
            # known_color is first in pair, find most common second color
            second_colors = [pair[1] for pair in observations]
        else:
            # known_color is second in pair, find most common first color
            second_colors = [pair[0] for pair in observations]
        
        from collections import Counter
        most_common = Counter(second_colors).most_common(3)
        
        # Return the most common color that's not known_color
        for color, count in most_common:
            if color != known_color:
                return color
        
        raise ValueError("Cannot deduce neighbor color")
    
    def generate_expected_pairs(self, color1: int, color2: int, is_first: bool) -> set:
        """
        Generate all possible pairs (π(color1), π(color2)) or (π(color2), π(color1))
        for all permutations π of {0,1,2}.
        """
        # All permutations of {0,1,2}
        import itertools
        pairs = set()
        
        for perm in itertools.permutations([0, 1, 2]):
            if is_first:
                pairs.add((perm[color1], perm[color2]))
            else:
                pairs.add((perm[color2], perm[color1]))
        
        return pairs
    
    def verify_coloring(self, coloring: list) -> bool:
        """Verify that the deduced coloring is valid"""
        for u, v in self.G.edges():
            if coloring[u] == coloring[v]:
                return False
        return True
    
    def attack(self, queries_per_edge=20):
        """
        Execute the full attack.
        
        Returns:
            The extracted coloring
        """
        self.connect()
        self.collect_observations(queries_per_edge)
        coloring = self.deduce_coloring()
        
        if self.verify_coloring(coloring):
            print("[+] Successfully extracted a valid coloring!")
        else:
            print("[!] Warning: Extracted coloring is invalid!")
        
        self.sock.close()
        return coloring


def main():
    print("=" * 60)
    print("Malicious Verifier - Extracting Graph Coloring")
    print("=" * 60)
    
    attacker = MaliciousVerifier()
    coloring = attacker.attack(queries_per_edge=10)  # Reduced for speed
    
    print("\n[+] Extracted coloring:")
    print(coloring)
    
    # Save to file
    with open('extracted_coloring.json', 'w') as f:
        json.dump(coloring, f)
    print("[+] Saved to extracted_coloring.json")
    
    # Compare with original if available
    try:
        with open('3col-coloring.json', 'r') as f:
            original = json.load(f)
        
        # Check if they're the same up to permutation
        # (since we might extract a different valid coloring)
        if coloring == original:
            print("[+] Extracted coloring matches original exactly!")
        else:
            print("[+] Extracted coloring differs from original (but may be valid)")
            
            # Check if it's a permutation
            from collections import Counter
            if Counter(coloring) == Counter(original):
                print("    - Same color distribution (likely a valid alternative coloring)")
    except FileNotFoundError:
        pass


if __name__ == '__main__':
    main()
