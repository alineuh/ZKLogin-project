#!/usr/bin/env python3
"""
Honest verifier for the 3-coloring zero-knowledge proof protocol.
"""

import json
import socket
import networkx as nx
from networkx.readwrite import json_graph
from utils import verify_commitment
from secrets import SystemRandom


class HonestVerifier:
    def __init__(self, host='localhost', port=1337):
        self.host = host
        self.port = port
        self.sock = None
        self.G = None
        self.num_rounds = None
        
    def connect(self):
        """Connect to the prover server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        # Receive initial message with the graph
        msg = self.recv_msg()
        print(f"[+] Connected to prover")
        print(f"[+] Statement: {msg['statement']}")
        self.G = json_graph.adjacency_graph(msg['graph'])
        self.num_rounds = msg.get('rounds', None)
        print(f"[+] Graph has {self.G.number_of_nodes()} nodes and {self.G.number_of_edges()} edges")
        if self.num_rounds:
            print(f"[+] Protocol will run for {self.num_rounds} rounds")
        
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
    
    def verify_round(self, rnd: int) -> bool:
        """
        Execute and verify one round of the protocol.
        
        Returns:
            True if the round passes, False otherwise
        """
        # Receive commitments
        msg = self.recv_msg()
        if 'status' in msg:
            print(f"[+] Received status: {msg['message']}")
            return True
            
        assert msg['round'] == rnd, f"Round mismatch: expected {rnd}, got {msg['round']}"
        commitments = [bytes.fromhex(c) for c in msg['commitments']]
        n = len(commitments)
        
        # Choose a random edge
        edges = list(self.G.edges())
        sr = SystemRandom()
        u, v = sr.choice(edges)
        
        print(f"[+] Round {rnd}: Challenging edge ({u}, {v})")
        
        # Send challenge
        self.send_msg({'query': {'u': u, 'v': v}})
        
        # Receive opening
        msg = self.recv_msg()
        color_u = msg['opening']['u'][0]
        random_u = bytes.fromhex(msg['opening']['u'][1])
        color_v = msg['opening']['v'][0]
        random_v = bytes.fromhex(msg['opening']['v'][1])
        
        # Verify commitments
        if not verify_commitment(commitments[u], color_u.to_bytes(1), random_u):
            print(f"[!] Round {rnd}: Invalid commitment for node {u}")
            return False
        
        if not verify_commitment(commitments[v], color_v.to_bytes(1), random_v):
            print(f"[!] Round {rnd}: Invalid commitment for node {v}")
            return False
        
        # Verify colors are valid and different
        if color_u not in [0, 1, 2] or color_v not in [0, 1, 2]:
            print(f"[!] Round {rnd}: Invalid colors: {color_u}, {color_v}")
            return False
        
        if color_u == color_v:
            print(f"[!] Round {rnd}: Same colors for adjacent nodes: {color_u}")
            return False
        
        print(f"    ✓ Commitments verified, colors differ: {color_u} ≠ {color_v}")
        return True
    
    def verify(self) -> bool:
        """
        Execute the full verification protocol.
        
        Returns:
            True if all rounds pass and the proof is accepted
        """
        self.connect()
        
        # If num_rounds is not specified, use a default
        if self.num_rounds is None:
            self.num_rounds = min(20, self.G.number_of_edges())  # Default for testing
            print(f"[+] Using default {self.num_rounds} rounds")
        
        print(f"\n[+] Starting verification protocol...")
        
        try:
            for rnd in range(1, self.num_rounds + 1):
                if not self.verify_round(rnd):
                    print(f"\n[✗] REJECT: Round {rnd} failed")
                    self.sock.close()
                    return False
            
            # Check for completion message
            try:
                msg = self.recv_msg()
                if msg.get('status') == 'complete':
                    print(f"\n[✓] ACCEPT: All {self.num_rounds} rounds passed successfully")
                    print(f"    {msg.get('message', '')}")
            except:
                print(f"\n[✓] ACCEPT: All {self.num_rounds} rounds passed")
            
        except Exception as e:
            print(f"\n[✗] REJECT: Error during verification: {e}")
            return False
        finally:
            self.sock.close()
        
        return True


def main():
    print("=" * 60)
    print("Honest Verifier - 3-Coloring Zero-Knowledge Proof")
    print("=" * 60)
    
    verifier = HonestVerifier()
    result = verifier.verify()
    
    if result:
        print("\n[+] ✓ Proof ACCEPTED - The graph is 3-colorable")
    else:
        print("\n[+] ✗ Proof REJECTED")


if __name__ == '__main__':
    main()
