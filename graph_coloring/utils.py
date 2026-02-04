import os
from hashlib import sha3_256
import networkx as nx

def commit(m: bytes) -> (bytes, bytes):
    h = sha3_256(m)
    r = os.urandom(32)
    h.update(r)
    c = h.digest()
    return c, r


def verify_commitment(c: bytes, m: bytes, r: bytes) -> bool:
    h = sha3_256(m)
    h.update(r)
    c_prime = h.digest()
    return len(r) == 32 and c_prime == c


def is_valid_coloring(G: nx.Graph, coloring: [int]) -> bool:
    n = G.number_of_nodes()
    if sorted(G.nodes) != list(range(n)):
        return False
    if len(coloring) != n:
        return False
    if any(c not in [0, 1, 2] for c in coloring):
        return False
    if any(coloring[u] == coloring[v] for u, v in G.edges):
        return False
    return True
