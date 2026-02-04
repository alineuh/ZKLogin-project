from matplotlib import pyplot as plt
import networkx as nx
from networkx.readwrite import json_graph
from secrets import SystemRandom
import json
import sys

N = 999
C = 10


def gen_3col(n: int, c: int=10) -> (nx.Graph, [int]):
    assert n % 3 == 0
    t = n // 3
    G = nx.generators.empty_graph(n)
    sr = SystemRandom()
    perm = list(range(n))
    sr.shuffle(perm)
    p = c / n
    for k in range(2):
        for u in range(k * t, (k+1) * t):
            for v in range((k+1) * t, n):
                if sr.random() <= p:
                    G.add_edge(perm[u], perm[v % n])

    coloring = [0] * n
    for u in range(t, 2*t):
        coloring[perm[u]] = 1
    for u in range(2*t, n):
        coloring[perm[u]] = 2

    return G, coloring


def main(file):
    G, coloring = gen_3col(N)

    for (u, v) in G.edges():
        assert coloring[u] != coloring[v], (u, v)

    #  nx.draw(G, node_color=[['blue', 'green', 'red'][c] for c in coloring])
    #  plt.show()

    with open(f'{file}-graph.json', 'w') as f:
        json.dump(json_graph.adjacency_data(G), f)
    with open(f'{file}-coloring.json', 'w') as f:
        json.dump(coloring, f)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <output-prefix>')
        exit(1)
    main(sys.argv[1])
