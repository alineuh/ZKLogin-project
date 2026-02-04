import json
import networkx as nx
from networkx.readwrite import json_graph
import json
from socketserver import ForkingTCPServer, StreamRequestHandler
from secrets import SystemRandom
from utils import commit, is_valid_coloring

HOST = 'localhost'
PORT = 1337
GRAPH_FILE = '3col-graph.json'
COLOR_FILE = '3col-coloring.json'

def commit_to_coloring(coloring: [int]) -> ([bytes], [bytes]):
    """
    Commit to a permuted version of the given graph coloring.

    Input: A coloring as length-n list of colors 0, 1, 2
    Outputs:
    - random permutation over 0, 1, 2
    - commitments to the permuted color of each vertex
    - opening information for each commitment
    """

    # Assume the colors are encoded as 0, 1, 2:
    assert all(c in [0, 1, 2] for c in coloring)
    commitments = []
    openings = []

    # Sample a random permutation:
    sr = SystemRandom()
    perm = list(range(3))
    sr.shuffle(perm)

    # Commit to the permuted color for every vertex:
    for c in coloring:
        (c, r) = commit(perm[c].to_bytes(1))
        commitments.append(c)
        openings.append(r)

    return perm, commitments, openings


class Prover(StreamRequestHandler):
    def send_msg(self, m: dict):
        self.wfile.write(json.dumps(m).encode('utf-8'))
        self.wfile.write(b'\n')
        self.wfile.flush()

    def recv_msg(self) -> dict:
        return json.loads(self.rfile.readline().decode('utf-8'))

    def handle(self):
        n = self.server.G.number_of_nodes()

        print(f'[+] handling connection with "{self.client_address}"')
        try:
            self.send_msg({'statement': 'I know a coloring for the graph G.',
                           'graph': json_graph.adjacency_data(self.server.G)})

            rnd = 0
            while True:
                rnd += 1
                print(f'[+] Round {rnd}')
                perm, commitments, openings = commit_to_coloring(self.server.coloring)
                print(f'- Sending commitments')
                self.send_msg({'round': rnd, 'commitments': [c.hex() for c in commitments]})
                print(f'- Receiving query')
                #  Expect message of the form: {"query": {"u": 13, "v": 37}}
                msg = self.recv_msg()
                u = msg['query']['u']
                v = msg['query']['v']
                assert 0 <= u < n
                assert 0 <= v < n
                print(f'- Opening commitments')
                self.send_msg({'opening': {
                    'u': [perm[self.server.coloring[u]], openings[u].hex()],
                    'v': [perm[self.server.coloring[v]], openings[v].hex()],
                }})

        except:
            pass

        print(f'[+] closing connection with "{self.client_address}"')


class Server(ForkingTCPServer):
    allow_reuse_address = True
    allow_reuse_port = True

    def __init__(self, server_address):
        with open(GRAPH_FILE, 'r') as f:
            self.G = json_graph.adjacency_graph(json.load(f))
        with open(COLOR_FILE, 'r') as f:
            self.coloring = json.load(f)
        assert is_valid_coloring(self.G, self.coloring)
        ForkingTCPServer.__init__(self, server_address, Prover)



def main():
    server = Server((HOST, PORT))
    server.serve_forever()


if __name__ == '__main__':
    main()
