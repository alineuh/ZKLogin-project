# Zero-Knowledge Proofs Final Project

**Course:** Zero-Knowledge Proofs  
**Date:** January 2026  
**Authors:** Aline SPANO

## 📋 Project Structure

```
zkp-project/
├── graph_coloring/          # Exercise 2: Breaking and Fixing Zero-Knowledge
│   ├── server.py           # Buggy prover implementation
│   ├── server_fixed.py     # Fixed implementation
│   ├── attacker.py         # Malicious verifier
│   ├── utils.py            # Utility functions (commit, verify)
│   ├── gen_3col.py         # Graph generator
│   ├── 3col-graph.json     # Sample graph
│   └── 3col-coloring.json  # Sample coloring
├── voting/                  # Exercise 3: Electronic Voting
│   ├── group.py            # Elliptic curve utilities
│   ├── schnorr.py          # Schnorr signatures
│   ├── elgamal.py          # ElGamal encryption
│   ├── voting_protocol.py  # Complete voting protocol
│   └── sigma_proofs.py     # Σ-protocols implementation
├── docs/                    # Documentation
│   └── report.md           # Project report
└── requirements.txt         # Python dependencies
```

## 🎯 Objectives

### Exercise 2: Graph 3-Coloring ZK Proof (11 points)
- [x] Analyze soundness error (2a)
- [x] Find the bug in the implementation (2b)
- [x] Describe the view difference (2c)
- [x] Implement malicious verifier (2d)
- [x] Fix the implementation (2e)
- [x] Add Merkle tree optimization (2f)

### Exercise 3: Electronic Voting (11 points)
- [x] Implement Schnorr signatures (3a)
- [x] Implement ElGamal encryption (3b)
- [x] Implement vote casting with proof (3c)
- [x] Implement vote aggregation (3d)
- [x] Implement result decryption with proof (3e)
- [x] Implement full simulation (3f)
      

## 🐛 Bug Found in Exercise 2

**Location:** `graph_coloring/server.py` line 65

**Issue:** The permutation is regenerated at each round, breaking zero-knowledge property.

**Impact:** A malicious verifier can extract the actual coloring by querying the same edge multiple times across different rounds.

## 🚀 Installation

```bash
# Install dependencies
pip install -r requirements.txt

# For graph coloring
cd graph_coloring
python server.py  # Run the buggy server

# For voting
cd voting
python voting_protocol.py  # Run the voting simulation
```

## 📚 References

- Course materials on Zero-Knowledge Proofs
- NetworkX documentation: https://networkx.org/
- LightECC library: https://github.com/serengil/LightECC
