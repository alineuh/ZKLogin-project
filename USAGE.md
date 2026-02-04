# How to Run the Project

This guide explains how to run each component of the ZKP final project.

## Prerequisites

```bash
# Install dependencies
pip install networkx lightecc matplotlib --user

# Or with break-system-packages flag
pip install networkx lightecc matplotlib --break-system-packages
```

## Exercise 2: Graph 3-Coloring Zero-Knowledge Proof

### 1. Testing the Buggy Server

```bash
cd graph_coloring

# Terminal 1: Start the buggy server
python server.py

# Terminal 2: Run the honest verifier (limited rounds)
python verifier.py

# Terminal 2: Run the attacker (extracts the coloring)
python attacker.py
```

**Expected behavior:**
- Honest verifier: Accepts the proof (graph is 3-colorable)
- Attacker: Extracts a valid 3-coloring by exploiting the `while True` bug

### 2. Testing the Fixed Server

```bash
cd graph_coloring

# Terminal 1: Start the fixed server
python server_fixed.py

# Terminal 2: Run the honest verifier
python verifier.py
```

**Expected behavior:**
- Protocol runs for exactly k rounds (calculated from graph size)
- Verifier accepts if all rounds pass
- Attacker cannot extract coloring (limited rounds)

### 3. Generating Test Graphs

```bash
cd graph_coloring

# Generate a small test graph (easier to debug)
python gen_3col.py test-small
# Creates: test-small-graph.json and test-small-coloring.json

# Modify server.py to use the new graph
# Change lines 11-12:
# GRAPH_FILE = 'test-small-graph.json'
# COLOR_FILE = 'test-small-coloring.json'
```

## Exercise 3: Electronic Voting System

### 1. Testing Individual Components

```bash
cd voting

# Test Schnorr signatures
python schnorr.py

# Test ElGamal encryption
python elgamal.py

# Test Σ-protocols
python sigma_proofs.py
```

**Expected output:** All tests should pass with ✓ marks

### 2. Running the Full Voting Simulation

```bash
cd voting

# Run complete election simulation
python voting_protocol.py
```

**Expected output:**
```
======================================================================
ELECTRONIC VOTING SYSTEM SIMULATION
======================================================================

[1] Key Generation
----------------------------------------------------------------------
✓ Election manager generated ElGamal key pair
✓ N voters generated Schnorr key pairs

[2] Voting Phase
----------------------------------------------------------------------
✓ Voter 0 voted for [Candidate]
...

[3] Aggregation Phase
----------------------------------------------------------------------
✓ Aggregated N/N valid votes
...

[4] Decryption Phase
----------------------------------------------------------------------
✓ Election manager decrypted result:
  - Alice:   X votes
  - Bob:     Y votes
  - Charlie: Z votes

[5] Verification Phase
----------------------------------------------------------------------
✓ Election result proof verified successfully!
✓ The election result is VALID and CORRECT

======================================================================
FINAL ELECTION RESULTS
======================================================================
[Winner announced]
```

### 3. Custom Election

You can modify `voting_protocol.py` to run custom elections:

```python
# Edit the main section at the bottom of voting_protocol.py

# Custom vote list
run_election(num_voters=5, votes=['Alice', 'Bob', 'Alice', 'Charlie', 'Bob'])

# Random votes
run_election(num_voters=7)  # Random votes for 7 voters
```

## Project Structure

```
zkp-project/
├── graph_coloring/          # Exercise 2
│   ├── server.py           # Buggy server (original)
│   ├── server_fixed.py     # Fixed server (your solution)
│   ├── verifier.py         # Honest verifier
│   ├── attacker.py         # Malicious verifier (your attack)
│   ├── utils.py            # Commitment utilities
│   ├── gen_3col.py         # Graph generator
│   ├── 3col-graph.json     # Large test graph (999 nodes)
│   └── 3col-coloring.json  # Corresponding coloring
│
├── voting/                  # Exercise 3
│   ├── group.py            # Elliptic curve operations
│   ├── schnorr.py          # Schnorr signatures (3a)
│   ├── elgamal.py          # ElGamal encryption (3b)
│   ├── sigma_proofs.py     # Σ-protocols (3c, 3e)
│   └── voting_protocol.py  # Complete protocol (3c-3f)
│
└── docs/                    # Documentation
    ├── exercise2_solutions.md  # Answers to Ex. 2
    ├── exercise3_solutions.md  # Answers to Ex. 3
    └── exercise2_analysis.md   # Detailed bug analysis
```

## Common Issues

### Issue: `ModuleNotFoundError: No module named 'networkx'`
**Solution:** Install dependencies: `pip install networkx --user`

### Issue: `ModuleNotFoundError: No module named 'lightecc'`
**Solution:** Install dependencies: `pip install lightecc --user`

### Issue: Server not accepting connections
**Solution:** 
- Check if port 1337 is already in use
- Kill any existing server processes: `killall python`
- Change the port in both server and client files

### Issue: "Connection refused" when running attacker
**Solution:** Make sure server.py is running in another terminal first

### Issue: Discrete log solving is slow
**Solution:** This is expected for large messages. The implementation uses brute force which is O(n). For the voting system, messages are small (≤ 999) so it's fast enough.

## Performance Notes

### Exercise 2
- Small graph (30 nodes): ~1 second for attack
- Medium graph (100 nodes): ~10 seconds for attack  
- Large graph (999 nodes): ~5 minutes for attack

The attack requires querying each edge multiple times, so it scales with |E|.

### Exercise 3
- 3 voters: Instant
- 9 voters: ~1 second (maximum due to discrete log constraint)

The bottleneck is discrete log solving during decryption.

## Testing Checklist

### Exercise 2
- [x] Honest verifier accepts valid proof
- [x] Bug identified in server.py
- [x] Attacker extracts valid coloring
- [x] Fixed server limits rounds
- [x] Documentation complete

### Exercise 3
- [x] Schnorr signatures work
- [x] ElGamal encryption/decryption work
- [x] Homomorphic addition works
- [x] Well-formed vote proof works
- [x] Correct decryption proof works
- [x] Full election runs successfully
- [x] Result verification works

## Submission

To prepare your submission:

```bash
# Make sure all tests pass
cd graph_coloring && python attacker.py
cd ../voting && python voting_protocol.py

# Create the tarball
cd /home/claude
tar -czf zkp-project-submission.tar.gz zkp-project/

# Or zip file
zip -r zkp-project-submission.zip zkp-project/
```

Include in your submission:
- All source code (`.py` files)
- Documentation (`.md` files)
- README.md with instructions
- This USAGE.md file
- Any test outputs or screenshots

## Contact

For questions about running the code, please refer to:
- Exercise 2 documentation: `docs/exercise2_solutions.md`
- Exercise 3 documentation: `docs/exercise3_solutions.md`
- Course materials and lecture notes
