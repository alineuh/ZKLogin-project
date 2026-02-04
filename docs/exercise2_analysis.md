# Exercise 2: Breaking and Fixing Zero-Knowledge

## Question (a): Soundness Error Analysis

### Single Round (k=1)
Given a graph G = (V, E) with m = |E| edges:

- If P has a valid 3-coloring, it can answer any challenge correctly
- If P does NOT have a valid 3-coloring, there exists at least one edge e* where the two endpoints have the same color
- The verifier picks one random edge e ∈ E
- Probability that V picks the "bad" edge e*: **1/m**
- Probability that P cheats successfully: **(m-1)/m**

**Soundness error for k=1: ε₁ = (m-1)/m**

### Multiple Rounds (k rounds)
For a cheating prover to succeed in ALL k rounds:
- P must avoid being caught in every single round
- Probability: ((m-1)/m)^k

**Soundness error for k rounds: εₖ = ((m-1)/m)^k**

### Achieving ε ≤ 2^(-40)
We need: ((m-1)/m)^k ≤ 2^(-40)

Taking logarithms:
```
k * log((m-1)/m) ≤ -40 * log(2)
k ≥ -40 * log(2) / log((m-1)/m)
k ≥ 40 * log(2) / log(m/(m-1))
```

For large m: log(m/(m-1)) ≈ 1/m
Therefore: **k ≥ 40 * m * ln(2) ≈ 27.7 * m**

## Question (b): The Bug

**Location:** `server.py`, line 65 inside the `handle()` method

```python
while True:
    rnd += 1
    perm, commitments, openings = commit_to_coloring(self.server.coloring)  # ← BUG HERE
    self.send_msg({'round': rnd, 'commitments': [c.hex() for c in commitments]})
    msg = self.recv_msg()
    u = msg['query']['u']
    v = msg['query']['v']
    self.send_msg({'opening': {
        'u': [perm[self.server.coloring[u]], openings[u].hex()],
        'v': [perm[self.server.coloring[v]], openings[v].hex()],
    }})
```

**The Problem:**
- A **new permutation** is generated at EVERY round (inside the loop)
- According to the protocol specification, the permutation should be sampled once per round
- However, the prover is supposed to use the SAME permutation throughout a single round

**Why this breaks Zero-Knowledge:**
The permutation keeps changing between rounds, so if a malicious verifier asks about the same edge multiple times across different rounds, they can observe different permuted colors for the same vertex. This leaks information about the original coloring!

## Question (c): View Distribution Analysis

### Correct Protocol View
In the correct protocol, for a single round:
1. P samples π : {r,g,b} → {r,g,b} uniformly at random
2. P commits to π(c(v)) for all v ∈ V
3. V challenges with edge e = {u,v}
4. P opens commitments for u and v, revealing π(c(u)) and π(c(v))

**View of V:** (G, e, com₁,...,comₙ, π(c(u)), π(c(v)), rᵤ, rᵥ)

**Distribution:** The opened colors π(c(u)) and π(c(v)) are:
- Uniformly distributed over {r,g,b}²
- Subject to the constraint π(c(u)) ≠ π(c(v))
- Independent of the actual colors c(u) and c(v)

This is zero-knowledge because the view can be simulated without knowing c!

### Faulty Implementation View
In the buggy implementation, over multiple rounds querying the same edge e = {u,v}:

Round 1: π₁ is sampled → opens (π₁(c(u)), π₁(c(v)))
Round 2: π₂ is sampled → opens (π₂(c(u)), π₂(c(v)))
...
Round k: πₖ is sampled → opens (πₖ(c(u)), πₖ(c(v)))

**Key Difference:**
- Each round uses a DIFFERENT permutation
- But they're all applied to the SAME underlying colors c(u) and c(v)
- This creates a correlation pattern that reveals information

**Statistical Leak:**
If we query the same edge 6 times, we'll see all 6 possible ordered pairs:
- If c(u) = r, c(v) = g: we'll see (π(r), π(g)) for different π
- Over enough rounds, we can determine which pairs correspond to the same original (c(u), c(v))

**Distribution difference:**
- **Correct**: Each round is independent, no correlation between rounds
- **Buggy**: Rounds are correlated through the fixed underlying coloring

## Question (d): Attack Strategy

See `attacker.py` for implementation.

### Attack Algorithm:
```
1. Connect to the server
2. For each vertex u in the graph:
   a. Pick any edge e = {u, v} incident to u
   b. Query edge e multiple times (say 10 times)
   c. Collect all colors seen for vertex u across rounds
   d. Store the set of observed colors for u
3. For each vertex u:
   - If colors seen = {0, 1}: original color is 2
   - If colors seen = {0, 2}: original color is 1
   - If colors seen = {1, 2}: original color is 0
4. Return the reconstructed coloring
```

### Why it works:
- The permutation π maps {0,1,2} → {0,1,2} bijectively
- If c(u) = 0, then over different permutations we'll see π(0) ∈ {0,1,2}
- But we'll see ALL THREE values {0,1,2} eventually
- However, by querying edges, we only see the permuted value, not all possibilities
- By querying the same vertex many times with different permutations, we see which colors it NEVER appears as
- The color it never appears as must be its original color... WAIT, that's wrong!

**Corrected logic:**
- If c(u) = 0, and we apply random permutations, we'll see π(0) which could be {0, 1, or 2}
- Each permutation independently maps 0 → {0,1,2} with equal probability
- After enough queries, we should see all three colors for vertex u

**Actual attack:**
The attack works differently. We need to exploit the fact that the same underlying coloring is being permuted differently each time.

Let me reconsider...

Actually, the attack is based on observing **which permuted colors appear together**:
- Query edge {u,v} many times
- If we see pairs like (0,1), (1,2), (2,0) → these come from the same (c(u), c(v))
- By checking which pairs we NEVER see, we can deduce the original coloring

For instance:
- If we never see (0,0), (1,1), or (2,2) → c(u) ≠ c(v) ✓ (expected)
- If we see (0,1) but never (1,0) in {u,v} → there's a pattern
- Actually with random permutations, we should see all valid pairs eventually

**Better attack approach:**
Query many edges and look for consistency:
- Assign c(u) = 0 arbitrarily for some vertex u
- For each neighbor v of u:
  - Query edge {u,v} multiple times
  - Observe the pairs (colorᵤ, colorᵥ)
  - Deduce the relative coloring c(v) based on consistency
- Propagate this through the graph

See implementation in `attacker.py`.

## Question (e): Fix

**Solution:** Move the permutation sampling OUTSIDE the round loop, or keep it inside but ensure the protocol completes properly within each round.

Wait, re-reading the protocol: The permutation SHOULD be sampled fresh in each round! That's step 1(a) of the protocol.

Let me re-read more carefully...

Ah! The protocol says "Repeat k times", and step 1(a) says "P samples a random permutation π". This means:
- For each of the k rounds, sample a NEW permutation
- Within that round, use that same permutation for the commitments and openings

The bug is NOT that we sample a new permutation each time. The bug must be something else...

**Re-examining the code:**

OH! I see it now. Line 65 is in the while loop, and that's fine. But look at the structure:

The protocol should be:
1. Sample permutation π
2. Commit to all vertices using π
3. Receive challenge edge e
4. Open commitments for that edge using THE SAME π

But the code structure allows MULTIPLE challenges in the same round! The `while True` loop means the verifier can keep asking questions indefinitely with the same commitments but different permutations revealed... 

No wait, looking again: each iteration of the while loop does ONE round:
- Line 65: sample new permutation and create commitments
- Line 67: send commitments
- Line 70: receive ONE challenge
- Line 76-79: open commitments for that challenge

So each iteration is one complete round. That seems correct...

**WAIT! I found it!**

Look at line 65 vs lines 76-78 more carefully:

```python
perm, commitments, openings = commit_to_coloring(self.server.coloring)
```

Then later:
```python
'u': [perm[self.server.coloring[u]], openings[u].hex()],
```

The function `commit_to_coloring` returns a NEW permutation each time. But the commitments were created with THAT permutation. However, we're using `openings[u]` which is the randomness for position u, not for the committed value.

Let me check `commit_to_coloring` again... 

Actually, I think the real bug is more subtle. Let me trace through what happens:

In `commit_to_coloring`:
- We have coloring = [c₀, c₁, c₂, ..., cₙ]
- We sample perm = [π(0), π(1), π(2)] (a permutation of {0,1,2})
- For each vertex i with color cᵢ:
  - We commit to perm[cᵢ] and store commitment at position i
  - We store opening randomness at position i

Then in the opening phase:
- For vertex u with color c(u):
  - We reveal perm[self.server.coloring[u]] = perm[c(u)]
  - We reveal openings[u]

This seems correct! The commitment at position u contains perm[c(u)], and we're opening it correctly.

Hmm, let me think about this differently. What if the bug is that the permutation is reused somehow, or that information leaks through the commitments?

Actually, I think I've been overthinking this. Let me check if the permutation is being shared across rounds inadvertently... No, each call to `commit_to_coloring` creates a fresh permutation.

**Let me look for a DIFFERENT bug:**

Actually, checking line 65 inside the while True loop - this creates a situation where the prover will keep responding to challenges indefinitely. A malicious verifier can query the same edge multiple times and get different permuted answers each time!

**THAT'S THE BUG!**

The protocol specifies "Repeat k times" - meaning after k rounds, we're done. But the implementation has `while True`, meaning it never stops! This allows a malicious verifier to:
1. Query edge {u,v} in round 1 → get (π₁(c(u)), π₁(c(v)))
2. Query edge {u,v} in round 2 → get (π₂(c(u)), π₂(c(v)))
3. Continue for many rounds...
4. Eventually deduce c(u) and c(v) from the pattern of pairs seen

**The fix:** Replace `while True` with `for rnd in range(k)` where k is a parameter (e.g., k = 40 * m as calculated in part (a)).

