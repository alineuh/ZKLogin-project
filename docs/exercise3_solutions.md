# Exercise 3: Electronic Voting

## Overview

Complete implementation of a privacy-preserving electronic voting system using:
- **Schnorr signatures** for voter authentication
- **ElGamal encryption** for vote privacy  
- **Σ-protocols** for vote integrity
- **Homomorphic addition** for vote aggregation

## Question (a): Schnorr Signatures ✅

See `voting/schnorr.py` for implementation.

### Implementation

```python
def keygen():
    sk = randbelow(q)  # Secret key ∈ Zq
    pk = sk * G        # Public key = g^sk
    return sk, pk

def sign(sk, message):
    r = randbelow(q)           # Random nonce
    R = r * G                   # Commitment R = g^r
    c = H(R || message) % q    # Challenge
    s = (r + c * sk) % q       # Response
    return (R, s)

def verify(pk, message, (R, s)):
    c = H(R || message) % q    # Recompute challenge
    return s * G == R + c * pk # Check: g^s = R · pk^c
```

### Key Points

1. **Security:** Based on discrete log hardness in the secp256k1 elliptic curve group
2. **Non-interactive:** Uses Fiat-Shamir transform with SHA-256
3. **Deterministic verification:** Anyone with pk can verify the signature
4. **Used for:** Authenticating that a vote came from a registered voter

### Test Results
```
✓ Generated key pair
✓ Signed message
✓ Signature verified successfully
✓ Signature correctly rejected for wrong message
✓ Signature correctly rejected for wrong public key
✓ Serialization/deserialization works correctly
✓ All tests passed!
```

---

## Question (b): ElGamal Encryption ✅

See `voting/elgamal.py` for implementation.

### Implementation

```python
def keygen():
    sk = randbelow(q)  # Secret key ∈ Zq
    pk = sk * G        # Public key = g^sk
    return sk, pk

def encrypt(pk, m):
    r = randbelow(q)       # Random r
    c1 = r * G             # c1 = g^r
    c2 = r * pk + m * G    # c2 = pk^r · g^m
    return ((c1, c2), r)

def decrypt(sk, (c1, c2)):
    M = c2 - sk * c1       # M = c2 · c1^(-sk) = g^m
    return solve_dlog(M)   # Solve m = log_g(M)
```

### Discrete Logarithm Solution

For small messages (m < 1,000,000), we use brute force:
```python
def solve_dlog(M, max_value=1000000):
    for m in range(max_value):
        if m * G == M:
            return m
    raise ValueError("Message too large")
```

**Note:** For larger messages, Baby-step Giant-step algorithm could be used (O(√n) instead of O(n)).

### Homomorphic Property

**Key property:** ElGamal is additively homomorphic in the exponent
```
Enc(m1) ⊕ Enc(m2) = Enc(m1 + m2)
```

Implementation:
```python
def add_ciphertexts((c1_1, c2_1), (c1_2, c2_2)):
    c1 = c1_1 + c1_2  # Component-wise addition
    c2 = c2_1 + c2_2
    return (c1, c2)
```

**Used for:** Aggregating encrypted votes without decryption!

### Test Results
```
✓ Generated key pair
✓ Encrypted message: 42
✓ Decrypted message: 42
✓ Tested multiple messages successfully
✓ Homomorphic addition works: 5 + 7 = 12
✓ Serialization/deserialization works correctly
✓ All tests passed!
```

---

## Question (c): Casting a Vote ✅

See `voting/voting_protocol.py` function `cast_vote()`.

### Protocol Steps

```python
def cast_vote(schnorr_sk, elgamal_pk, candidate):
    # 1. Encode vote
    v = 1    if candidate == 'Alice'
        10   if candidate == 'Bob'  
        100  if candidate == 'Charlie'
    
    # 2. Encrypt vote
    (c1, c2), r = encrypt(elgamal_pk, v)
    
    # 3. Sign ciphertext
    message = Hash(c1 || c2)
    σ = sign(schnorr_sk, message)
    
    # 4. Prove well-formed vote
    π_vote = prove_wellformed_vote(elgamal_pk, c1, c2, v, r)
    
    return {ciphertext, signature, proof}
```

### Proof of Well-Formed Vote

**Relation:**
```
R_Vote = {(pk, c1, c2; m, r) | c1 = g^r ∧ c2 = pk^r · g^m ∧ m ∈ {1, 10, 100}}
```

**Technique:** OR-proof using Fiat-Shamir transform

The relation is equivalent to:
```
(c1 = g^r ∧ c2 = pk^r · g^1) ∨ 
(c1 = g^r ∧ c2 = pk^r · g^10) ∨ 
(c1 = g^r ∧ c2 = pk^r · g^100)
```

**Proof structure:**
1. Real branch: Generate actual proof for correct message m
2. Fake branches: Simulate proofs for other two messages
3. Combine using challenge equation: c_total = c_0 + c_1 + c_2

**Implementation:** See `sigma_proofs.py` function `prove_wellformed_vote()`

### Why This Prevents Cheating

Without the proof, a malicious voter could:
- Encrypt a large number (e.g., 1,000,000) to "stuff" the ballot
- Encrypt an invalid value (e.g., 5) to confuse the system
- Encrypt garbage to cause decryption to fail

The proof ensures:
✓ The encrypted value is exactly one of {1, 10, 100}
✓ The voter knows what they're voting for (can't accidentally break the system)
✓ The aggregation will work correctly

---

## Question (d): Vote Aggregation ✅

See `voting/voting_protocol.py` function `aggregate_votes()`.

### Protocol Steps

```python
def aggregate_votes(elgamal_pk, votes):
    valid_votes = []
    
    for vote in votes:
        # 1. Verify Schnorr signature
        sig_valid = schnorr_verify(pk_i, Hash(c1||c2), σ_i)
        
        # 2. Verify proof of well-formed vote
        proof_valid = verify_wellformed_vote(elgamal_pk, c1, c2, π_i)
        
        # 3. Include only if both checks pass
        if sig_valid and proof_valid:
            valid_votes.append((c1, c2))
    
    # 4. Aggregate using homomorphic addition
    (c1_agg, c2_agg) = valid_votes[0]
    for (c1_i, c2_i) in valid_votes[1:]:
        c1_agg = c1_agg + c1_i
        c2_agg = c2_agg + c2_i
    
    return (c1_agg, c2_agg)
```

### Why Aggregation Works

**Mathematical proof:**

If vote i encrypts v_i, then:
```
(c1_i, c2_i) = (r_i · G, r_i · pk + v_i · G)
```

Aggregating all votes:
```
c1_agg = Σ c1_i = Σ(r_i · G) = (Σ r_i) · G = r_agg · G
c2_agg = Σ c2_i = Σ(r_i · pk + v_i · G) 
       = (Σ r_i) · pk + (Σ v_i) · G
       = r_agg · pk + m_agg · G
```

where r_agg = Σ r_i and m_agg = Σ v_i

Therefore: **(c1_agg, c2_agg) is a valid ElGamal encryption of m_agg = Σ v_i**

### Security Properties

1. **Privacy:** The aggregator never learns individual votes
2. **Integrity:** Invalid votes are rejected before aggregation
3. **Verifiability:** Anyone can verify the signature and proof for each vote
4. **Homomorphism:** Aggregation works without decryption

---

## Question (e): Result Decryption with Proof ✅

See `voting/voting_protocol.py` function `decrypt_and_prove()`.

### Protocol Steps

```python
def decrypt_and_prove(elgamal_sk, elgamal_pk, (c1, c2)):
    # 1. Decrypt aggregated ciphertext
    m = decrypt(elgamal_sk, (c1, c2), max_message=1000)
    
    # 2. Decode result
    a = m % 10          # Votes for Alice
    b = (m // 10) % 10  # Votes for Bob
    c = m // 100        # Votes for Charlie
    
    # 3. Prove correct decryption
    π_dec = prove_correct_decryption(elgamal_pk, c1, c2, m, elgamal_sk)
    
    return {m, a, b, c, π_dec}
```

### Proof of Correct Decryption

**Relation:**
```
R_Dec = {(pk, c1, c2, m; sk) | pk = g^sk ∧ c2 · c1^(-sk) = g^m}
```

**Σ-protocol:**
1. **Commitment:** 
   - w ← random
   - A = w · G
   - B = w · c1

2. **Challenge:** 
   - c = H(pk, c1, c2, m, A, B)

3. **Response:** 
   - z = w + c · sk

**Verification:**
- Check: g^z = A · pk^c
- Check: c1^z = B · (c2/g^m)^c

**Implementation:** See `sigma_proofs.py` function `prove_correct_decryption()`

### Why This Is Necessary

Without the proof, a corrupt election manager could:
- Lie about the decryption result
- Claim a different winner
- No way for observers to verify

With the proof:
✓ Anyone can verify the decryption is correct
✓ Election manager cannot cheat without being caught
✓ Zero-knowledge: proof doesn't reveal the secret key sk

---

## Question (f): Complete Simulation ✅

See `voting/voting_protocol.py` function `run_election()`.

### Full Election Flow

```
[1] Key Generation
    ✓ Election manager: (sk_em, pk_em) for ElGamal
    ✓ Each voter i: (sk_i, pk_i) for Schnorr

[2] Voting Phase  
    ✓ Each voter encrypts their vote
    ✓ Signs the ciphertext
    ✓ Generates proof of well-formed vote

[3] Aggregation Phase
    ✓ Verify all signatures and proofs
    ✓ Aggregate valid votes homomorphically

[4] Decryption Phase
    ✓ Election manager decrypts the result
    ✓ Generates proof of correct decryption

[5] Verification Phase
    ✓ Anyone verifies the decryption proof
    ✓ Accept or reject the result
```

### Example Output

```
======================================================================
ELECTRONIC VOTING SYSTEM SIMULATION
======================================================================

[1] Key Generation
----------------------------------------------------------------------
✓ Election manager generated ElGamal key pair
✓ 7 voters generated Schnorr key pairs

[2] Voting Phase
----------------------------------------------------------------------
✓ Voter 0 voted for Alice
✓ Voter 1 voted for Alice
✓ Voter 2 voted for Bob
✓ Voter 3 voted for Charlie
✓ Voter 4 voted for Alice
✓ Voter 5 voted for Bob
✓ Voter 6 voted for Charlie

[3] Aggregation Phase
----------------------------------------------------------------------
✓ Aggregated 7/7 valid votes
  Voter 0: ✓ VALID
  Voter 1: ✓ VALID
  Voter 2: ✓ VALID
  Voter 3: ✓ VALID
  Voter 4: ✓ VALID
  Voter 5: ✓ VALID
  Voter 6: ✓ VALID

[4] Decryption Phase
----------------------------------------------------------------------
✓ Election manager decrypted result:
  - Alice:   3 votes
  - Bob:     2 votes
  - Charlie: 2 votes
  - Total:   7 votes

[5] Verification Phase
----------------------------------------------------------------------
✓ Election result proof verified successfully!
✓ The election result is VALID and CORRECT

======================================================================
FINAL ELECTION RESULTS
======================================================================
Alice:   3 votes
Bob:     2 votes
Charlie: 2 votes

🎉 WINNER: Alice with 3 votes!
======================================================================
```

### Verification Function

```python
def verify_election_result(elgamal_pk, (c1, c2), result):
    m = result['decrypted_value']
    π_dec = result['proof']
    return verify_correct_decryption(elgamal_pk, c1, c2, m, π_dec)
```

---

## Security Analysis

### Privacy Properties

1. **Vote Privacy:** Individual votes are never revealed
   - Votes are encrypted with semantically secure ElGamal
   - Only the aggregate is decrypted
   - Even the election manager cannot see individual votes

2. **Receipt-Freeness:** Voter cannot prove how they voted to a coercer
   - The proof π_vote is zero-knowledge
   - Signatures authenticate but don't reveal vote content

### Integrity Properties

1. **Vote Authenticity:** Each vote is signed
   - Only registered voters with valid Schnorr keys can vote
   - Signatures prevent vote injection attacks

2. **Vote Validity:** Each vote is well-formed
   - Σ-proof ensures vote ∈ {1, 10, 100}
   - Prevents ballot stuffing and invalid votes

3. **Correct Tallying:** Result is verifiable
   - Proof of correct decryption
   - Anyone can verify the final result

### Limitations

1. **Voter Registration:** Assumes secure key distribution
2. **Coercion Resistance:** Limited (voter could be forced to use specific randomness)
3. **Scalability:** Discrete log solving limits to small elections (n ≤ 9)
4. **Availability:** Single election manager (could use threshold decryption)

---

## Implementation Details

### File Structure

```
voting/
├── group.py           # Elliptic curve group operations
├── schnorr.py         # Schnorr signatures (1.5 points)
├── elgamal.py         # ElGamal encryption (1.5 points)
├── sigma_proofs.py    # Σ-protocols for both relations (4 points)
└── voting_protocol.py # Complete voting system (4 points)
```

### Testing

All components have been tested:
- ✅ Schnorr: keygen, sign, verify, serialization
- ✅ ElGamal: keygen, encrypt, decrypt, homomorphic addition
- ✅ Σ-proofs: well-formed vote (all 3 branches), correct decryption
- ✅ Full protocol: 3, 7, and 9 voter elections

### Dependencies

```
lightecc  # Elliptic curve cryptography
hashlib   # SHA-256 for Fiat-Shamir
secrets   # Cryptographically secure randomness
```

---

## Summary

| Question | Points | Status | Implementation |
|----------|--------|--------|----------------|
| (a) Schnorr | 1.5 | ✅ | `schnorr.py` |
| (b) ElGamal | 1.5 | ✅ | `elgamal.py` |
| (c) Cast Vote | 2.0 | ✅ | `voting_protocol.py:cast_vote()` |
| (d) Aggregate | 2.0 | ✅ | `voting_protocol.py:aggregate_votes()` |
| (e) Decrypt | 2.0 | ✅ | `voting_protocol.py:decrypt_and_prove()` |
| (f) Simulate | 1.0 | ✅ | `voting_protocol.py:run_election()` |
| **Total** | **11** | **✅** | **All components working** |
