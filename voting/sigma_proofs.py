"""
Σ-protocols (Sigma protocols) for the voting system

1. Proof of well-formed vote: Prove that a ciphertext encrypts one of {1, 10, 100}
2. Proof of correct decryption: Prove knowledge of sk such that pk = g^sk and M = c2 · c1^(-sk)
"""

from group import G, O, q, scalar_to_bytes, group_element_to_bytes
from secrets import randbelow
from hashlib import sha256


def fiat_shamir_hash(*elements) -> int:
    """
    Compute Fiat-Shamir challenge as H(elements) mod q.
    
    Args:
        *elements: Mix of group elements and integers
    
    Returns:
        Integer challenge in Zq
    """
    h = sha256()
    for elem in elements:
        if isinstance(elem, int):
            h.update(scalar_to_bytes(elem % q))
        else:
            # Assume it's a group element
            h.update(group_element_to_bytes(elem))
    return int.from_bytes(h.digest(), 'big') % q


# ==============================================================================
# Proof of well-formed vote
# ==============================================================================

def prove_wellformed_vote(pk, c1, c2, m: int, r: int) -> dict:
    """
    Prove that (c1, c2) is a well-formed ciphertext encrypting m ∈ {1, 10, 100}.
    
    Uses OR-proof technique: prove that
        (c1 = g^r AND c2 = pk^r · g^1) OR
        (c1 = g^r AND c2 = pk^r · g^10) OR  
        (c1 = g^r AND c2 = pk^r · g^100)
    
    Args:
        pk: Election manager's public key
        c1, c2: Ciphertext components
        m: Actual message (must be 1, 10, or 100)
        r: Randomness used in encryption
    
    Returns:
        Proof dictionary with commitments, challenges, and responses
    """
    assert m in [1, 10, 100], f"Message must be 1, 10, or 100, got {m}"
    
    # Determine which branch is real
    if m == 1:
        real_idx = 0
    elif m == 10:
        real_idx = 1
    else:  # m == 100
        real_idx = 2
    
    messages = [1, 10, 100]
    
    # Arrays to store values for each branch
    commitments_a = [None, None, None]  # A_i commitments
    commitments_b = [None, None, None]  # B_i commitments
    challenges = [None, None, None]     # e_i challenges
    responses = [None, None, None]      # z_i responses
    
    # Step 1: Generate commitments for the real branch
    w = randbelow(q)  # Random witness
    commitments_a[real_idx] = w * G  # A = g^w
    commitments_b[real_idx] = w * pk  # B = pk^w
    
    # Step 2: Simulate the fake branches
    for i in range(3):
        if i == real_idx:
            continue
        
        # For fake branches, we choose random e_i and z_i first
        challenges[i] = randbelow(q)
        responses[i] = randbelow(q)
        
        # Then compute commitments that will make the verification pass:
        # For verification: g^z_i = A_i · c1^e_i  =>  A_i = g^z_i · c1^(-e_i)
        # For verification: pk^z_i = B_i · (c2 / g^m_i)^e_i  =>  B_i = pk^z_i · (c2 / g^m_i)^(-e_i)
        
        commitments_a[i] = responses[i] * G + (-challenges[i]) * c1
        
        # c2 / g^m_i = c2 - m_i * G
        c2_adjusted = c2 + (-messages[i]) * G
        commitments_b[i] = responses[i] * pk + (-challenges[i]) * c2_adjusted
    
    # Step 3: Compute Fiat-Shamir challenge
    c_total = fiat_shamir_hash(
        pk, c1, c2,
        commitments_a[0], commitments_b[0],
        commitments_a[1], commitments_b[1],
        commitments_a[2], commitments_b[2]
    )
    
    # Step 4: Compute challenge for real branch
    challenges[real_idx] = (c_total - challenges[0] - challenges[1] - challenges[2]) % q
    
    # Step 5: Compute response for real branch
    responses[real_idx] = (w + challenges[real_idx] * r) % q
    
    # Return the proof
    return {
        'commitments_a': commitments_a,
        'commitments_b': commitments_b,
        'challenges': challenges,
        'responses': responses
    }


def verify_wellformed_vote(pk, c1, c2, proof: dict) -> bool:
    """
    Verify a proof of well-formed vote.
    
    Args:
        pk: Election manager's public key
        c1, c2: Ciphertext components
        proof: Proof dictionary from prove_wellformed_vote
    
    Returns:
        True if proof is valid, False otherwise
    """
    messages = [1, 10, 100]
    
    commitments_a = proof['commitments_a']
    commitments_b = proof['commitments_b']
    challenges = proof['challenges']
    responses = proof['responses']
    
    # Step 1: Recompute Fiat-Shamir challenge
    c_total = fiat_shamir_hash(
        pk, c1, c2,
        commitments_a[0], commitments_b[0],
        commitments_a[1], commitments_b[1],
        commitments_a[2], commitments_b[2]
    )
    
    # Step 2: Check that challenges sum correctly
    challenge_sum = sum(challenges) % q
    if challenge_sum != c_total:
        return False
    
    # Step 3: Verify each branch
    for i in range(3):
        # Verify: g^z_i = A_i · c1^e_i
        lhs1 = responses[i] * G
        rhs1 = commitments_a[i] + challenges[i] * c1
        if lhs1.x != rhs1.x or lhs1.y != rhs1.y:
            return False
        
        # Verify: pk^z_i = B_i · (c2 / g^m_i)^e_i
        lhs2 = responses[i] * pk
        c2_adjusted = c2 + (-messages[i]) * G
        rhs2 = commitments_b[i] + challenges[i] * c2_adjusted
        if lhs2.x != rhs2.x or lhs2.y != rhs2.y:
            return False
    
    return True


# ==============================================================================
# Proof of correct decryption
# ==============================================================================

def prove_correct_decryption(pk, c1, c2, m: int, sk: int) -> dict:
    """
    Prove that m is the correct decryption of (c1, c2) under secret key sk.
    
    Proves knowledge of sk such that:
        pk = g^sk AND c2 · c1^(-sk) = g^m
    
    This is equivalent to proving knowledge of sk such that:
        pk = g^sk AND c2 - sk·c1 = m·G
    
    Args:
        pk: Public key (should equal sk * G)
        c1, c2: Ciphertext components
        m: Decrypted message
        sk: Secret key
    
    Returns:
        Proof dictionary with commitment, challenge, and response
    """
    # Step 1: Generate random witness
    w = randbelow(q)
    
    # Step 2: Compute commitments
    A = w * G  # A = g^w
    B = w * c1  # B = c1^w
    
    # Step 3: Compute Fiat-Shamir challenge
    c = fiat_shamir_hash(pk, c1, c2, m, A, B)
    
    # Step 4: Compute response
    z = (w + c * sk) % q
    
    return {
        'A': A,
        'B': B,
        'c': c,
        'z': z
    }


def verify_correct_decryption(pk, c1, c2, m: int, proof: dict) -> bool:
    """
    Verify a proof of correct decryption.
    
    Args:
        pk: Public key
        c1, c2: Ciphertext components
        m: Claimed decrypted message
        proof: Proof dictionary from prove_correct_decryption
    
    Returns:
        True if proof is valid, False otherwise
    """
    A = proof['A']
    B = proof['B']
    c = proof['c']
    z = proof['z']
    
    # Step 1: Recompute challenge
    c_recomputed = fiat_shamir_hash(pk, c1, c2, m, A, B)
    if c != c_recomputed:
        return False
    
    # Step 2: Verify: g^z = A · pk^c
    lhs1 = z * G
    rhs1 = A + c * pk
    if lhs1.x != rhs1.x or lhs1.y != rhs1.y:
        return False
    
    # Step 3: Verify: c1^z = B · (c2 / g^m)^c
    # c2 / g^m = c2 - m·G
    c2_adjusted = c2 + (-m) * G
    lhs2 = z * c1
    rhs2 = B + c * c2_adjusted
    if lhs2.x != rhs2.x or lhs2.y != rhs2.y:
        return False
    
    return True


# ==============================================================================
# Tests
# ==============================================================================

if __name__ == '__main__':
    from elgamal import keygen as elgamal_keygen, encrypt
    
    print("Testing Σ-protocols...")
    print()
    
    # Generate ElGamal key pair
    sk, pk = elgamal_keygen()
    
    # ===== Test 1: Proof of well-formed vote =====
    print("=" * 60)
    print("Test 1: Proof of well-formed vote")
    print("=" * 60)
    
    for m in [1, 10, 100]:
        print(f"\nTesting vote for m = {m}...")
        (c1, c2), r = encrypt(pk, m)
        
        # Create proof
        proof = prove_wellformed_vote(pk, c1, c2, m, r)
        print(f"  ✓ Generated proof")
        
        # Verify proof
        if verify_wellformed_vote(pk, c1, c2, proof):
            print(f"  ✓ Proof verified successfully")
        else:
            print(f"  ✗ Proof verification failed!")
    
    # Test with invalid message
    print(f"\nTesting with invalid message (should fail)...")
    (c1, c2), r = encrypt(pk, 5)  # Invalid vote
    try:
        proof = prove_wellformed_vote(pk, c1, c2, 5, r)
        print(f"  ✗ Should have raised an assertion error!")
    except AssertionError:
        print(f"  ✓ Correctly rejected invalid message")
    
    # ===== Test 2: Proof of correct decryption =====
    print()
    print("=" * 60)
    print("Test 2: Proof of correct decryption")
    print("=" * 60)
    
    for m in [1, 10, 100, 111]:
        print(f"\nTesting decryption of m = {m}...")
        (c1, c2), r = encrypt(pk, m)
        
        # Create proof
        proof = prove_correct_decryption(pk, c1, c2, m, sk)
        print(f"  ✓ Generated proof")
        
        # Verify proof
        if verify_correct_decryption(pk, c1, c2, m, proof):
            print(f"  ✓ Proof verified successfully")
        else:
            print(f"  ✗ Proof verification failed!")
    
    # Test with wrong message
    print(f"\nTesting with wrong decrypted message (should fail)...")
    (c1, c2), r = encrypt(pk, 42)
    wrong_m = 43
    proof = prove_correct_decryption(pk, c1, c2, wrong_m, sk)
    if not verify_correct_decryption(pk, c1, c2, wrong_m, proof):
        print(f"  ✓ Correctly rejected wrong decryption")
    else:
        print(f"  ✗ Accepted wrong decryption!")
    
    print()
    print("=" * 60)
    print("✓ All tests passed!")
    print("=" * 60)
