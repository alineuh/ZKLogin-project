"""
Electronic Voting System

Complete implementation of the e-voting protocol with:
- Schnorr signatures for authentication
- ElGamal encryption for vote privacy
- Σ-proofs for vote integrity
- Homomorphic aggregation
"""

from schnorr import keygen as schnorr_keygen, sign, verify as schnorr_verify, serialize_signature, deserialize_signature
from elgamal import keygen as elgamal_keygen, encrypt, decrypt, add_ciphertexts, serialize_ciphertext, deserialize_ciphertext
from sigma_proofs import prove_wellformed_vote, verify_wellformed_vote, prove_correct_decryption, verify_correct_decryption
from group import group_element_to_bytes
from hashlib import sha256


# ==============================================================================
# Vote Casting (Question 3c)
# ==============================================================================

def cast_vote(schnorr_sk: int, elgamal_pk, candidate: str) -> dict:
    """
    Cast a vote for a candidate.
    
    Args:
        schnorr_sk: Voter's Schnorr secret key
        elgamal_pk: Election manager's ElGamal public key
        candidate: One of {'Alice', 'Bob', 'Charlie'}
    
    Returns:
        Dictionary with encrypted vote, signature, and proof
    """
    # Step 1: Encode the vote
    if candidate == 'Alice':
        v = 1
    elif candidate == 'Bob':
        v = 10
    elif candidate == 'Charlie':
        v = 100
    else:
        raise ValueError(f"Invalid candidate: {candidate}. Must be Alice, Bob, or Charlie")
    
    # Step 2: Encrypt the vote
    (c1, c2), r = encrypt(elgamal_pk, v)
    
    # Step 3: Sign the ciphertext
    # Hash the ciphertext components to create message to sign
    message = group_element_to_bytes(c1) + group_element_to_bytes(c2)
    sigma = sign(schnorr_sk, message)
    
    # Step 4: Create proof of well-formed vote
    pi_vote = prove_wellformed_vote(elgamal_pk, c1, c2, v, r)
    
    # Step 5: Return the vote package
    return {
        'ciphertext': (c1, c2),
        'signature': sigma,
        'proof': pi_vote,
        'candidate': candidate  # For debugging/display only
    }


# ==============================================================================
# Vote Aggregation (Question 3d)
# ==============================================================================

def aggregate_votes(elgamal_pk, votes: list) -> dict:
    """
    Aggregate encrypted votes from multiple users.
    
    Args:
        elgamal_pk: Election manager's ElGamal public key
        votes: List of vote dictionaries, each containing:
            - schnorr_pk: Voter's Schnorr public key
            - vote_data: Output from cast_vote()
    
    Returns:
        Dictionary with aggregated ciphertext and verification results
    """
    valid_ciphertexts = []
    verification_results = []
    
    for i, vote_info in enumerate(votes):
        schnorr_pk = vote_info['schnorr_pk']
        vote_data = vote_info['vote_data']
        
        c1, c2 = vote_data['ciphertext']
        sigma = vote_data['signature']
        pi_vote = vote_data['proof']
        
        # Step 1: Verify the signature
        message = group_element_to_bytes(c1) + group_element_to_bytes(c2)
        sig_valid = schnorr_verify(schnorr_pk, message, sigma)
        
        # Step 2: Verify the proof of well-formed vote
        proof_valid = verify_wellformed_vote(elgamal_pk, c1, c2, pi_vote)
        
        is_valid = sig_valid and proof_valid
        verification_results.append({
            'voter_id': i,
            'signature_valid': sig_valid,
            'proof_valid': proof_valid,
            'overall_valid': is_valid
        })
        
        # Step 3: Include only valid votes in aggregation
        if is_valid:
            valid_ciphertexts.append((c1, c2))
    
    # Step 4: Aggregate the valid ciphertexts
    if not valid_ciphertexts:
        raise ValueError("No valid votes to aggregate!")
    
    # Start with the first ciphertext
    c1_agg, c2_agg = valid_ciphertexts[0]
    
    # Add all other ciphertexts
    for c1_i, c2_i in valid_ciphertexts[1:]:
        c1_agg, c2_agg = add_ciphertexts((c1_agg, c2_agg), (c1_i, c2_i))
    
    return {
        'aggregated_ciphertext': (c1_agg, c2_agg),
        'num_valid_votes': len(valid_ciphertexts),
        'num_total_votes': len(votes),
        'verification_results': verification_results
    }


# ==============================================================================
# Result Decryption and Verification (Question 3e)
# ==============================================================================

def decrypt_and_prove(elgamal_sk: int, elgamal_pk, aggregated_ciphertext: tuple) -> dict:
    """
    Decrypt the aggregated votes and create a proof of correct decryption.
    
    Args:
        elgamal_sk: Election manager's ElGamal secret key
        elgamal_pk: Election manager's ElGamal public key
        aggregated_ciphertext: (c1, c2) from aggregation
    
    Returns:
        Dictionary with election results and proof
    """
    c1, c2 = aggregated_ciphertext
    
    # Step 1: Decrypt the aggregated ciphertext
    # Maximum possible value: 9 voters each vote 100 = 900
    m = decrypt(elgamal_sk, aggregated_ciphertext, max_message=1000)
    
    # Step 2: Decode the result
    # m = a + 10*b + 100*c where a, b, c are votes for Alice, Bob, Charlie
    a = m % 10
    b = (m // 10) % 10
    c = m // 100
    
    # Step 3: Create proof of correct decryption
    pi_dec = prove_correct_decryption(elgamal_pk, c1, c2, m, elgamal_sk)
    
    return {
        'decrypted_value': m,
        'votes_alice': a,
        'votes_bob': b,
        'votes_charlie': c,
        'proof': pi_dec
    }


# ==============================================================================
# Result Verification (Question 3f)
# ==============================================================================

def verify_election_result(elgamal_pk, aggregated_ciphertext: tuple, result: dict) -> bool:
    """
    Verify the election result proof.
    
    Args:
        elgamal_pk: Election manager's ElGamal public key
        aggregated_ciphertext: (c1, c2) from aggregation
        result: Dictionary from decrypt_and_prove()
    
    Returns:
        True if the proof is valid, False otherwise
    """
    c1, c2 = aggregated_ciphertext
    m = result['decrypted_value']
    pi_dec = result['proof']
    
    return verify_correct_decryption(elgamal_pk, c1, c2, m, pi_dec)


# ==============================================================================
# Full Election Simulation (Question 3f)
# ==============================================================================

def run_election(num_voters: int = 5, votes: list = None):
    """
    Simulate a complete election.
    
    Args:
        num_voters: Number of voters (max 9)
        votes: Optional list of votes (e.g., ['Alice', 'Bob', 'Alice', ...])
               If None, random votes are generated
    
    Returns:
        Dictionary with complete election results
    """
    import random
    
    assert num_voters <= 9, "Maximum 9 voters allowed"
    
    print("=" * 70)
    print("ELECTRONIC VOTING SYSTEM SIMULATION")
    print("=" * 70)
    print()
    
    # ===== Key Generation =====
    print("[1] Key Generation")
    print("-" * 70)
    
    # Election manager generates ElGamal key pair
    elgamal_sk, elgamal_pk = elgamal_keygen()
    print(f"✓ Election manager generated ElGamal key pair")
    
    # Each voter generates Schnorr key pair
    voter_keys = []
    for i in range(num_voters):
        schnorr_sk, schnorr_pk = schnorr_keygen()
        voter_keys.append({
            'id': i,
            'schnorr_sk': schnorr_sk,
            'schnorr_pk': schnorr_pk
        })
    print(f"✓ {num_voters} voters generated Schnorr key pairs")
    print()
    
    # ===== Voting Phase =====
    print("[2] Voting Phase")
    print("-" * 70)
    
    # Generate votes if not provided
    if votes is None:
        candidates = ['Alice', 'Bob', 'Charlie']
        votes = [random.choice(candidates) for _ in range(num_voters)]
    
    assert len(votes) == num_voters, "Number of votes must match number of voters"
    
    # Each voter casts their vote
    cast_votes = []
    for i, (voter, candidate) in enumerate(zip(voter_keys, votes)):
        vote_data = cast_vote(voter['schnorr_sk'], elgamal_pk, candidate)
        cast_votes.append({
            'schnorr_pk': voter['schnorr_pk'],
            'vote_data': vote_data
        })
        print(f"✓ Voter {i} voted for {candidate}")
    print()
    
    # ===== Aggregation Phase =====
    print("[3] Aggregation Phase")
    print("-" * 70)
    
    aggregation_result = aggregate_votes(elgamal_pk, cast_votes)
    print(f"✓ Aggregated {aggregation_result['num_valid_votes']}/{aggregation_result['num_total_votes']} valid votes")
    
    # Show verification results
    for vr in aggregation_result['verification_results']:
        status = "✓ VALID" if vr['overall_valid'] else "✗ INVALID"
        print(f"  Voter {vr['voter_id']}: {status}")
    print()
    
    # ===== Decryption Phase =====
    print("[4] Decryption Phase")
    print("-" * 70)
    
    result = decrypt_and_prove(
        elgamal_sk,
        elgamal_pk,
        aggregation_result['aggregated_ciphertext']
    )
    
    print(f"✓ Election manager decrypted result:")
    print(f"  - Alice:   {result['votes_alice']} votes")
    print(f"  - Bob:     {result['votes_bob']} votes")
    print(f"  - Charlie: {result['votes_charlie']} votes")
    print(f"  - Total:   {result['votes_alice'] + result['votes_bob'] + result['votes_charlie']} votes")
    print()
    
    # ===== Verification Phase =====
    print("[5] Verification Phase")
    print("-" * 70)
    
    is_valid = verify_election_result(
        elgamal_pk,
        aggregation_result['aggregated_ciphertext'],
        result
    )
    
    if is_valid:
        print("✓ Election result proof verified successfully!")
        print("✓ The election result is VALID and CORRECT")
    else:
        print("✗ Election result proof verification FAILED!")
    print()
    
    # ===== Final Results =====
    print("=" * 70)
    print("FINAL ELECTION RESULTS")
    print("=" * 70)
    print(f"Alice:   {result['votes_alice']} votes")
    print(f"Bob:     {result['votes_bob']} votes")
    print(f"Charlie: {result['votes_charlie']} votes")
    print()
    
    # Determine winner
    max_votes = max(result['votes_alice'], result['votes_bob'], result['votes_charlie'])
    winners = []
    if result['votes_alice'] == max_votes:
        winners.append('Alice')
    if result['votes_bob'] == max_votes:
        winners.append('Bob')
    if result['votes_charlie'] == max_votes:
        winners.append('Charlie')
    
    if len(winners) == 1:
        print(f"🎉 WINNER: {winners[0]} with {max_votes} votes!")
    else:
        print(f"🤝 TIE between {' and '.join(winners)} with {max_votes} votes each!")
    
    print("=" * 70)
    print()
    
    return {
        'votes': votes,
        'result': result,
        'valid': is_valid
    }


# ==============================================================================
# Main
# ==============================================================================

if __name__ == '__main__':
    # Example 1: Small election with 3 voters
    print("\n\nExample 1: Small election with 3 voters")
    print()
    run_election(num_voters=3, votes=['Alice', 'Bob', 'Alice'])
    
    # Example 2: Larger election with 7 voters
    print("\n\nExample 2: Larger election with 7 voters")
    print()
    run_election(num_voters=7, votes=['Alice', 'Alice', 'Bob', 'Charlie', 'Alice', 'Bob', 'Charlie'])
    
    # Example 3: Maximum size election with 9 voters
    print("\n\nExample 3: Maximum size election with 9 voters (random votes)")
    print()
    run_election(num_voters=9)
    
    print("\n✓ All simulations completed successfully!")
