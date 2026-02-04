"""
ElGamal Encryption with message in the exponent

Key generation: sk ∈ Zq, pk = g^sk
Encryption: (c1, c2) = (g^r, pk^r · g^m) for random r
Decryption: M = c2 · c1^(-sk), then solve m = log_g(M)

Note: This only works for small messages since we need to solve discrete log.
"""

from group import G, O, q, scalar_to_bytes, scalar_from_bytes, group_element_to_bytes, group_element_from_bytes
from secrets import randbelow


def keygen():
    """
    Generate an ElGamal key pair.
    
    Returns:
        (sk, pk): secret key (int) and public key (group element)
    """
    sk = randbelow(q)  # Sample sk uniformly from Zq
    pk = sk * G  # pk = g^sk (in additive notation: sk * G)
    return sk, pk


def encrypt(pk, message: int, max_message: int = 1000000):
    """
    Encrypt a small integer message using ElGamal encryption.
    
    Args:
        pk: Public key (group element)
        message: Message to encrypt (small integer, m < max_message)
        max_message: Maximum expected message value (for decryption)
    
    Returns:
        ((c1, c2), r): Ciphertext tuple and randomness r
    """
    assert 0 <= message < max_message, f"Message {message} must be in range [0, {max_message})"
    
    # Sample random r ∈ Zq
    r = randbelow(q)
    
    # Compute c1 = g^r
    c1 = r * G
    
    # Compute c2 = pk^r · g^m
    # In additive notation: c2 = r * pk + message * G
    c2 = r * pk + message * G
    
    return ((c1, c2), r)


def decrypt(sk: int, ciphertext: tuple, max_message: int = 1000000) -> int:
    """
    Decrypt an ElGamal ciphertext.
    
    Args:
        sk: Secret key (integer)
        ciphertext: (c1, c2) ciphertext tuple
        max_message: Maximum expected message value
    
    Returns:
        Decrypted message (integer)
    """
    c1, c2 = ciphertext
    
    # Compute M = c2 · c1^(-sk)
    # In additive notation: M = c2 - sk * c1
    M = c2 + (-sk * c1)
    
    # Solve discrete log: find m such that M = m * G
    # Use brute force for small messages
    return solve_dlog(M, max_message)


def solve_dlog(M, max_value: int = 1000000) -> int:
    """
    Solve discrete logarithm m = log_g(M) for small m.
    
    Uses brute force search (baby-step giant-step could be used for larger values).
    
    Args:
        M: Group element
        max_value: Maximum value to search up to
    
    Returns:
        m such that M = m * G
    
    Raises:
        ValueError: If discrete log not found within max_value
    """
    # Try m = 0, 1, 2, ..., max_value
    for m in range(max_value):
        if (m * G).x == M.x and (m * G).y == M.y:
            return m
    
    raise ValueError(f"Could not solve discrete log (message > {max_value})")


def add_ciphertexts(ct1: tuple, ct2: tuple) -> tuple:
    """
    Homomorphically add two ElGamal ciphertexts.
    
    If ct1 encrypts m1 and ct2 encrypts m2, then the result encrypts m1 + m2.
    
    Args:
        ct1: (c1_1, c2_1) ciphertext
        ct2: (c1_2, c2_2) ciphertext
    
    Returns:
        (c1, c2) ciphertext encrypting m1 + m2
    """
    c1_1, c2_1 = ct1
    c1_2, c2_2 = ct2
    
    # Component-wise multiplication in multiplicative notation
    # = component-wise addition in additive notation
    c1 = c1_1 + c1_2
    c2 = c2_1 + c2_2
    
    return (c1, c2)


def serialize_ciphertext(ciphertext: tuple) -> bytes:
    """Serialize a ciphertext to bytes"""
    c1, c2 = ciphertext
    return group_element_to_bytes(c1) + group_element_to_bytes(c2)


def deserialize_ciphertext(data: bytes) -> tuple:
    """Deserialize a ciphertext from bytes"""
    from group import encoded_group_element_len
    c1_bytes = data[:encoded_group_element_len]
    c2_bytes = data[encoded_group_element_len:2*encoded_group_element_len]
    c1 = group_element_from_bytes(c1_bytes)
    c2 = group_element_from_bytes(c2_bytes)
    return (c1, c2)


# Test the implementation
if __name__ == '__main__':
    print("Testing ElGamal Encryption...")
    
    # Generate key pair
    sk, pk = keygen()
    print(f"✓ Generated key pair")
    
    # Test encryption and decryption
    message = 42
    (ciphertext, r) = encrypt(pk, message)
    print(f"✓ Encrypted message: {message}")
    
    decrypted = decrypt(sk, ciphertext)
    assert decrypted == message, f"Decryption failed: got {decrypted}, expected {message}"
    print(f"✓ Decrypted message: {decrypted}")
    
    # Test with different messages
    test_messages = [0, 1, 10, 100, 999]
    for msg in test_messages:
        (ct, _) = encrypt(pk, msg)
        dec = decrypt(sk, ct, max_message=1000)
        assert dec == msg, f"Failed for message {msg}"
    print(f"✓ Tested multiple messages successfully")
    
    # Test homomorphic addition
    m1, m2 = 5, 7
    (ct1, _) = encrypt(pk, m1)
    (ct2, _) = encrypt(pk, m2)
    ct_sum = add_ciphertexts(ct1, ct2)
    dec_sum = decrypt(sk, ct_sum, max_message=100)
    assert dec_sum == m1 + m2, f"Homomorphic addition failed: got {dec_sum}, expected {m1 + m2}"
    print(f"✓ Homomorphic addition works: {m1} + {m2} = {dec_sum}")
    
    # Test serialization
    ct_bytes = serialize_ciphertext(ciphertext)
    ct_restored = deserialize_ciphertext(ct_bytes)
    dec_restored = decrypt(sk, ct_restored)
    assert dec_restored == message, "Serialization/deserialization failed"
    print(f"✓ Serialization/deserialization works correctly")
    
    print("\n✓ All tests passed!")
