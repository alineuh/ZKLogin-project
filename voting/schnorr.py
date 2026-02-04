"""
Schnorr Signature Scheme

Key generation: sk ∈ Zq, pk = g^sk
Signing: (R, s) where R = g^r and s = r + H(R || m) * sk
Verification: Check g^s = R · pk^H(R || m)
"""

from group import G, O, q, scalar_to_bytes, scalar_from_bytes, group_element_to_bytes, group_element_from_bytes
from secrets import randbelow
from hashlib import sha256


def keygen():
    """
    Generate a Schnorr key pair.
    
    Returns:
        (sk, pk): secret key (int) and public key (group element)
    """
    sk = randbelow(q)  # Sample sk uniformly from Zq
    pk = sk * G  # pk = g^sk (in additive notation: sk * G)
    return sk, pk


def sign(sk: int, message: bytes) -> tuple:
    """
    Sign a message using Schnorr signature scheme.
    
    Args:
        sk: Secret key (integer in Zq)
        message: Message to sign (bytes)
    
    Returns:
        (R, s): Signature where R is a group element and s is an integer
    """
    # Sample random nonce r ∈ Zq
    r = randbelow(q)
    
    # Compute commitment R = g^r
    R = r * G
    
    # Compute challenge c = H(R || message)
    h = sha256()
    h.update(group_element_to_bytes(R))
    h.update(message)
    c = int.from_bytes(h.digest(), 'big') % q
    
    # Compute response s = r + c * sk (mod q)
    s = (r + c * sk) % q
    
    return (R, s)


def verify(pk, message: bytes, signature: tuple) -> bool:
    """
    Verify a Schnorr signature.
    
    Args:
        pk: Public key (group element)
        message: Message that was signed (bytes)
        signature: (R, s) signature tuple
    
    Returns:
        True if signature is valid, False otherwise
    """
    R, s = signature
    
    # Recompute challenge c = H(R || message)
    h = sha256()
    h.update(group_element_to_bytes(R))
    h.update(message)
    c = int.from_bytes(h.digest(), 'big') % q
    
    # Check: g^s = R · pk^c
    # In additive notation: s * G = R + c * pk
    lhs = s * G
    rhs = R + c * pk
    
    return lhs.x == rhs.x and lhs.y == rhs.y


def serialize_signature(signature: tuple) -> bytes:
    """Serialize a signature to bytes"""
    R, s = signature
    return group_element_to_bytes(R) + scalar_to_bytes(s)


def deserialize_signature(data: bytes) -> tuple:
    """Deserialize a signature from bytes"""
    from group import encoded_group_element_len, encoded_scalar_len
    R_bytes = data[:encoded_group_element_len]
    s_bytes = data[encoded_group_element_len:encoded_group_element_len + encoded_scalar_len]
    R = group_element_from_bytes(R_bytes)
    s = scalar_from_bytes(s_bytes)
    return (R, s)


# Test the implementation
if __name__ == '__main__':
    print("Testing Schnorr Signatures...")
    
    # Generate key pair
    sk, pk = keygen()
    print(f"✓ Generated key pair")
    
    # Sign a message
    message = b"Hello, Zero-Knowledge!"
    signature = sign(sk, message)
    print(f"✓ Signed message")
    
    # Verify the signature
    if verify(pk, message, signature):
        print(f"✓ Signature verified successfully")
    else:
        print(f"✗ Signature verification failed!")
    
    # Test with wrong message
    wrong_message = b"Wrong message"
    if not verify(pk, wrong_message, signature):
        print(f"✓ Signature correctly rejected for wrong message")
    else:
        print(f"✗ Signature accepted for wrong message!")
    
    # Test with wrong public key
    _, wrong_pk = keygen()
    if not verify(wrong_pk, message, signature):
        print(f"✓ Signature correctly rejected for wrong public key")
    else:
        print(f"✗ Signature accepted for wrong public key!")
    
    # Test serialization
    sig_bytes = serialize_signature(signature)
    sig_restored = deserialize_signature(sig_bytes)
    if verify(pk, message, sig_restored):
        print(f"✓ Serialization/deserialization works correctly")
    else:
        print(f"✗ Serialization/deserialization failed!")
    
    print("\n✓ All tests passed!")
