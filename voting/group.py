from lightecc import LightECC
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

# Elliptic Curve group
ec = LightECC(form_name='weierstrass', curve_name='secp256k1')
# - generator
G = ec.G
# - identity element
O = ec.O
# - group order
q = ec.n
# - size of a group element in bytes
encoded_group_element_len = 64
# - size of a scalar in bytes
encoded_scalar_len = encoded_group_element_len // 2

def scalar_to_bytes(x: int) -> bytes:
    """Serialize a 256-bit integer into 32 bytes"""
    assert 0 <= x < 2**256
    return x.to_bytes(encoded_scalar_len, 'little')

def scalar_from_bytes(b: bytes) -> int:
    """Deerialize a 256-bit integer from 32 bytes"""
    assert len(b) == encoded_scalar_len
    return int.from_bytes(b, 'little')

def group_element_to_bytes(P) -> bytes:
    """Serialize a group element into 64 bytes"""
    return scalar_to_bytes(P.x) + scalar_to_bytes(P.y)

def group_element_from_bytes(b: bytes):
    """Deserialize a group element from 64 bytes"""
    assert len(b) == encoded_group_element_len
    x = scalar_from_bytes(b[:encoded_scalar_len])
    y = scalar_from_bytes(b[encoded_scalar_len:])
    return EllipticCurvePoint(x, y, ec.curve)
