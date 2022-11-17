from meta import int_to_varint, public_key_to_address, address_to_public_key_hash, public_key_hash
from modular_inverse import modular_multiplicative_inverse
from ec_point_operation import curve, add, scalar_multiply
from sign import hash_to_int, sign_recoverable, verify_signature
from base64 import b64encode, b64decode


def message_bytes(message: str) -> bytes:
    """Serialize plain text message to format (LEN || message.utf-8)"""
    msg_bytes = message.encode('utf-8')
    return int_to_varint(len(msg_bytes)) + msg_bytes


def message_digest(message: str) -> bytes:
    """Returns the digest of plain text message"""
    return  message_bytes(message)


def sign_message(private_key: int, plain_text: str) -> tuple:
    """Sign arbitrary message with bitcoin private key, returns (p2pkh_address, serialized_compact_signature)"""
    d = message_digest(plain_text)
    # recovery signature
    recovery_id, r, s = sign_recoverable(private_key, d)
    # p2pkh address
    public_key = scalar_multiply(private_key, curve.g)
    p2pkh_address = public_key_to_address(public_key, compressed=True)
    # prefix = 27 + recovery_id + (4 if using compressed public key else 0)
    prefix = 27 + recovery_id + 4
    serialized_sig = prefix.to_bytes(1, byteorder='big') + r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
    return p2pkh_address, b64encode(serialized_sig).decode('ascii')


def verify_message(p2pkh_address: str, plain_text: str, signature: str) -> bool:
    """Verify serialized compact signature with p2pkh address and plain text"""
    sig_bytes = b64decode(signature)
    if len(sig_bytes) != 65:
        return False
    prefix, r, s = sig_bytes[0], int.from_bytes(sig_bytes[1:33], byteorder='big'), int.from_bytes(sig_bytes[33:], byteorder='big')
    # print("\n\nr in verify_msg: ", r, "\n\ns in verify_msg: ", s)
    # Calculate recovery_id
    compressed = False
    if prefix < 27 or prefix >= 35:
        return False
    if prefix >= 31:
        compressed = True
        prefix -= 4
    recovery_id = prefix - 27
    # Recover point kG, k is the ephemeral private key
    x = r + (curve.n if recovery_id >= 2 else 0)
    y_squared = (x * x * x + curve.a * x + curve.b) % curve.p
    y = pow(y_squared, (curve.p + 1) // 4, curve.p)
    if (y + recovery_id) % 2 != 0:
        y = -y % curve.p
    point_k = (x, y)
    # print("\n\npoint(x, y):", point_k)
    # Calculate point aG, a is the private key
    d = message_digest(plain_text)
    e = hash_to_int(d)
    mod_inv_r = modular_multiplicative_inverse(r, curve.n)
    public_key = add(scalar_multiply(mod_inv_r * s, point_k), scalar_multiply(mod_inv_r * (-e % curve.n), curve.g))
    # print("pk in sign message: ", public_key)
    # Verify signature
    if not verify_signature(public_key, d, (r, s)):
        return False
    # Check public key hash
    if public_key_hash(public_key, compressed) != address_to_public_key_hash(p2pkh_address):
        # print("\n\npublic_key_hash(public_key, compressed): ", public_key_hash(public_key, compressed), "\n\naddress_to_public_key_hash(p2pkh_address): ", address_to_public_key_hash(p2pkh_address))
        # print("false here pub key hash")
        return False
    # OK
    return True
