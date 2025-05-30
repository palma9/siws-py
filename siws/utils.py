import secrets
import struct
from ctypes import Array, c_char, create_string_buffer

from siws.defs import ALPHANUMERICS


def generate_nonce() -> str:
    return "".join(secrets.choice(ALPHANUMERICS) for _ in range(11))


def varuint_encode(number: int, offset: int = 0) -> Array[c_char]:
    """Encode an integer into a bytearray

    Args:
        number (int): Variable integer to decode
        offset (int): Offset to start decoding from
    Returns:
        Array[c_char]: encoded Buffer
    """
    MAX_SAFE_INTEGER = 9007199254740991

    def encoding_len(number: int) -> int:
        val = 9
        if number < 0xFD:
            val = 1
        elif number <= 0xFFFF:
            val = 3
        elif number <= 0xFFFFFFFF:
            val = 5

        return val

    if number < 0 or number > MAX_SAFE_INTEGER or number % 1 != 0:
        raise ValueError("value out of range")

    buff = create_string_buffer(encoding_len(number))

    if number < 0xFD:
        struct.pack_into("<B", buff, offset, number)
    elif number <= 0xFFFF:
        struct.pack_into("<B", buff, offset, 0xFD)
        struct.pack_into("<H", buff, offset + 1, number)
    elif number <= 0xFFFFFFFF:
        struct.pack_into("<B", buff, offset, 0xFE)
        struct.pack_into("<Q", buff, offset + 1, number)
    else:
        struct.pack_into("<B", buff, offset, 0xFE)
        struct.pack_into("<Q", buff, offset + 1, (number % 0x100000000) >> 0)
        struct.pack_into("<Q", buff, offset + 5, (number / 0x100000000) or 0)

    return buff


def encode_defunc(message: str) -> bytearray:
    """Encode the signed message

    Args:
        message (str): Message to be encoded

    Returns:
        bytearray: encoded message
    """
    encoded_message = message.encode() if type(message) == str else message

    chain_prefix = bytearray(b"\x17Stacks Signed Message:\n")
    msg_bytearray = bytearray(encoded_message)
    encoded = varuint_encode(len(msg_bytearray))

    return chain_prefix + encoded + msg_bytearray


def build_signature(signature: str) -> bytearray:
    """Check if signature is RSV or VRS and return it

    Args:
        signature (str): the signature of the signed message

    Returns:
        str: The RS signature
    """
    if signature[:2] in ["00", "01"]:  # RSV
        sig = signature[2:]
    elif signature[-2:] in ["00", "01"]:  # VRS
        sig = signature[:-2]
    else:
        raise ValueError("Signature format not supported")

    return bytearray.fromhex(sig)
