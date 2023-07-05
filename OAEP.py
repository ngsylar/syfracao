import hashlib
from byteblock import *
from utilities import Qualities as quality, Conversions as convert, PseudoRandom as random

BYTE_ZERO = bytearray(b'\x00')
BYTE_ONE = bytearray(b'\x01')

HASH_BYTE_COUNT = 32

def MGF1 (seed: bytearray, length: int, hash_func=hashlib.sha3_256) -> bytearray:
    hLen = hash_func().digest_size
    if length > (hLen << 32):
        raise ValueError("MGF1 Error: mask length must be at most 2^32(hLen)")

    T = b''
    counter = 0
    while len(T) < length:
        C = convert.int_to_bytes(counter, 4)
        T += hash_func(bytes(seed) + C).digest()
        counter += 1
    return bytearray(T[:length])

def GenerateHash (label: str) -> bytearray:
    return bytearray(hashlib.sha3_256(convert.str_to_bytes(label)).digest())

def Pad (publicKey: tuple[int, int], messsage: str, label: str="") -> bytearray:
    (modulus, _) = publicKey
    labelHash = GenerateHash(label)

    msgByteCount = len(messsage)
    modulusByteCount = quality.count_bytes_of_int(modulus)

    if msgByteCount > (modulusByteCount - 2*HASH_BYTE_COUNT - 2):
        raise ValueError("OAEP Error: message to be padded must be at most (k-2*hLen-2) bytes")
    
    paddingZeros = bytearray(modulusByteCount - msgByteCount - 2*HASH_BYTE_COUNT - 2)
    seed = random.bytearray_with_byte_count(HASH_BYTE_COUNT)
    dataBlock = labelHash + paddingZeros + BYTE_ONE + convert.str_to_bytearray(messsage)
    dbByteCount = len(dataBlock)

    maskedDB = XorBlocks(dataBlock, MGF1(seed, dbByteCount))
    maskedSeed = XorBlocks(seed, MGF1(maskedDB, HASH_BYTE_COUNT))
    paddedMsg = BYTE_ZERO + maskedSeed + maskedDB

    return paddedMsg

def Unpad (paddedMsg: bytearray, label: str="") -> str:
    if paddedMsg[0] != 0x00:
        raise ValueError("OAEP Error: first byte is non-zero")

    byte_i = HASH_BYTE_COUNT + 1
    maskedSeed = paddedMsg[1:byte_i]
    maskedDB = paddedMsg[byte_i:]
    dbByteCount = len(maskedDB)

    labelHash = GenerateHash(label)
    computedSeed = XorBlocks(maskedSeed, MGF1(maskedDB, HASH_BYTE_COUNT))
    computedDB = XorBlocks(maskedDB, MGF1(computedSeed, dbByteCount))

    byte_i = HASH_BYTE_COUNT
    computedHash = computedDB[:byte_i]
    if (computedHash != labelHash):
        raise ValueError("OAEP Error: calculated hash does not match")

    while computedDB[byte_i] != 0x01:
        if computedDB[byte_i] != 0x00:
            raise ValueError("OAEP Error: padding string is corrupted")
        byte_i += 1
    byte_i += 1

    unpaddedMsg = computedDB[byte_i:]
    message = convert.bytearray_to_str(unpaddedMsg)
    return message