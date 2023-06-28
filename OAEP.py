import hashlib
from utilities import Qualities as quality, Conversions as convert, PseudoRandom as random

def MGF1 (seed: bytearray, length: int, hash_func=hashlib.sha3_256) -> bytearray:
    hLen = hash_func().digest_size
    if length > (hLen << 32):
        raise ValueError("mask length must be at most 2^32(hLen)")

    T = b''
    counter = 0
    while len(T) < length:
        C = convert.int_to_bytes(counter, 4)
        T += hash_func(bytes(seed) + C).digest()
        counter += 1
    return bytearray(T[:length])

def PadMessage (publicKey: tuple[int, int], messsage: bytearray, label: str="") -> bytearray:
    (rsaModulus, _) = publicKey
    labelHash = bytearray(hashlib.sha3_256(convert.str_to_bytes(label)).digest())

    msgByteCount = len(messsage)
    hashByteCount = len(labelHash)
    modulusByteCount = quality.count_bytes_of_int(rsaModulus)

    if msgByteCount > (modulusByteCount - 2*hashByteCount - 2):
        raise ValueError("message to be padded must be at most (k-2*hLen-2) bytes")
    
    paddingZeros = bytearray(modulusByteCount - msgByteCount - 2*hashByteCount - 2)
    seed = random.bytearray_with_byte_count(hashByteCount)
    dataBlock = labelHash + paddingZeros + bytearray(b'\x01') + messsage
    dbByteCount = len(maskedDB)

    maskedDB = XorBlock(dataBlock, MGF1(seed, dbByteCount))
    maskedSeed = XorBlock(seed, MGF1(maskedDB, hashByteCount))

    paddedMsg = bytearray(b'\x00') + maskedSeed + maskedDB
    return paddedMsg

def UnpadMessage ():
    return 0

def XorBlock (dominantBlock: bytearray, recessiveBlock: bytearray) -> bytearray:
    xoredBlock = bytearray(len(dominantBlock))
    for i in range(len(xoredBlock)):
        xoredBlock[i] = dominantBlock[i] ^ recessiveBlock[i]
    return xoredBlock