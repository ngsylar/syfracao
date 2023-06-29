import hashlib
from utilities import Qualities as quality, Conversions as convert, PseudoRandom as random

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

def PadMessage (publicKey: tuple[int, int], messsage: bytearray, label: bytearray=bytearray()) -> bytearray:
    (modulus, _) = publicKey
    labelHash = bytearray(hashlib.sha3_256(bytes(label)).digest())

    msgByteCount = len(messsage)
    modulusByteCount = quality.count_bytes_of_int(modulus)

    if msgByteCount > (modulusByteCount - 2*HASH_BYTE_COUNT - 2):
        raise ValueError("OAEP Error: message to be padded must be at most (k-2*hLen-2) bytes")
    
    paddingZeros = bytearray(modulusByteCount - msgByteCount - 2*HASH_BYTE_COUNT - 2)
    seed = random.bytearray_with_byte_count(HASH_BYTE_COUNT)
    dataBlock = labelHash + paddingZeros + bytearray(b'\x01') + messsage
    dbByteCount = len(dataBlock)

    maskedDB = XorBlock(dataBlock, MGF1(seed, dbByteCount))
    maskedSeed = XorBlock(seed, MGF1(maskedDB, HASH_BYTE_COUNT))

    paddedMsg = bytearray(b'\x00') + maskedSeed + maskedDB
    return paddedMsg

def UnpadMessage (paddedMsg: bytearray, label: bytearray=bytearray()) -> bytearray:
    if (paddedMsg[0] != 0x00):
        print("OAEP Error: first byte is non-zero")
        return bytearray(0)
    
    byte_i = HASH_BYTE_COUNT + 1
    maskedSeed = paddedMsg[1:byte_i]
    maskedDB = paddedMsg[byte_i:]
    dbByteCount = len(maskedDB)

    labelHash = bytearray(hashlib.sha3_256(bytes(label)).digest())
    computedSeed = XorBlock(maskedSeed, MGF1(maskedDB, HASH_BYTE_COUNT))
    computedDB = XorBlock(maskedDB, MGF1(computedSeed, dbByteCount))

    byte_i = HASH_BYTE_COUNT
    computedHash = computedDB[:byte_i]

    if (computedHash != labelHash):
        print("OAEP Error: calculated hash does not match")
        return bytearray(0)

    while computedDB[byte_i] != 0x01:
        if computedDB[byte_i] != 0x00:
            print("OAEP Error: padding string is corrupted")
            return bytearray(0)
        byte_i += 1
    byte_i += 1

    unpaddedMsg = computedDB[byte_i:]
    return unpaddedMsg

def XorBlock (dominantBlock: bytearray, recessiveBlock: bytearray) -> bytearray:
    xoredBlock = bytearray(len(dominantBlock))
    for i in range(len(xoredBlock)):
        xoredBlock[i] = dominantBlock[i] ^ recessiveBlock[i]
    return xoredBlock

# # teste
# import millerrabin
# E_DEF = 65537

# labelT = "Gabriel F., 27at2301"
# messageT = "A Hello, World! program is generally a computer program that ignores any input, and outputs or displays a message similar to Hello, World!"

# p = millerrabin.GenPrime(1024)
# q = millerrabin.GenPrime(1024)
# n = p * q

# senderT = PadMessage((n, E_DEF), convert.str_to_bytearray(messageT), convert.str_to_bytearray(labelT))
# # senderT[6] ^= 0b00001000
# receiverT = UnpadMessage(senderT, convert.str_to_bytearray(labelT))

# print(convert.bytearray_to_str(receiverT))
# print(bytearray())