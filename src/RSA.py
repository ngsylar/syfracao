import math
import millerrabin
import OAEP
from utilities import Conversion as convert, PseudoRandom as random

PUBLIC_EXP_DEFAULT = 65537
PRIME_BIT_COUNT_MIN = 1024

def GenerateKeys (msgByteCount: int=0) -> tuple[tuple[int, int], tuple[int, int]]:
    msgByteCountDef = ((2*PRIME_BIT_COUNT_MIN + 7) // 8) - (2*OAEP.HASH_BYTE_COUNT) - 2
    if (msgByteCount < msgByteCountDef):
        msgByteCount = msgByteCountDef

    keyBitCountMax = (msgByteCount + 2*OAEP.HASH_BYTE_COUNT + 2) * 8
    primeBitCount = (keyBitCountMax + 1) // 2
    publicExp = PUBLIC_EXP_DEFAULT

    # editar: usar threads
    primeP = millerrabin.GenPrime(primeBitCount)
    primeQ = millerrabin.GenPrime(primeBitCount)

    while primeP == primeQ:
        primeQ = millerrabin.GenPrime(primeBitCount)
    modulus = primeP * primeQ

    lambdaP = primeP - 1
    lambdaQ = primeQ - 1
    lambdaN = math.lcm(lambdaP, lambdaQ)

    while math.gcd(publicExp, lambdaN) != 1:
        publicExp = random.int_in_range(3, lambdaN)
    privateExp = pow(publicExp, -1, lambdaN)

    return (modulus, publicExp), (modulus, privateExp)

def Cipher (publicKey: tuple[int, int], message: str, label: str="") -> int:
    (modulus, publicExp) = publicKey

    paddedMsg = OAEP.Pad(modulus, message, label)
    msgBase = convert.bytearray_to_int(paddedMsg)
    cipher = pow(msgBase, publicExp, modulus)

    return cipher

def Decipher (privateKey: tuple[int, int], cipher: int, label: str="") -> str:
    (modulus, privateExp) = privateKey

    decipher = pow(cipher, privateExp, modulus)
    paddedMsg = convert.int_to_bytearray(decipher)
    message = OAEP.Unpad(modulus, paddedMsg, label)

    return message