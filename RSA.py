import math
import millerrabin
import OAEP
from utilities import Conversions as convert, PseudoRandom as random

PUBLIC_EXP_DEFAULT = 65537
PRIME_BIT_COUNT_MIN = 1024

def GenerateKeys (msgByteCount: int=0):
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
        primeQ = millerrabin.GenPrime(1024)
    modulus = primeP * primeQ

    lambdaP = primeP - 1
    lambdaQ = primeQ - 1
    lambdaN = math.lcm(lambdaP, lambdaQ)

    while math.gcd(publicExp, lambdaN) != 1:
        publicExp = random.int_in_range(3, lambdaN)
    privateExp = pow(publicExp, -1, lambdaN)

    return (modulus, publicExp), privateExp

def Cipher (publicKey: tuple[int, int], message: str, label: str="") -> int:
    (modulus, publicExp) = publicKey

    paddedMsg = OAEP.Pad(publicKey, message, label)
    msgBase = convert.bytearray_to_int(paddedMsg)
    cipher = pow(msgBase, publicExp, modulus)

    return cipher

def Decipher (privateKey: int, publicKey: tuple[int, int], cipher: int, label: str="") -> str:
    (modulus, _) = publicKey
    privateExp = privateKey

    decipher = pow(cipher, privateExp, modulus)
    paddedMsg = bytearray(1) + convert.int_to_bytearray(decipher)
    message = OAEP.Unpad(paddedMsg, label)

    return message