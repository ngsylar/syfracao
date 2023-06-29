import math
import millerrabin
import OAEP
from utilities import Qualities as quality, Conversions as convert, PseudoRandom as random

PUBLIC_EXP_DEFAULT = 65537
__msgByteCountDef = 254 - (2 * OAEP.HASH_BYTE_COUNT)

def GenerateKeys (msgByteCount: int=__msgByteCountDef):
    if (msgByteCount < __msgByteCountDef):
        msgByteCount = __msgByteCountDef

    keyBitCountMax = (msgByteCount + 2*OAEP.HASH_BYTE_COUNT + 2) * 8
    primeBitCount = (keyBitCountMax + 1) // 2
    publicExp = PUBLIC_EXP_DEFAULT

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

    return ((modulus, publicExp), privateExp)

# teste
labelT = "Gabriel F., 27at2301"
messageT = "A Hello, World! program is generally a computer program that ignores any input, and outputs or displays a message similar to Hello, World!"

((nT, eT), dT) = GenerateKeys(len(messageT))
msgTInt = convert.str_to_int(messageT)

print(quality.count_bytes_of_int(nT))
print(quality.count_bytes_of_int(msgTInt))

paddedMsgT = OAEP.PadMessage((nT, eT), convert.str_to_bytearray(messageT), convert.str_to_bytearray(labelT))

cipherT = pow(convert.bytearray_to_int(paddedMsgT), eT, nT)
decipherT = convert.int_to_bytearray(pow(cipherT, dT, nT))

print(OAEP.UnpadMessage(bytearray(1) + decipherT, convert.str_to_bytearray(labelT)))