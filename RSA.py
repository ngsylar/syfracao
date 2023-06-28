import math
import millerrabin
from utilities import PseudoRandom as random

PUBLIC_EXP_DEFAULT = 65537

def GenerateKeys (keyBitCountMax: int=2048):
    primeBitCount = keyBitCountMax // 2
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
        publicExp = random.int_in_range(2, lambdaN)
    privateExp = pow(publicExp, -1, lambdaN)

    return ((modulus, publicExp), privateExp)

print(GenerateKeys())