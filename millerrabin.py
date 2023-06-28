from utilities import PseudoRandom as random

oddNumber_i = 0 # editar: remover esse contador e fazer threads para gerar p e q primos

def TheoremTest (a: int, n: int) -> bool:
    # factorization
    exp = n - 1
    while not (exp & 0b1):
        exp >>= 1

    # test for the last term
    if pow(a, exp, n) == 1:
        return True

    # test for previous terms
    while exp < n-1:
        if pow(a, exp, n) == n-1:
            return True
        exp <<= 1

    return False

def IsPrime (n: int, testCount: int=40) -> bool:
    for i in range(testCount):
        print("\rIndex " + str(oddNumber_i) + " Test " + str(i+1), end="")
        a = random.int_in_range(2, n-1)
        print("\r", end="")
        if not TheoremTest(a, n):
            return False
    return True

def GenPrime (bitCount: int, testCount: int=40) -> bool:
    global oddNumber_i
    oddNumber_i = 0

    while True:
        oddNumber = (random.int_with_full_bit_count(bitCount-1) << 1) | 0b1
        oddNumber_i += 1
        if IsPrime(oddNumber, testCount):
            return oddNumber