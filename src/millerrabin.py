from utilities import PseudoRandom as random

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

def IsPrime (n: int, testCount: int=40, index: int=0) -> bool:
    for i in range(testCount):
        print("\rIndex " + str(index) + " Test " + str(i+1), end="")
        a = random.int_in_range(2, n-1)
        print("\r", end="")
        if not TheoremTest(a, n):
            return False
    print()
    return True

def GenPrime (bitCount: int, testCount: int=40, index: int=0) -> bool:
    while True:
        index += 1
        oddNumber = (random.int_with_full_bit_count(bitCount-1) << 1) | 0b1
        if IsPrime(oddNumber, testCount, index):
            return oddNumber