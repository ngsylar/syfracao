import secrets

# int n, int a
def SingleTest (n, a):
    # factorization
    exp = n - 1
    while not (exp & 1):
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

# int n, int testCount
def SeveralTests (n, testCount=40):
    for _ in range(testCount):
        a = secrets.randbelow(n-3) + 2 # [2, n-1)
        if not SingleTest(n, a):
            return False
    return True

# int bitCount
def GenPrime (bitCount):
    while True:
        prime = (secrets.randbits(bitCount - 1) << 1) | 0b1
        if SeveralTests(prime):
            return prime