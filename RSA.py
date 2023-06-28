import math
import millerrabin

__eDefault = 65537

e = __eDefault

p = millerrabin.GenPrime(1024)
q = millerrabin.GenPrime(1024)

print("\n")
print(p != q)

n = p * q
print(math.gcd(e, (p-1)*(q-1)))