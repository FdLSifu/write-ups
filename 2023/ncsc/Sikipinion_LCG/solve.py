from sage.all import *
from binascii import unhexlify

# Load values from file
with open("out.txt", "r") as f:
    f.readline()
    p = int(f.readline().split(' ')[1].strip())
    a = int(f.readline().split(' ')[1].strip())
    b = int(f.readline().split(' ')[1].strip())
    s = int(f.readline().split(' ')[1].strip())
    A = int(f.readline().split(' ')[1].strip())
    B = int(f.readline().split(' ')[1].strip())
    enc = int(f.readline().split(' ')[1].strip())

# Original f function
def f(z):
    return (a * z + b) % p

# Original compose_f
def compose_f(z , n):
    for _ in range(n):
        z = f(z)
    return z

# Optimized and contracted form f compose_f
# f^n(z) = z.a^n + b*(a^n - 1)/(a-1) mod p
def compose_ffast(z,n):
    r = inverse_mod(a-1,p)
    r *= power_mod(a,n,p) - 1
    r = (r*b)%p
    r += power_mod(a,n,p)*z 
    return r%p

# Check validity of the contracted form
assert compose_ffast(43124,24) == compose_f(43124,24)

# from the contracted form we can express a^na 
# A = f^na(s)   B = f^nb(s)
# a^na = (A(a-1) + b) / (as -s + b) mod p
# a^nb = (B(a-1) + b) / (as -s + b) mod p
ana = inverse_mod((a*s)-s+b,p)*(A*(a-1) +b) % p
anb = inverse_mod((a*s)-s+b,p)*(B*(a-1) +b) % p

# a^na * a^nb = a^(na+nb) 
anaplusnb = ana*anb % p

# now we can compute shared_secret
# ss=f^(na+nb)(s) = s*a^(na+nb) + b*(a^(na+nb) - 1)/(a-1) mod p
ss = (s*anaplusnb + (inverse_mod(a-1,p)*b*(anaplusnb-1))) %p

# we can now compute m by computing the inverse of ss
m = (enc*inverse_mod(ss,p)) %p
print(unhexlify(hex(m)[2:]).decode())

