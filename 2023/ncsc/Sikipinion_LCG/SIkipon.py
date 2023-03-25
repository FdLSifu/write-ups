from Crypto.Util.number import *
from secrets import randbelow
import random
# from Sikipon best unicar student :)

flag=open("flag.txt",'rb').read()

flag = b''


def generate_prime(bit_length):
    while True:
        p = random.getrandbits(bit_length)
        p |= (1 << bit_length - 1) | 1
        if isPrime(p):
            return int(p)



p = generate_prime(1024)
a = randbelow(p)
b = randbelow(p)
s = randbelow(p)

#private_key
na = randbelow(2**512)
nb = randbelow(2**512)
def f(z):
    return (a * z + b) % p

def compose_f(z , n):
    for _ in range(n):
        z = f(z)
    return z



#public_key
A = compose_f(s, na)
B = compose_f(s, nb)

shared_secret = compose_f(A, nb)
assert compose_f(B, na) == shared_secret



m = bytes_to_long(flag)
enc = (shared_secret * m) % p


print('p=' , p)
print('a=' , a)
print('b=' , b)
print('s=', s)
print('A=' , A)
print('B=' , B)
print('enc=' , enc)
