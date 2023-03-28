# CTF Cryptography Challenge Write-up

## Challenge Description

You are given the following source code:

```python
from Crypto.Util.number import *
from secrets import randbelow
import random

flag = b'flag'

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

# private_key
na = randbelow(2**512)
nb = randbelow(2**512)

def f(z):
    return (a * z + b) % p

def compose_f(z , n):
    for _ in range(n):
        z = f(z)
    return z

# public_key
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
```

and this output:
```
18014838808495280399
p= 138738401466900565040450303083632367893847463466107669711409864101799177361263459826541936326742972782376396758761943269914060531542676904776176934310486048846522183424592323642466849133398927768118016854999956420610892278699506965169998416753662538788895370970371022249628860199762972564882686645000256909871
a= 126781583157521222250475247938271091811677133852874785913019057928029289396790949466805956243367134365574824890637028599494243131950282774012116795208300046183453446689977465283614472996206256379620854248760741286207457182535254617444440557810731635318034203148056316545222203374915579523706620027160017842994
b= 83892067453145670751139678904833512707337140865877220594175732242729017671725515228417945796691993178345584505771251905613011382580903486012959184236895449845477934867025007833702926023261733967649731599879839933065101975641631223760460213724029012558966717117465153899460682192938441255931891404635893744240
s= 24190596617077127032294754642210001394794739858666758890836813740773804838740669005876014182814839452722668251054241117626335271447168113660615992026517314232009330518394585106381637370121890852907600182906026646262055693098701030960758777125453954873391649255358003639583918273335710716898207423594091868681
A= 34039798789131085864905539054023915623858407960620689710531514294092059456753413906023893853272797702676443979733688237030137342866733011856518704054099242215019097768626703317027021935580818079153636932385319011184911254936914415347008548675501557744942347934351797466652577640422648359095242871127773307621
B= 129959663163953284392431077891835336602205121125017599439525714004344098257709866664927158009975783180370828339704467043786533070764713843809658149504798434817706067668345152345626733549576417247343808989656217806890132452519359938277406521102584634011267960951129350401112250056058751009448490064496943437465
enc= 104148092282482493878595325692474317947772276590642703530089812074365089502817576489037610569321529224781874437663048604968601389471595393006607510334604724582788301449046946587552701887396049213376917024752904470074749081661060102702709406831088343806011fd
```

Notice that the first line of the output seems to be a glitch and has not been used at all.

The given source code implements a key exchange protocol using a one-way function, which is the composition of the function `f(z) = (a * z + b) % p` `n` times with a random value `s`. The two parties, Alice and Bob, each choose their private keys `na` and `nb`, respectively, and compute their public keys `A` and `B` by composing `f` with `s` using their private keys.

The shared secret is computed by composing `f` with the other party's public key using one's own private key. That is, Alice computes `shared_secret = compose_f(B, na)` and Bob computes `shared_secret = compose_f(A, nb)`. The shared secret is then used to encrypt the flag using a multiplicative one-time pad scheme.

Our goal is to recover the flag by breaking the key exchange protocol. In order to do so, we need to extract the private keys `na` and `nb`.

In order to achieve our goal, let's express `compose_f` to understand the computation, let's note f<sup>n</sup>(z) the output of `compose_f(z,n)`. We have:

f(z) = z.a + b mod p

Using this expression we can derive a formula for 

f<sup>n</sup>(z) = z.a<sup>n</sup> + (b.a<sup>n-1</sup> + b.a<sup>n-2</sup> + ... + b.a<sup>2</sup> + b.a + b) mod p

f<sup>n</sup>(z) = z.a<sup>n</sup> + b.(a<sup>n-1</sup> + a<sup>n-2</sup> + ... + a<sup>2</sup> + a + 1) mod p

We can simplify this formula further by noticing that the second term can be expressed as a geometric series:

f<sup>n</sup>(z) = a<sup>n</sup> * z + b.(a<sup>n</sup> - 1)/(a-1) mod p

Therefore, as `A = compute_f(s,na)` we have:

A = f<sup>na</sup>(s) = s.a<sup>na</sup> + b.(a<sup>na</sup> - 1)/(a-1) mod p

A*(a-1) = (a-1).s.a<sup>na</sup> + b*(a<sup>na</sup> - 1) mod p

A*(a-1) = a.s.a<sup>na</sup> - s.a<sup>na</sup> + b*a<sup>na</sup> - b mod p

A*(a-1) + b = (a.s - s + b).a<sup>na</sup> mod p

Now we can express a<sup>na</sup> with only known values:

a<sup>na</sup> = (A*(a-1) + b) / (a.s - s + b) mod p

so does for a<sup>nb</sup>:

a<sup>nb</sup> = (B*(a-1) + b) / (a.s - s + b) mod p

However we still didn't succeed in computing `na` nor `nb`. Our goal is not to compute `na` or `nb`, basically we need the flag and if we can compute the `shared_secret` we will able to decrypt `enc `. Can we do this with knowledge of a<sup>na</sup> and a<sup>nb</sup> ? ... Yes!

We have to notice that:
```python
shared_secret = compose_f(A, nb)
assert compose_f(B, na) == shared_secret
```
but we also have:
```python
shared_secret = compose_f(s, na+nb)
````
Let's use f<sup>n</sup>(s) to compute shared_secret.

We have:

a<sup>na+nb</sup> = a<sup>na</sup>.a<sup>nb</sup>

shared_secret = f<sup>na+nb</sup>(s) = s.a<sup>na+nb</sup> + b.(a<sup>na+nb</sup> - 1)/(a-1) mod p


