# A PAKE in the wild
**Category:** Crypto

**Points:** 300

We were given pake-in-the-wild.py file which is exectued on a remote server.

## The code
The purpose of the server is to compute a shared secret with the client and send over the encrypted flag once the client passes the authentication check.

## The vulnerabilities
### Key agreement
The computation of the shared secret involves scalar multiplcation over the NIST P-256 elliptic curve and is done as follow:
```
other = input("Your public key: ").split(",")
other_x = int(other[0], 16)
other_y = int(other[1], 16)

other_key = point.Point(other_x, other_y, curve.P256)

dh_secret = private_key * other_key
```

The server starts by sharing its public key and `other` is submitted by the client.
By submitting the base point `G` as client's public key, `dh_secret` will be equal to the server public key, which is known.

This allows to compute `dh_secret` on the client side without knowing `private_key`. 

As an alternative, we could have generated a key pair and perform the scalar multplication of the client's private key with the server public key.

### CMAC (a.k.a XOR + ECB)

Once the shared secret `ck` computed, the server does the following using another secret `auth_value`:

1. Server generates a random `nonce` and send to the client its `confirm` which is `AES-CMAC(ck,nonce+auth_value)`
2. Server asks for the client's `confirm` which is expected to be computed with the same `auth_value` but a different `nonce`
3. Server provides its `nonce`
4. Server asks for client's `nonce`
5. Server does the client authentication by compute the CMAC over the client `nonce` and the secret `auth_value`
6. If the check is valid, the server send the encrypted flag

As we know the secret key, the only unknow is `auth_value`. Thanks to the sequence of exchanges, we are able to get the server's `nonce` before providing the client's `nonce`.

The strategy here is to forge a `nonce` that will pass the check:

1. Get the server's `server_CMAC`
2. Send a random value as client's confirm `client_CMAC`
3. Retrieve server's `server_nonce`
4. Compute `forged_nonce` and send it to server

The server should answer with the encrypted flag which needs to be decrypted with `ck`.

How to compute `forged_nonce`?
`forged_nonce` should respect the following:
```
CMAC(ck,forged_nonce + auth_value) == client_CMAC
AES-ECB(ck,AES-ECB(ck,forged_nonce) XOR auth_value) == client_CMAC
AES-ECB(ck,forged_nonce) XOR auth_value == AES-ECB_d(ck,client_CMAC)
```
As such:
```
forged_nonce = AES-CBC_d(ck,AES-ECB_d(ck,client_CMAC) XOR auth_value)
```

Likewise, `auth_value` can be computed as follow:
```
auth = AES-ECB_d(ck,server_CMAC) XOR AES-ECB(ck,server_nonce)
```

Voilà
