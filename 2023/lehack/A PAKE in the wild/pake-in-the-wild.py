#!/usr/bin/python
import os
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes

from secret import MESSAGE

from fastecdsa import curve, ecdsa, keys, point

import hashlib
import time

# Generate keypair
private_key = keys.gen_private_key(curve.P256)
public_key = keys.get_public_key(private_key, curve.P256)

# Generate authentication value
auth_value = os.urandom(16)

if __name__ == "__main__":

    try:
        print("Welcome to my authenticated key exchange")
        print("Authenticate to me to recover my super secret")

        # Diffie-Hellman exchange on P256
        print(f"My public key: {public_key.x:0>64x},{public_key.y:0>64x}")

        other = input("Your public key: ").split(",")

        assert len(other[0]) == 64
        assert len(other[1]) == 64

        other_x = int(other[0], 16)
        other_y = int(other[1], 16)

        other_key = point.Point(other_x, other_y, curve.P256)

        dh_secret = private_key * other_key

        # Key derivation
        encoded = bytes.fromhex(f"{dh_secret.x:0>64x}{dh_secret.y:0>64x}")
        ck = hashlib.sha256(encoded).digest()[:16]

        # Autentication protocol: first exchange confirmation values (i.e., commitment), then nonces
        my_nonce = os.urandom(16) # Nonce is 16-bytes long
        mac = CMAC.new(ck, ciphermod=AES)
        mac.update(my_nonce + auth_value)
        my_confirm = mac.digest()

        print(f"My confirm: {my_confirm.hex()}")
        msg = input(f"Your confirm: ")

        assert len(msg) == 32 # Verify confirmation value is 16-bytes long

        other_confirm = bytes.fromhex(msg)
        assert other_confirm != my_confirm # Prevent reflection attacks

        print(f"My nonce: {my_nonce.hex()}")
        msg = input(f"Your nonce: ")

        assert len(msg) == 32 # Verify nonce value is 16-bytes long

        other_nonce = bytes.fromhex(msg)
        assert other_nonce != my_nonce

        mac = CMAC.new(ck, ciphermod=AES)
        mac.update(other_nonce + auth_value)
        computed_confirm = mac.digest()

        assert computed_confirm == other_confirm

        iv = os.urandom(8)
        cipher = AES.new(ck, AES.MODE_CTR, nonce=iv)
        ciphertext = cipher.encrypt(MESSAGE.encode("utf-8"))

        print(f"Encrypted message: {iv.hex()}{ciphertext.hex()}")
    except:
        print("Invalid message received")

