#!/usr/bin/env python3
from Crypto.Util.number import *
import random
import os
import hashlib


FLAG = os.getenv("FLAG", "PCTF{flag}").encode("utf8")
FLAG = bytes_to_long(FLAG[5:-1])
assert FLAG.bit_length() < 384
# print(f"FLAG={FLAG!r}")

# FLAG = random.getrandbits(383)
BITS = 1024
# print(f"FLAG random.getrandbits(383)={FLAG!r}")


def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])


# This doesn't really matter right???
def custom_hash(n):
    state = b"\x00" * 16
    for i in range(len(n) // 16):
        state = xor(state, n[i: i + 16])

    for _ in range(5):
        state = hashlib.md5(state).digest()
        state = hashlib.sha1(state).digest()
        state = hashlib.sha256(state).digest()
        state = hashlib.sha512(state).digest() + hashlib.sha256(state).digest()

    value = bytes_to_long(state)

    return value

# const_p = getPrime(BITS)
# print("const_p", const_p)
def fiat_shamir():
    from ctf.oven.challenge.solve import _nullify_endian_bytes
    p = getPrime(BITS)
    # p = const_p
    g = 2
    y = pow(g, FLAG, p)

    v = random.randint(2, 2**512)
    t = pow(g, v, p)

    c = custom_hash(long_to_bytes(g) + long_to_bytes(y) + long_to_bytes(t))
    c1 = custom_hash(long_to_bytes(g) + _nullify_endian_bytes(long_to_bytes(y), 15 + 16) + b"\x00" * 128)
    assert c == c1
    r = (v - c * FLAG) % (p - 1)
    # assert FLAG == (v - r) % (p - 1) / c

    assert c * FLAG == (v - r) % (p - 1)

    """ r + F*h = rand_v % (p-1) """
    assert t == (pow(g, r, p) * pow(y, c, p)) % p
    assert t == (pow(g, r, p) * pow(pow(g, FLAG, p), c, p)) % p
    # assert (2 ** v) % p == (2 ** r) % p * (
    #         ((2 ** FLAG) % p) ** c
    # ) % p  # too long to compute:)
    #
    # assert (g ** v) % p == (g ** r) % p * (y ** c) % p  # ?
    # return (t, r), (p, g, y)
    return (t, r), (p, g, y), c , FLAG, v


if __name__ == '__main__':
    while True:
        # resp = input("[1] Get a random signature\n[2] Exit\nChoice: ")
        # if "1" in resp:
        #     print()
        #     (t, r), (p, g, y) = fiat_shamir()
        #     print(f"t = {t}\nr = {r}")
        #     print()
        #     print(f"p = {p}\ng = {g}\ny = {y}")
        #     print()
        # elif "2" in resp:
        #     print("Bye!")
        #     exit()
        # elif "3" in resp:
        if True:
            for i in range(100):
                FLAG = random.getrandbits(383)
                # (t, r), (p, g, y) = fiat_shamir()
                # c, FLAG = fiat_shamir()
                (t, r), (p, g, y), c, FLAG, v = fiat_shamir()
                cf = c * FLAG
                # print(hex(x))
                # print(hex(r))
                # print(hex(t - p))
                # print(hex(t + p))
                # print(hex(t))
                print(hex(cf))
                print(hex(c))
                # print()

                # print(f"bin(r) = {bin(r)}")
                # print(long_to_bytes(r))
                # print(hex(r))
                # print(hex(r))

