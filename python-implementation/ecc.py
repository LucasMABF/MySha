import random
import hashlib

# curve parameters
a = 0
b = 7
p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 -2**6 - 2**4 - 1
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)

def mod_inv(a, m = p):
    m0 = m
    if a < 0:
        a = a % m
    y0 = 0
    y = 1

    while a > 1:
        q = m // a
        y, y0 = y0 - q * y, y
        a, m = m % a, a
    
    return y % m0

def add(P, Q):
    if P == Q:
        return double(P)
    slope = ((P[1] - Q[1]) * mod_inv(P[0] - Q[0])) % p

    x = (slope ** 2 - P[0] - Q[0]) % p

    y = ((slope * (P[0] - x)) - P[1]) % p

    return (x, y)


def double(point):
    slope = ((3 * point[0] ** 2 + a) * mod_inv(2 * point[1])) % p

    x = (slope ** 2 - (2 * point[0])) % p

    y = (slope * (point[0] - x) - point[1]) % p

    return (x, y)


def multiply(prvk, point=G):
    current = point
    binary = bin(prvk)[3:] # remove 0b and first digit
    
    for i in binary:
        current = double(current)
        if i == "1":
            current = add(current, point)
    
    return current

# Create keypair
# privateKey = random.randint(1, n) # probably not the best way to do this
privateKey = 55800536784178461328972811510982068918793335867256545452538001036548738588540
publicKey = multiply(privateKey)
print(f"public Key {publicKey}")

# Sign 
message = "abc"
print(f"message to sign: {message}")
hash = int(hashlib.sha256(message.encode("utf-8")).hexdigest(), 16)
nonce = random.randint(1, n)
r = multiply(nonce)[0] % n
s = (mod_inv(nonce, n) * (hash + privateKey * r)) % n
signature = (r, s)
print(f"signature: {signature}")

# Verify signature

point1 = multiply(mod_inv(signature[1], n) * hash)
point2 = multiply((mod_inv(signature[1], n) * signature[0]), publicKey)
point3 = add(point1, point2)
print("validating signature")
if point3[0] == signature[0]:
    print("valid!")
else:
    print("invalid!")
