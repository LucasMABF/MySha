def shift_r(bits, shift):
    bits = bits[:-shift]
    bits = bits.zfill(shift + len(bits))
    return bits


def rotate_r(bits, shift):
    shift %= len(bits)
    t = bits[-shift:]
    bits = t + bits[:-shift]
    return bits


def xor(bits1, bits2):
    bits = ''
    for i1, i2 in zip(bits1, bits2):
        if int(i1) + int(i2) == 1:
            bits += '1'
        else:
            bits += '0'
    return bits


def add(bits1, bits2):
    l = len(bits1)
    n1 = int(bits1, 2)
    n2 = int(bits2, 2)
    bits = bin(n1 + n2)[2:]
    bits = bits[-l:]
    bits = bits.zfill(l)
    return bits


def sigma0(bits):
    return xor(xor(rotate_r(bits, 7), rotate_r(bits, 18)), shift_r(bits, 3))


def sigma1(bits):
    return xor(xor(rotate_r(bits, 17), rotate_r(bits, 19)), shift_r(bits, 10))


def SIGMA0(bits):
    return xor(xor(rotate_r(bits, 2), rotate_r(bits, 13)), rotate_r(bits, 22))


def SIGMA1(bits):
    return xor(xor(rotate_r(bits, 6), rotate_r(bits, 11)), rotate_r(bits, 25))


def choice(bits1, bits2, bits3):
    bits = ''
    for i1, i2, i3 in zip(bits1, bits2, bits3):
        if i1 == '1':
            bits += i2
        else:
            bits += i3
    return bits


def majority(bits1, bits2, bits3):
    bits = ''
    for i in zip(bits1, bits2, bits3):
        if i.count('0') < 2:
            bits += '1'
        else:
            bits += '0'
    return bits


def get_message_blocks(message):
    size = bin(len(message))[2:].zfill(64)
    message += '1'

    while (len(message) + len(size)) % 512 != 0:
        message += '0'

    message += size
    message_blocks = []
    for i in range(0, len(message), 512):
        message_blocks.append(message[i:i+512])

    return message_blocks


PRIMES = []

i = 2
while len(PRIMES) < 64:
    isPrime = True
    for b in range(2, i):
        if i % b == 0:
            isPrime = False

    if isPrime:
        PRIMES.append(i)

    i += 1

K = []

for prime in PRIMES:
    K.append(bin(int((prime**(1/3) - int(prime**(1/3))) * 2**32))[2:].zfill(32))

A = []
for i in range(8):
    A.append(bin(int((PRIMES[i] ** (1 / 2) - int(PRIMES[i] ** (1 / 2))) * 2 ** 32))[2:].zfill(32))


def main():
    text = 'abc'

    bits = ''.join(format(ord(i), '08b') for i in text)

    message_blocks = get_message_blocks(bits)

    a0, b0, c0, d0, e0, f0, g0, h0 = A
    
    for message_block in message_blocks:
        message_schedule = []

        for i in range(0, 512, 32):
            message_schedule.append(message_block[i:i+32])

        for i in range(16, 64):
            message_schedule.append(add(add(add(sigma1(message_schedule[i - 2]), message_schedule[i - 7]), sigma0(message_schedule[i - 15])), message_schedule[i - 16]))

        a = a0
        b = b0
        c = c0
        d = d0
        e = e0
        f = f0
        g = g0
        h = h0

        for i, m in enumerate(message_schedule):
            t1 = add(add(add(add(SIGMA1(e), choice(e, f, g)), h), K[i]), m)
            t2 = add(SIGMA0(a), majority(a, b, c))
            h = g
            g = f
            f = e
            e = add(d, t1)
            d = c
            c = b
            b = a
            a = add(t1, t2)

        a0 = add(a, a0)
        b0 = add(b, b0)
        c0 = add(c, c0)
        d0 = add(d, d0)
        e0 = add(e, e0)
        f0 = add(f, f0)
        g0 = add(g, g0)
        h0 = add(h, h0)

    a = hex(int(a0, 2))[2:].zfill(8)
    b = hex(int(b0, 2))[2:].zfill(8)
    c = hex(int(c0, 2))[2:].zfill(8)
    d = hex(int(d0, 2))[2:].zfill(8)
    e = hex(int(e0, 2))[2:].zfill(8)
    f = hex(int(f0, 2))[2:].zfill(8)
    g = hex(int(g0, 2))[2:].zfill(8)
    h = hex(int(h0, 2))[2:].zfill(8)

    hash256 = a + b + c + d + e + f + g + h  # ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

    print(hash256)


if __name__ == '__main__':
    main()
