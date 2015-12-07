from math import sqrt
from itertools import count, islice


def next_prime(n):
    while isprime(n) is False or safeprime(n) is False:
        n += 1
    return n


def safeprime(n):
    p = n * 2 + 1
    if isprime(p) is True:
        return True
    else:
        return False


def isprime(n):
    if n < 2: return False
    return all(n%i for i in islice(count(2), int(sqrt(n)-1)))


def genp(username, password):
    s = username + password
    sum = 0
    for c in s:
        i = ord(c)
        sum += i
    p = next_prime(sum)
    sp = p * 2 + 1
    return sp
