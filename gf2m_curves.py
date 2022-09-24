import math
import secrets
from ecc import *
from copy import deepcopy
from collections import Counter

# Galois Field 2^m Value Error, raise when there is an invalid value in GF(2^m)
class GF2mValueError(ValueError):
   pass 

class Sect571r1:
    def __init__(self):
        self.q = [571, 10, 5, 2, 1]
        self.n = 0x03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47
        self.a = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
        self.b = 0x02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A
        self.G = (0x0303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19,
                  0x037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B)
        self.h = 0x02

def int_to_poly(x:int):
    bits = bin(x)[2:]
    lenbits = len(bits)
    poly = set()
    for i in range(lenbits):
        if bits[i] == '1':
            poly.add(lenbits-i)
    return poly

def poly_to_int(x:list):
    y = [0]*(max(x))
    for i in range(len(x)):
        y[x[i]-1] = 1
    return int(str(y)[1:-1].replace(', ', '')[::-1],2)

def add_poly(x:set, y:set):
    x = set(x)
    y = set(y)
    poly = x|y
    for i in poly:
        if i in x and i in y:
            x.remove(i)
            y.remove(i)
    poly = sorted(x|y, reverse=True)
    return poly

def poly_mod_gf2m(x, f):
    while max(x) >= max(f):
        div = max(x) - max(f)
        mod = [] 
        for i in f:
            mod.append(i+div)
        print("poly:\t", mod)
        x = add_poly(x, mod)
    return x

x=0b1100
y=0b0110
for i in range(1, 16):
    print(bin(poly_to_int(list(poly_mod_gf2m(int_to_poly(2**i), {5,2,1}))))[2:].zfill(4))
raise Exception()
value = add_poly(int_to_poly(x),int_to_poly(y))

raise Exception(poly_mod(value, [5,2,1], 16))

# from https://www.cs.miami.edu/home/burt/learning/Csc609.142/ecdsa-cert.pdf
def gf2m_point_add(P, Q, q, m, a):
    lambda_ = ((P[1] + Q[1])*pow((P[0] + Q[0]),-1, q))%q
    x3 = (lambda_**2%q + lambda_ + P[0] + Q[0] + a)%q
    y3 = lambda_*(P[0] + x3) + x3 + P[1]
    return (x3,y3&q)
raise Exception(gf2m_point_add((6,8),(3,13), 2**4, 4, 1))

class GF_2m_Weierstrass:
    def __init__(self, curve):
        self.curve = curve
    
    # define private key generation for where cofactor doesn't have to be equal to one
    def set_priv_key(self, priv_key):
        self.priv_key = priv_key
        if self.priv_key == None:
            try:
                while self.priv_key%curve.h != 0:
                    self.priv_key = secrets.randbelow(curve.n)
            except TypeError:
                self.priv_key = secrets.randbelow(curve.n)
        else:
            if self.priv_key%curve.n != 0:
                raise GF2mValueError(f"private key is invalid: not multiple of h in {type(curve)}")
        return self.priv_key

    def set_pub_key(self, pub_key):
        pass
