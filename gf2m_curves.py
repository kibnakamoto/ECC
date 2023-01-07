import math
import secrets
from ecc import *
from copy import deepcopy
from collections import Counter

# Galois Field 2^m Value Error, raise when there is an invalid value in GF(2^m)
class GF2mValueError(ValueError):
   pass 

class Sect571r1:
    """ default class constructor """
    def __init__(self):
        self.f = [572, 11, 6, 3, 1]
        self.m = 571
        self.q = 0x040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000213
        self.n = 0x03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47
        self.a = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
        self.b = 0x02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A
        self.G = (0x0303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19,
                  0x037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B)
        self.h = 0x02

# Integer to Polynomial
def int_to_poly(x:int):
    bits = bin(x)[2:]
    lenbits = len(bits)
    poly = set()
    for i in range(lenbits):
        if bits[i] == '1':
            poly.add(lenbits-i)
    return poly

# Polynomial to Integer
def poly_to_int(x:list):
    x = list(x)
    if len(x) == 1:
        return x[0]
    else:
        y = [0]*max(x)
    for i in range(len(x)):
        y[x[i]-1] = 1
    return int(str(y)[1:-1].replace(', ', '')[::-1],2)

# Add 2 Polynomials in any Galois Field
def add_poly(x:set, y:set):
    x = set(x)
    y = set(y)
    poly = x|y
    for i in poly:
        if i in x and i in y:
            x.remove(i)
            y.remove(i)
    poly = x|y
    if not poly:
        poly.add(0)
    else: # causes infinite loop with repetatition values
        poly.discard(0)
    return poly

# Polynomial Galois Field Modulo
def poly_mod_gf2m(x:set, f:set):
    maxf = max(f) 
    if not x:
        x.add(0)
    while max(x) >= maxf:
        div = max(x) - maxf
        mod = [] 
        for i in f:
            mod.append(i+div)
        x = add_poly(x, mod)
        if not x: 
            x.add(0)
    return x

############################ THE PROBLEM MIGHT BE WITH NEGATIVE VALUE CALCULATIONS

def poly_div(x:set, f:set):
    if not x:
        x.add(0)

    if not f:
        f.add(0)
    maxx = max(x)
    maxf = max(f)
    if maxx > 0:
        div = maxx - maxf
    else:
        div = maxx + maxf
    mod = []
    for i in f:
        mod.append(i+div)
    x = add_poly(x, mod)
    if not x:
        x.add(0)
    else:
        x.discard(0) # added later since value is changed a lot by this
    return x

# GF(2^m) polynomial multiplication without modulo
def poly_mul_nm(x:set,y:set):
    poly = set()
    if x:
        x.discard(0)
    if y:
        y.discard(0)
    for i in y:
        for j in x:
            if i < 0: # for negative polynomials
                ij = i-j-1
            else:
                ij = i+j-1
            if ij in poly:
                poly.remove(ij)
            else:
                poly.add(ij)
    if poly:
        poly.discard(0)
    return poly

# polynomial multiplication in Galois Field 2^m
def poly_mul_gf2m(x, y, f):
    poly = poly_mod_gf2m(poly_mul_nm(x,y),f)
    copy = {i for i in poly if i >= 0}
    return copy

# convert to Galois Field 2^m Element
def to_gf2m_e(x, f):
    return poly_mod_gf2m(int_to_poly(2**x), f)

# addition in GF(2^m) modulo f(x)
def gf2m_add(x:set, y:set, f:set):
    return poly_mod_gf2m(add_poly(x,y), f)

# modular inverse of a Binary Galois Field (GF 2^m) Polynomial
# TODO: debug
def mod_inv_gf2m(a:set, f:set):
    t = {0}
    newt = {1}
    r = f
    newr = a
    while newr != {0}:
        quo = poly_div(r, newr)
        r, newr = newr, gf2m_add(poly_div({1}, r), poly_mul_gf2m(quo, newr, f), f)
        t, newt = newt, gf2m_add(poly_div({1}, t), poly_mul_gf2m(quo, newt, f), f)
        print(f"q: {quo}\tr: {r}\tnewr: {newr}\tnewt: {newt}")
    return poly_mul_gf2m(r, t, f)
    return poly_mul_gf2m(poly_div({1}, r), t, f)
raise Exception(mod_inv_gf2m({3,1}, {5,2,1}))
raise Exception(poly_mul_gf2m({3,1}, {3}, {5,2,1}))
raise Exception(poly_mul_gf2m(mod_inv_gf2m({3,1}, {5,2,1}), {3,1}, {5,2,1}))

def poly_div_gf2m(a:set,b:set, f:set):
    return poly_mul_gf2m(a, mod_inv_gf2m(b, f), f)

# Operations in the Galois Field 2^m
class GF2m:
    """ default class constructor """
    def __init__(self, elem=None, f:list=None):
        self.f = f
        if isinstance(elem, int):
            self.e = set(to_gf2m_e(elem, f))
        else:
            self.e = set(elem) # if elem is not int, it is already a polynomial
    
    # Addition in Galois Field 2^m
    def __add__(self, other):
        if isinstance(other, GF2m):
            obj = GF2m(gf2m_add(self.e, other.e, self.f), self.f)
        else:
            obj = GF2m(gf2m_add(self.e, to_gf2m_e(other, self.f), self.f), self.f)
        return obj

    def __iadd__(self, other):
        self.e = gf2m_add(self.e, other.e, self.f)
        return self
    
    # Polynomial multiplication in Galois Field 2^m
    def __mul__(self, other):
        obj = GF2m(poly_mul_gf2m(self.e, other.e, self.f), self.f)
        return obj
    
    # Polynomial multiplication on Galois Field in 2^m
    def __imul__(self, other):
        self.e = poly_mul_gf2m(self.e, other.e, self.f)
        return self
    
    # get the power of a number as a polynomial, not for large numbers since it uses loop
    def __pow__(self, x):
        integer = self.e # actually a poly not int
        for i in range(x):
            integer = poly_mul_gf2m(integer, integer, self.f)
        obj = GF2m(integer, self.f)
        return obj

    def __ipow__(self, x):
        integer = self.e # actually a poly not int
        for i in range(x):
            integer = poly_mul_gf2m(integer, integer, self.f)
        self.e = integer
        return self
    
    # Polynomial Modulo f(x)
    def __mod__(self, f):
        obj = GF2m(poly_mod_gf2m(self.e, f), f)
        return obj
    
    # Polynomial Modulo f(x)
    def __imod__(self, f):
        self.e = poly_mod_gf2m(self.e, f)
        return self
    
    # modular inverse in Galois Field 2^m
    def __invert__(self):
        #self.e.discard(0) 
        #tmp = mod_inv_gf2m(self.e, self.f)
        #tmp.discard(0)
        obj = GF2m(pow(poly_to_int(self.e), -1, poly_to_int(self.f)), self.f)
        return obj

    # Binary Galois Field Polynomial Division
    def __truediv__(self, other):
        obj = GF2m(poly_div(self.e, other.e), self.f)
        return obj

    # Binary Galois Field Polynomial Division
    def __itruediv__(self, other):
        self.e = poly_div(self.e, other.e)
        return self
     
    # Galois Field Division using Modular Inverse
    def __floordiv__(self, other):
        obj = GF2m(poly_div_gf2m(self.e, other.e, self.f), self.f)
        return obj
    
    # Galois Field Division using Modular Inverse
    def __ifloordiv__(self, other):
        self.e = poly_div_gf2m(self.e, other.e, self.f)
        return self
    
    # Boolean Comparison Operators

    # <
    def __lt__(self, other):
        return max(self.e) < max(other.e)
    
    # <=
    def __le__(self, other):
        return max(self.e) <= max(other.e)
 
    # >
    def __gt__(self, other):
        return max(self.e) > max(other.e)

    # >=
    def __ge__(self, other):
        return max(self.e) >= max(other.e)
    
    # ==
    def __eq__(self, other):
        return self.e == other.e
    
    # !=
    def __ne__(self, other):
        return self.e != other.e
    
    def __repr__(self):
        return "polynomial:\t% s\nf(x):\t% s" % (self.e, self.f)

# TEST finding GF(2^m) elements
# for i in range(1,16):
#     h = to_gf2m_e(i, [5,2,1])
#     conv = poly_to_int(h)
#     print(h, i, conv)

# raise Exception(GF2m(8, [5,2,1]) + GF2m(13, [5,2,1])) # addition test
# raise Exception(GF2m(13, [5,2,1]) * GF2m(14, [5,2,1])) # multiplication test
# raise Exception(~GF2m(13, [5,2,1])) # modular inverse test
#raise Exception(GF2m(11,[5,2,1]) // GF2m(11, [5,2,1])) # modular inverse test 2
#raise Exception(GF2m(11,[5,2,1]) * ~GF2m(11, [5,2,1])) # modular inverse test 3
################ ALL ARITHMETIC OPERATIONS TESTED ABOVE ARE CORRECT

# from https://www.cs.miami.edu/home/burt/learning/Csc609.142/ecdsa-cert.pdf
def gf2m_point_add(P, Q, f):
    x1 = GF2m(P[0], f)
    y1 = GF2m(P[1], f)
    x2 = GF2m(Q[0], f)
    y2 = GF2m(Q[1], f)
    lambda_ =  (y1+y2) // (x1+x2)
    print(f"lambda: {lambda_}")
    x3 = lambda_**2 + lambda_ + x1 + x2 + GF2m([2,1], f) # a = 4, a = alhpa^4, a = 0b0011
    y3 = lambda_*(x1+x3) + x3 + y1
    return (x3, y3)

def gf2m_point_double(P, f):
    x1s = GF2m(P[0], f)**2
    x1 = GF2m(P[0], f)
    y1 = GF2m(P[1], f)
    b = GF2m(1, f)
    x3 = x1s + b / x1s
    y3 = x1s + (x1 + y1/x1)*x3 + x3
    return (x3, y3)

raise Exception(gf2m_point_add((6,8),(3,13), [5,2,1]))
#print(GF2m(10, [5,2,1]))
#print(GF2m(8, [5,2,1]))
raise Exception(gf2m_point_double((6,8), [5,2,1]))

class GF_2m_Weierstrass:
    """ default class constructor """
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
