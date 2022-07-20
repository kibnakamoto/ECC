import secrets
import math

# implementation of secp521r1 and weistress curve

class Weierstrass:
    # x and y coordinates of points should satisfy the following equation:
    # y2 = x3 + Ax + B
    """ default class initializer """
    def __init__(self, p: int, a: int, b: int):
        self.p = p
        self.a = a
        self.b = b
    
    def point_add(self, xp, yp, xq, yq):
        # equation for private key and pointG
        # find lambda
        if yp == yq or xp == xq:
            __lambda = ((3*(xp**2) + self.a)*pow(2*yp, self.p-2*yp, self.p)) % self.p
        else:
            __lambda = ((yq-yp)*pow(xq-xp, -1, self.p)) % self.p
        xr = (__lambda**2 - xp - xq) % self.p
        yr = (__lambda*(xp-xr) - yp) % self.p
        return (xr%self.p, yr%self.p)

    def point_double(self, x, y):
        __lambda = ((3*(x**2) + self.a)*pow(2*y, self.p-2*y, 
                                            self.p)) % self.p
        xr = __lambda**2 - 2*x
        
        # use ys's negative values
        yr = __lambda*(x - xr) - y
        return (xr%self.p,yr%self.p)
    
    def rec_mul(self, g: tuple, d: int):
        w = Weierstrass(self.p,self.a,self.b)
        if d == 0:
            return (0,0)
        elif d == 1:
            return g
        elif d%2 == 1:
            add = w.rec_mul(g, d - 1)
            return w.point_add(g[0], g[1], add[0], add[1])
        else:
            return w.rec_mul(w.point_double(g[0],g[1]), d//2)
    
    def multiply(self,pointG: tuple, prikey: int):
        weierstrass = Weierstrass(self.p,self.a,self.b)
        self.pointG = pointG
        self.prikey = prikey
        
        if prikey == 0:
            return math.inf
        
        if (pointG[1]**2)%self.p == (pointG[0]**3 + 
                                     self.a*pointG[0] + 
                                     self.b) % self.p:
            # bits = bin(prikey)[2:]
            # i = len(bits)-2
            # result = [pointG[0],pointG[1]]
            # while i >= 0:
            #     result = weierstrass.point_double(result[0], 
            #                                       result[1])
            #     if bits[i] == '1':
            #         result = weierstrass.point_add(result[0],
            #                                        result[1],
            #                                        pointG[0],
            #                                        pointG[1])
            #     i-=1
            r0 = (0,1)
            r1 = list(self.pointG)
            bits = bin(self.prikey)[2:]
            for i in range(len(bits)-1,-1,-1):
                if bits[i] == '0':
                    r1 = weierstrass.point_add(r0[0],r0[1],
                                               r1[0],r1[1])
                    r0 = weierstrass.point_double(r0[0],r0[1])
                else:
                    r0 = weierstrass.point_add(r0[0],r0[1],
                                               r1[0],r0[1])
                    r1 = weierstrass.point_double(r1[0],r1[1])
            return (r0[0],r0[1])
            
            # result = weierstrass.rec_mul(self.pointG, self.prikey)
            # return (result[0]%self.p,result[1]%self.p)
            
            # return ((prikey*pointG[0])%p, (prikey*pointG[1])%p)
        else:
            raise Exception("parameters do not satisfy equation")

class Secp521r1:
    def __init__(self):
        self.p = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        self.h = 1
        self.n = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
        self.tr = 0x5ae79787c40d069948033feb708f65a2fc44a36477663b851449048e16ec79bf7
        self.a = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
        self.b = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
        self.G = (0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
                  0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)
        self.c = 0x0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637
        self.seed = 0xd09e8800291cb85396cc6717393284aaa0da64ba
    
    def get_privkey(self, pri_k=0):
        # numbers from 1 to n-1. But 1 is not given as the starting range
        if(pri_k == 0):
            self.pri_k = secrets.randbelow(self.n)
        else:
            self.pri_k = pri_k
    
    def get_pubkey(self):
        weierstrass = Weierstrass(self.p,self.a,self.b)
        self.pub_k = weierstrass.multiply(self.G, self.pri_k)

class Secp256r1:
    def __init__(self):
        self.p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
        self.n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        self.a = 0x0000000000000000000000000000000000000000000000000000000000000000
        self.b = 0x0000000000000000000000000000000000000000000000000000000000000007
        self.G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
        self.h = 1

    def get_privkey(self, pri_k=0):
        # numbers from 1 to n-1. But 1 is not given as the starting range
        if(pri_k == 0):
            self.pri_k = secrets.randbelow(self.n)
        else:
            self.pri_k = pri_k
    
    def get_pubkey(self):
        weierstrass = Weierstrass(self.p, self.a, self.b)
        self.pub_k = weierstrass.multiply(self.G, self.pri_k)
