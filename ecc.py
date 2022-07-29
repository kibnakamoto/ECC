import curves
from sha512 import *

# same p,a,b parameters have to be used by both parties for 
# creating a shared key, the shared key will be used for symmetric encryption and elliptic cryptography digital signatures
def gen_shared_key(pri_k,pub_k, p, a):
    return curves.montgomery_ladder(pub_k, pri_k, p, a)[0]

# Hash-based Message Authentication Code
class Hmac:
    pass

# Cipher-based Message Authentication Code
class Cmac:
    pass

# sources (For finding resources, not representation)
# ANSI X9.62
# https://www.cs.miami.edu/home/burt/learning/Csc609.142/ecdsa-cert.pdf
#  only for odd prime field size p. For field size q = 2^m, use integer conversion specified in ANSI X9.62
class Ecdsa:
    def __init__(self, p, G, n, a):
        self.p = p
        self.G = G
        self.n = n
        self.a = a
    
    # generate A's signature
    def gen_signature(self, message: str, pri_key: int, key: int = None):
        if key == 0:
            raise Exception("key x is zero")
        
        m_hash = int(str(Sha512(message)),16)
        self.m_hash = m_hash
        y = 0

        # make sure y is not zero
        while y == 0:
            if key == None:
                self.key = 0
                
                # make sure the generated key is not zero
                while self.key == 0:
                    new_key = curves.gen_key(self.n)
                    kn = new_key+self.n
                    knn = kn+self.n
                    if len(bin(kn)[2:]) == len(bin(self.n)[2:]):
                        mul = curves.montgomery_ladder(self.G,knn,self.p,self.a)
                    else:
                        mul = curves.montgomery_ladder(self.G,kn,self.p,self.a)
                    self.key = mul[0] % self.n
            else:
                # use key provided as function parameter
                self.key = key
            
            # calculate modular inverse of key
            inv_key = pow(new_key,-1,self.n)
            
            # calculate y coordinate of signature
            y = inv_key*(m_hash + pri_key * self.key) % self.n
                        
            # if input key returns y = 0, exit with custom error message to
            # avoid endless loop
            if key != None and y == 0:
                raise Exception("inputted key returns y = 0")
            
            
            self.signature = (self.key,y)
        return self.signature
    
    # let B verify A's signature
    def verify_signature(self, signature: tuple, m_hash: int, a_pub_key: tuple):
        # verify that the signature point is generated correctly
        for i in range(2):
            if signature[i] == 0 or signature[i] > self.n:
                raise Exception("signature is zero or bigger than n")
        
        inv_y = pow(signature[1],-1,self.n)
        u1 = (m_hash*inv_y) % self.n
        u2 = (signature[0]*inv_y) % self.n
        g_u1 = curves.montgomery_ladder(self.G,u1,self.p,self.a)
        a_pub_key_u2 = curves.montgomery_ladder(a_pub_key,u2,self.p,self.a)
        pointX = curves.point_add(g_u1[0],g_u1[1],
                                  a_pub_key_u2[0],a_pub_key_u2[1],
                                  self.p,self.a)
        print("signature sign: ",pointX)
        if pointX == (0,1):
            print("generated verification signature is point at infinity")
            return float("inf")
        
        if pointX[0] == signature[0]:
            return True
        return False

class Ecies:
    pass

# Elliptic Cryptography Diffie Hellman - Elliptic Cryptography Digital 
# Signature Algorithm - 256-bit Advanced Encryption Standard - 
# 512-bit Secure Hashing Algorithm
class ecdhe_ecdsa_aes256_sha512:
    pass
