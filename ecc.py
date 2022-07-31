import curves
from sha512 import *
from hashlib import sha1,sha256,sha384 # optional
from aes import *

# same p,a,b parameters have to be used by both parties for 
# creating a shared key, the shared key will be used for symmetric encryption and elliptic cryptography digital signatures
def gen_shared_key(pri_k,pub_k, p, a):
    return curves.montgomery_ladder(pub_k, pri_k, p, a)[0]

# field element to integer, used for non-prime fields
# m = None is when prime field, not tested. Test with sect571k1
def field_e_to_int(a, size, m=None):
    if m == None:
        return a
    x = 0
    bits = bin(a)[2:].zfill(m)
    for i in range(m):
        x = (x + int(bits[i])*2**i) % size
    return x

# Hash-based Message Authentication Code
def hmac(key: bytearray, msg: str,block_s: int = 128, machashf=Sha512):
    if len(key) == block_s:
        new_key = bytearray(key)
    elif len(key) > block_s:
        new_key = machashf(key).digest()

        # pad
        for i in range(block_s-len(new_key)):
            new_key += b'\x00'
    else:
        # pad
        new_key = key
        for i in range(len(key),block_s):
            new_key += b'\x00'
    
    # calculate opad and ipad
    ipadkey,opadkey = bytearray(),bytearray()
    for i in range(block_s):
        ipadkey.append(new_key[i] ^ 0x36)
        opadkey.append(new_key[i] ^ 0x5c)
    return machashf(opadkey + machashf((ipadkey + 
                     msg.encode())).digest()).hexdigest()

# Cipher-based Message Authentication Code
class Cmac:
    def __init__(cipher=Aes256):
        pass

#  only for odd prime field size p. For field size q = 2^m, use integer 
#  conversion specified in ANSI X9.62
class Ecdsa:
    def __init__(self, curve=curves.Secp521r1):
        if hasattr(curve,"p"):
            self.p = curve.p
        else:
            self.m = curve.m
            self.size = curve.size
        self.G = curve.G
        self.n = curve.n
        self.a = curve.a
    
    # generate A's signature
    def gen_signature(self, message: str, pri_key: int, key: int = None,hashf=Sha512):
        if key == 0:
            raise Exception("key x is zero")
        
        m_hash = int(str(hashf(message).hexdigest()),16)
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
        
        if pointX == (0,1):
            print("generated verification signature is point at infinity")
            return float("inf")
        
        if pointX[0] == signature[0]:
            return True
        return False

class Ecies:
    def __init__(curve=Secp521r1):
        pass
    
    def check_hmac():
        pass
    
    def check_cmac():
        pass

# Elliptic Cryptography Diffie Hellman - Elliptic Cryptography Digital 
# Signature Algorithm - 256-bit Advanced Encryption Standard - 
# 512-bit Secure Hashing Algorithm
class ecdhe_ecdsa_aes256_sha512:
    pass
