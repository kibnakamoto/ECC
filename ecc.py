import curves

# same p,a,b parameters have to be used by both parties for 
# creating a shared key, the shared key will be used for symmetric encryption and elliptic cryptography digital signatures
def gen_shared_key(pri_key,pub_k, p, a):
    return curves.montgomery_ladder(pub_k, pri_k, p, a)[0]

# For hashing, sha512 is used. use hashlib for more hashing algorithms

# Hash-based Message Authentication Code
class Hmac:
    pass

# Cipher-based Message Authentication Code
class Cmac:
    pass

class Ecdsa:
    def __init__(self, p, G, n, a):
        self.p = p
        self.a = a
        self.n = n
        self.G = G
    
    # generate A's signature
    def gen_signature(message: str, pri_key: int, key: int = None):
        if key == 0:
            raise Exception("key x is zero")
        
        m_hash = int(Sha512(message),16)
        y = 0
        while y == 0:
            if key == None:
                self.key = 0
                
                # make sure the generated key is not zero
                while self.key == 0:
                    new_key = curves.gen_key(self.n)
                    self.key = gen_shared_key(new_key,self.G,
                                              self.p,self.a)
            else:
                self.key = key
                
            # calculate modular inverse of key
            inv_key = pow(self.key,-1,self.n) % self.n
            
            # calculate y coordinate of signature
            y = inv_key*(m_hash + pri_key*self.key) % self.n
            self.signature = (self.key,y)
        return self.signature
    
    # let B verify A's signature
    def verify_signature(signature: tuple, message: str, a_pub_key: tuple):
        # verify that the signature point is generated correctly
        for i in range(2):
            if signature[i] == 0 or signature[i] > self.n:
                raise Exception("signature is zero or bigger than n")
        m_hash = int(Sha512(message),16)
        inv_y = pow(sigmature[1],-1,self.n) % self.n
        u1 = (m_hash*inv_y) % self.n
        u2 = (signature[0]*inv_y) % self.n
        mul_g_u1 = curves.montgomery_ladder(self.G,u1,self.p,self.a)
        mul_a_pub_key_u2 = curves.montgomery_ladder(a_pub_key,u2,self.p,self.a)
        pointX = curves.point_add(mul_g_u1[0],mul_g_u1[1],
                                  mul_a_pub_key_u2[0],mul_a_pub_key_u2[1],
                                  self.p,self.a)
        
        if pointX == (0,1):
            print("pointX points to infinity")
            return float("inf")
        
        if pointX[0] == signature[0]:
            return True
        return False

class Ecies:
    pass

# Elliptic Cryptography Diffie Hellman - Elliptic Cryptography Digital 
# Signature Algorithm - 256-bit Advanced Encryption Standard - 
# 512-bit Secure Hashing Algorithm
class ecdh_ecdsa_aes256_sha512:
    pass
