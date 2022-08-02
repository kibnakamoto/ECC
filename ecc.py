from math import ceil
from hashlib import sha256 # optional
import curves
from sha512 import *
from aes import *

# convert key input in ECIES as byte

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
def hmac(key: bytearray, msg: bytearray,block_s: int = 128, machashf=Sha512,             form="hexdigest"):
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
    
    # param form is the format output,default is hex
    hashobj = machashf(opadkey + machashf((ipadkey + 
                       msg)).digest())
    if form[0] == "h": # if hexdigest
        return hashobj.hexdigest()
    return hashobj.digest()

# Cipher-based Message Authentication Code
class Cmac:
    def __init__(cipher=Aes256):
        pass

# Hash-based Key Deravation Function
def hkdf(key,salt=None,hashf=sha256,hashlen=32,blocklen=64,inf=b"",
         outlen=32,keylen=66):
    # if no salt is provided, salt = zero of length hashlen
    if salt == None:
        salt = bytes.fromhex("00"*hashlen)
    elif isinstance(salt,str):
        salt = bytes.fromhex(salt)
    
    # make sure data types of info and key are bytes, same thing for salt above
    if isinstance(inf,str):
        inf = bytes.fromhex(inf)
    if isinstance(key,int):
        key = hex(key)[2:].zfill(keylen*2)
        key = bytes.fromhex(key)
    prk = hmac(salt,key,blocklen,hashf,"d")
    n = ceil(outlen/hashlen)
    t = b""
    okm = b""
    for i in range(1,n+1):
        t = hmac(prk,t+inf+bytes([i]),blocklen,hashf,"d")
        okm+=t
    return okm[:outlen]

def hkdft(length: int, ikm, salt: bytes = b"", info: bytes = b"") -> bytes:
    """Key derivation function"""
    if len(salt) == 0:
        salt = bytes([0] * 32)
    prk = hmac(salt, ikm,64,sha256,'d')
    t = b""
    okm = b""
    for i in range(ceil(length / 32)):
        t = hmac(prk, t + info + bytes([i + 1]),64,sha256,'d')
        okm += t
    return okm[:length]
    
#  only for odd prime field size p. For field size q = 2^m, use integer 
#  conversion specified in ANSI X9.62
class Ecdsa:
    def __init__(self, curve=curves.Secp521r1):
        if hasattr(curve,"p"): # if prime curve
            self.p = curve.p
        else:
            self.m = curve.m
            self.size = curve.size # 2**m
        self.G = curve.G
        self.n = curve.n
        self.a = curve.a
    
    # generate A's signature
    def gen_signature(self, message: str, pri_key: int,
                      key: int = None,hashf=Sha512):
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

# from https://www.secg.org/sec1-v2.pdf
class Ecies:
    def __init__(self,keylen=66, encypt_alg=Aes256, curve=curves.Secp521r1):
        self.curve = curve
        self.keylen = keylen # shared-key length of hkdf shared key in octets
        self.tag = None
        self.encypt_alg = encrypt_alg
        self.enc = None
    
    # generate hmac of sender
    def gen_hmac(self,msg,key,alg=sha256,block_s=64):
        # if key is an integer, convert to byte array
        if isinstance(key,int):
            key = hex(key)[2:].zfill(self.keylen*2)
            key = bytes.fromhex(key)
        
        self.tag = hmac(key,msg.encode(),block_s,alg)
        return self.tag
    
    # verify HMAC, the receiver has to verify it to make sure message is
    # not tampered
    def check_hmac(self,msg,key,tag=None,alg=sha256,block_s=64):
        if tag == None:
            if self.tag == None:
                raise Exception("no tag provided")
        else:
            self.tag = tag

        # if key is an integer, convert to byte array
        if isinstance(key,int):
            key = hex(key)[2:].zfill(self.keylen*2)
            key = bytes.fromhex(key)
        self.unv_tag = hmac(key,msg.encode(),block_s,alg)
        
        # check tag
        self.tag_verified = self.tag == self.unv_tag
        if not self.tag_verified:
            raise Exception("wrong tag, message is tampered")
        return True
    
    def gen_cmac():
        pass

    def check_cmac():
        pass
    
    # msg is the message you want to encrypt
    # key is the established shared secret using the KDF as a bytearray
    # tag, verify that tag equals True 
    # if you want iv generated for you, then iv should equal True, no iv is None
    # add delimeter if msg length isn't 16 octets, None for none
    def encrypt(self,msg,key, iv=None, delimeter=None):
        # supported Symmetric Encryption Schemes
        # AES–128 in CBC mode
        # AES–192 in CBC mode
        # AES–256 in CBC mode
        
        # if key is an integer, convert to byte array
        if isinstance(key,int):
            key = hex(key)[2:].zfill(self.keylen*2)
            key = bytes.fromhex(key)
        
        self.key = key
        self.enc = self.encrypt_alg(iv)
        self.iv = self.enc.iv
        self.cipher = self.enc.encrypt(msg,key,delimeter)
        return self.cipher
    
    def decrypt(self,cipher,key,iv=None,delimeter=None):
        # if key is an integer, convert to byte array
        if isinstance(key,int):
            key = hex(key)[2:].zfill(self.keylen*2)
            key = bytes.fromhex(key)
        
        # decrypt ciphertext
        try:
            self.iv = self.enc.iv
        except NameError:
            self.enc = self.encrypt_alg(iv)
            self.iv = self.enc.iv
        self.plain = self.enc.decrypt(cipher,key,delimeter)
        
        # after decrypting, verify MAC so that you know message isn't tampered
        return self.plain


# Elliptic Cryptography Diffie Hellman - Elliptic Cryptography Digital 
# Signature Algorithm - 256-bit Advanced Encryption Standard - 
# 512-bit Secure Hashing Algorithm
class ecdhe_ecdsa_aes256_sha512:
    pass

# calculate keylen in ECIES using:
# ceil(bitkeysize/8)
