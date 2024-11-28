from math import ceil,sqrt
from copy import deepcopy
from collections import Counter
from hashlib import sha256 # optional
import secrets
from . import curves
from .sha512 import *
from .aes import *

def poly_mul(a,b,p):
    alength,blength = len(a),len(b)
    lst = [0]*(alength+blength-1)
    for i in range(alength):
        for j in range(blength):
            lst[i+j] = (a[i] * b[j] + lst[i+j])%p
    return lst

def poly_sq(a,p):
    alength = len(a)
    lst = [0]*(alength*2 - 1)
    for i in range(alength):
        for j in range(alength):
            lst[i+j] = (a[i] * a[j] + lst[i+j])%p
    return lst

def poly_mod(a,f,p):
    lenf = len(f)
    if lenf < 2:
        raise ValueError("f(x) smaller than 2")
    looped = False
    while len(a) >= lenf:
        if a[-1] != 0:
            for i in range(lenf,1,-1):
                a[-i] = (a[-i]-a[-1]*f[-i]) % p
        a = a[0:len(a)-1]
        looped = True
    if a[0] != 0 and looped:
        raise ValueError("Polynomial Modulo Error")
    return a

# calculatate the jacobi symbol
def jacobi(n,p):
    if p % 2 == 0 and p < 3:
        raise ValueError("Jacobi parameter p isn't odd and above 3")
    n%=p
    res = 1
    while n != 0:
        while n%2 == 0:
            n>>=1
            p8 = p%8
            if p8 == 3 or p8 == 5:
                res=-res
        p,n = deepcopy(n),deepcopy(p)
        if n%4 == 3 and p%4 == 3:
            res=-res
        n%=p
    if p == 1:
        return res
    else:
        return 0

# not necesarry
# def extended_euclidian(a,b):
#     pass # see https://cacr.uwaterloo.ca/hac/about/chap2.pdf algorithm 2.142

# Repeated square-and-multiply algorithm for exponentiation in Fpm
def rep_sq_mul_exp(gx, k, f, p):
    if k == 0:
        return list(1)
    
    if k > p:
        raise ValueError("k is not in prime field p")
    
    Gx = deepcopy(gx)
    if k%2 == 1:
        sx = deepcopy(gx)
    else:
        sx = list(1)
        
    while k > 1:
        k>>=1
        Gx = poly_mod(poly_sq(Gx,p),f,p)
        if k%2 == 1:
            sx = poly_mod(poly_mul(Gx,sx,p),f,p)
    return sx
    
# modular square root
def modular_sqrt(a,p):
    if 1 < a > p-1:
        raise ValueError("input isn't in correct range ")
    
    # calculate the jacobi symbol to find if there is a modular sqare root of a in p
    jacobi_symbol = jacobi(a,p)
    if jacobi_symbol == -1:
        raise ValueError("a does not have a sqrt modulo p")
    
    # This Implmenetation might be prone against timing side-channel attacks
    # Try only returning at the end of function
    
    if p % 4 == 3:
        return pow(a, (p+1)//4, p)
    
    if p % 8 == 5:
        d = pow(a, (p-1)//4, p)
        if d == 1:
            return pow(a, (p+3)//8, p)
        if d != p - 1:
            raise ValueError("d != p-1 when p%8 == 5")
        return (2*a*pow(4 * a, (p - 5)//8, p)) % p
    
    b = 2
    b_symbol = jacobi(pow(b,2,p)-4*a,p)
    while b_symbol != -1:
        # make sure b is in range(1,p)
        b+=1 # increment b until jacobi symbol is -1
        b_symbol = jacobi(pow(b,2,p)-4*a,p) # quadratic non-residue modulo p
        
        if b >= p:
            raise ValueError("no b can be calculated for chosen GF(p)")
    f = (a,-b,1)
    return rep_sq_mul_exp([0,1],(p+1)>>1,f,p)[0]

# same p,a,b parameters have to be used by both parties for 
# creating a shared key, the shared key will be used for symmetric encryption and elliptic cryptography digital signatures
def gen_shared_key(pri_k,pub_k, p, a):
    return curves.montgomery_ladder(pub_k, pri_k, p, a)[0]

# Hash-based Message Authentication Code
def hmac(key: bytearray, msg: bytearray,block_s: int = 128, 
         machashf=Sha512, form="hexdigest"):
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
    
#  only for odd prime field size p. For field size q = 2^m, use integer 
#  conversion specified in ANSI X9.62
class Ecdsa:
    def __init__(self, curve=curves.Secp521r1):
        self.q = curve.p
        self.G = curve.G
        self.n = curve.n
        self.a = curve.a
        self.b = curve.b
        self.h = curve.h
    
    # Potentially recover senders public key. Doesn't always work
    # for weierstrass curves only
    def recover_pubkey(self, m_hash, signature):
        # verify that the signature point is generated correctly
        for i in range(2):
            if signature[i] == 0 or signature[i] > self.n:
                raise ValueError("signature is zero or bigger than n")
        
        x = deepcopy(signature[0])
        
        # while x is not equal to Public key of sender
        for i in range(self.h):
            # x,y is on the curve, modular_sqrt is correct
            y = modular_sqrt((pow(x,3,self.q) + self.a*x +
                              self.b+self.q)%self.q,self.q)
            if y%2 == 0:
                y = self.q-y
            if y**2 == (pow(x,3,self.q) + self.a*x + self.b):
                if curves.montgomery_ladder((x,y),self.n,self.q,self.a) == (0,1):
                    break
            
            if self.h > 1:
                x = (x + self.n)%self.q

        for i in range(2):
            rinv = pow(x,-1,self.n)
            e_g = curves.montgomery_ladder(self.G, -m_hash%self.n, self.q, self.a)
            y_r = curves.montgomery_ladder((x,y), signature[1], self.q, self.a)
            yreg = list(curves.point_add(y_r[0],y_r[1],e_g[0],e_g[1],self.q,self.a))
            qa = curves.montgomery_ladder(yreg, rinv, self.q, self.a)
            if self.verify_signature(signature,m_hash,qa):
                break
            y = -y%self.q
        return qa

    # generate A's signature
    def gen_signature(self, message: str, pri_key: int,
                      key: int=None,hashf=Sha512):
        if key == 0:
            raise Exception("key x is zero")
        
        m_hash = int(str(hashf(message.encode()).hexdigest()),16) % self.n
        self.m_hash = deepcopy(m_hash)
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
                        mul = curves.montgomery_ladder(self.G,knn,
                                                       self.q,self.a)
                    else:
                        mul = curves.montgomery_ladder(self.G,kn,
                                                       self.q,self.a)
                    self.key = mul[0] % self.n
            else:
                # use key provided as function parameter
                self.key = key
            
            # calculate modular inverse of key
            inv_key = pow(new_key, -1, self.n)

            # calculate y coordinate of signature
            y = inv_key*(m_hash + pri_key * self.key) % self.n
                        
            # if input key returns y = 0, exit with custom error message to
            # avoid endless loop
            if key != None and y == 0:
                raise ValueError("inputted key returns y = 0")
            
            self.signature = (self.key,y)
        return self.signature
    
    # let B verify A's signature
    def verify_signature(self, signature: tuple, m_hash: int, a_pub_key: tuple):
        # verify that the signature point is generated correctly
        for i in range(2):
            if signature[i] == 0 or signature[i] > self.n:
                raise ValueError("signature is zero or bigger than n")
        
        inv_y = pow(signature[1],-1,self.n)
        u1 = ((m_hash%self.n)*inv_y) % self.n
        u2 = (signature[0]*inv_y) % self.n
        g_u1 = curves.montgomery_ladder(self.G,u1,self.q,self.a)
        a_pub_key_u2 = curves.montgomery_ladder(a_pub_key,u2,self.q,self.a)
        self.unauth_sign = curves.point_add(g_u1[0],g_u1[1],
                                            a_pub_key_u2[0],
                                            a_pub_key_u2[1],
                                            self.q,self.a)
        
        if self.unauth_sign == (0,1):
            raise ValueError("generated verification signature is point at infinity")
        return self.unauth_sign[0] == signature[0]

class Ecies:
    def __init__(self,keylen=66, encrypt_alg=Aes256, curve=curves.Secp521r1):
        self.curve = curve
        self.keylen = keylen # shared-key length of hkdf shared key in octets
        self.tag = None
        self.encrypt_alg = encrypt_alg
        self.enc = None
    
    # generate hmac of sender
    def gen_hmac(self,msg,key,alg=Sha512,block_s=128):
        # if key is an integer, convert to byte array
        if isinstance(key,int):
            key = hex(key)[2:].zfill(self.keylen*2)
            key = bytes.fromhex(key)
        
        self.htag = hmac(key,msg.encode(),block_s,alg)
        return self.htag
    
    # verify HMAC, the receiver has to verify it to make sure message is
    # not tampered
    def verify_hmac(self,msg,key,tag=None,alg=Sha512,block_s=128):
        if tag == None:
            if self.htag == None:
                raise Exception("no tag provided")
        else:
            self.htag = tag

        # if key is an integer, convert to byte array
        if isinstance(key,int):
            key = hex(key)[2:].zfill(self.keylen*2)
            key = bytes.fromhex(key)
        self.unv_htag = hmac(key,msg.encode(),block_s,alg)
        
        # check tag
        self.htag_verified = self.htag == self.unv_htag
        if not self.htag_verified:
            return False
            # raise ValueError("wrong tag, message is tampered")
        return True
    
    # TODO: define cmac
    # def gen_cmac(self,msg,key,cipher=Aes256,aeskeylen=32):
    #     # if key is an integer, convert to byte array
    #     if isinstance(key,int):
    #         key = hex(key)[2:].zfill(self.keylen*2)
    #         key = bytes.fromhex(key)
        
    #     self.ctag = cmac(key,msg.encode(),cipher,aeskeylen)
    #     return self.ctag
    
    
    # def verify_cmac(self,msg,key,tag=None,cipher=Aes256,aeskeylen=32):
    #     if tag == None:
    #         if self.ctag == None:
    #             raise Exception("no tag provided")
    #     else:
    #         self.ctag = tag
        
    #     # if key is an integer, convert to byte array
    #     if isinstance(key,int):
    #         key = hex(key)[2:].zfill(self.keylen*2)
    #         key = bytes.fromhex(key)
    #     self.unv_ctag = cmac(key,msg.encode(),cipher,aeskeylen)
        
    #     # check tag
    #     self.ctag_verified = self.ctag == self.unv_ctag
    #     if not self.ctag_verified:
            # return False
            # # raise ValueError("wrong tag, message is tampered")
    #     return True
    
    # msg is the message you want to encrypt
    # key is the established shared secret using the KDF as a bytearray
    # tag, verify that tag equals True 
    # iv should stay None in ECIES
    # add delimeter if msg length isn't 16 octets, None for none
    def encrypt(self, msg, key, iv=None, delimeter=None):
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
        self.enc = self.encrypt_alg(iv)
        self.iv = self.enc.iv
        self.plain = self.enc.decrypt(cipher,key,delimeter)
        
        # after decrypting, verify MAC so that you know message isn't tampered
        return self.plain

# calculate keylen in ECIES using:
# ceil(bitkeysize/8)
