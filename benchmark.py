# bench mark tests. mostly for time and a little bit for accuracy
from hashlib import *
from time import time
import secrets
import tracemalloc
from decimal import Decimal
from curves import *
from ecc import *
from aes import *
from sha512 import *

# generate list of random private keys
def genrandkeylist(n,to):
    # parameter n is curve.n
    x = []
    for i in range(to):
        x.append(secrets.randbelow(n))
    return x

# generate list of random private keys with timer
def genrandkeylist_wtimer(n,to,pair):
    # parameter n is curve.n
    x = []
    start = time()
    for i in range(to):
        pair.get_prikey()
        x.append(pair.pri_k)
    return time()-start,x

# test key generation of curves from the curves module
class Benchmark_Time_Curves:
    def __init__(self,curve=curves.Secp521r1,prikey_count=1000):
        self.curve = curve
        pair = Curve(self.curve)
        
        # generate list private keys
        self.randkeytimer, \
        self.prikeys = genrandkeylist_wtimer(self.curve.n,
                                             prikey_count,pair)
        self.pubkeys = []
        self.startpubkey = time()
        for i in range(prikey_count):
            pair.get_pubkey(self.prikeys[i])
            self.pubkeys.append(pair.pub_k)
        self.endpubkey = time()
        
        # print values
        print("---------------------")
        print("Benchmark_Time_Curves")
        print(f"key pair count = {len(self.prikeys)}")
        print(f"{prikey_count} private keys gen time:", 
              Decimal(self.randkeytimer))
        print(f"private key gen time:", Decimal(Decimal(self.randkeytimer)/
                                                prikey_count))
        print(f"{prikey_count} Public keys gen time:", 
              self.endpubkey-self.startpubkey)
        print(f"public key gen time:", Decimal((Decimal(self.endpubkey)-
                                                 Decimal(self. \
                                                         startpubkey)) /
                                                 prikey_count))
        print("TOTAL time:", Decimal(Decimal(self.randkeytimer)/
                                     prikey_count) +
              Decimal(Decimal(self.endpubkey)-Decimal(self.startpubkey)))
        print("DONE")
    
    def __call__(self):
        return (self.prikeys,self.pubkeys)

# test key generation memory usage of curves from the curves module
class Benchmark_Memory_Curves:
    def __init__(self,curve=curves.Secp521r1,prikey_count=1000):
        tracemalloc.start()
        before_calc_memory = tracemalloc.get_traced_memory()[0]
        self.curve = curve
        pair = Curve(self.curve)
        
        # generate list private keys
        self.prikeys = genrandkeylist(self.curve.n,
                                      prikey_count)
        self.after_prikey_memory = tracemalloc.get_traced_memory()[0] - \
                                   before_calc_memory
        self.pubkeys = []
        for i in range(prikey_count):
            pair.get_pubkey(self.prikeys[i])
            self.pubkeys.append(pair.pub_k)
        self.after_pubkey_memory = tracemalloc.get_traced_memory()[0] - \
                                   self.after_prikey_memory
        # print values
        print(f"\n-------- MEMORY (bytes) --------\n")
        print("memory useage before calculations:\t", 
              before_calc_memory)
        print(f"memory useage after private key calculations:\t",
              self.after_prikey_memory)
        print(f"memory useage after public key calculations:\t",
                self.after_pubkey_memory)
        print(f"current memory: {tracemalloc.get_traced_memory()[0]}")
        print(f"peak memory usage throughout program:",tracemalloc. \
              get_traced_memory()[1])
        print("DONE")
        tracemalloc.stop()
    
    def __call__(self):
        return (self.prikeys,self.pubkeys)

class Benchmark_Hkdf():
    def __init__(data1,data2,hashf=Sha512,curve=Secp521r1,hashlen=64,
                 hash_block_size=128,size=32,sk_size=66):
        # use 2 sets of data Alice's and Bob's
        prikeys1, pubkeys1,length = data1[0],data1[1],len(data1[0])
        prikeys2, pubkeys2 = data2[0],data2[1]
        
        hkdf_salt = None # no salt
        hkdf_info = b"" # no info
        a_shared_secrets,b_shared_secrets = [],[]
        weierstrass = Weierstrass(curve.p,curve.a,curve.b)
        start_a_sc = time()
        
        # find Alice's shared secrets
        for i in range(length):
            a_shared_secrets.append(weierstrass.multiply(pubkeys1[i],prikeys1[i])[0])
        start_a_sc = time()-start_a_sc
        start_b_sc time()
        for i in range(length):
            b_shared_secrets.append(weierstrass.multiply(pubkeys2[i],prikeys2[i])[0])
        start_b_sc = time()-start_b_sc
        start_a_sc_hkdf = time()
        
        # use HKDF for choosing size of key
        for i in range(length):
            a_shared_secrets[i] = hkdf(a_shared_secrets[i], hkdf_salt,
                                         hashf, hashlen, hash_block_size,
                                         hkdf_info,size,sk_size)
        start_a_sc_hkdf = time()-start_a_sc_hkdf
        start_b_sc_hkdf = time()
        
        # use HKDF for choosing size of key for encryption
        for i in range(length):
            b_shared_secrets[i] = hkdf(b_shared_secrets[i], hkdf_salt,
                                         hashf, hashlen, hash_block_size,
                                         hkdf_info,size,sk_size)
        self.hkdf_keys = (a_shared_secrets,b_shared_secrets)
        start_b_sc_hkdf = time()-start_b_sc_hkdf
        
        # Test correctness
        ab_sc_correct = 0
        for i in range(length):
            ab_sc_correct |= int(a_shared_secrets == b_shared_secrets)
        if bool(ab_sc_correct):
            print("--------------SUCCESS--------------")
            print("correct shared secret(s) generated")
        else:
            print("-------------FAILURE-------------")
            print("wrong shared secret(s) generated")
        print(f"data length = {length}")
        print(f"Alice's shared key of size {sk_size} octets\tgeneration time:", 
              start_a_sc)
        print(f"Bob's shared key of size {sk_size} octets\tgeneration time:", 
              start_b_sc)
        print(f"Alice's shared key of size {size} octets\tgeneration time:", 
              start_a_sc_hkdf)
        print(f"Bob's shared key after hkdf of size {size} octets\tgeneration time:", 
              start_b_sc_hkdf)
    
    def __call__(self):
        return (self.hkdf_keys)

class Benchmark_Ecies:
    def __init__(self,hkdf_keys,curve=Secp521r1,keylen=66, symm_alg=Aes256,symmkey_sise = 32):
        

class Benchmark_Ecdsa:
    pass

# time
curve = Secp521r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10)
curve = Secp256k1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10)
curve = Secp256r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10)

# memory
curve = Secp521r1()
Benchmark_Memory_Curves(curve=curve,prikey_count=10)
curve = Secp256k1()
Benchmark_Memory_Curves(curve=curve,prikey_count=10)
curve = Secp256r1()
Benchmark_Memory_Curves(curve=curve,prikey_count=10)
