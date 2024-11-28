# bench mark tests. mostly for time and a little bit for accuracy
from hashlib import *
from time import time
from pprint import pprint
from decimal import Decimal
import secrets
import tracemalloc
import string

from .curves import *
from .ecc import *
from .aes import *
from .sha512 import *

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
    def __init__(self,curve=Secp521r1,prikey_count=1000):
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
        print("-------- Time (Seconds) --------")
        print(f"curve: {type(curve)}")
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
        self.pair = (self.prikeys,self.pubkeys)
        
    def __call__(self):
        return self.pair

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
        print(f"curve: {type(curve)}")
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
        self.pair = (self.prikeys,self.pubkeys)
        
    def __call__(self):
        return self.pair

class Benchmark_Hkdf():
    def __init__(self,data1,data2,hashf=Sha512,curve=Secp521r1,hashlen=64,
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
            a_shared_secrets.append(weierstrass.multiply(pubkeys2[i],prikeys1[i])[0])
        start_a_sc = time()-start_a_sc
        start_b_sc = time()
        for i in range(length):
            b_shared_secrets.append(weierstrass.multiply(pubkeys1[i],prikeys2[i])[0])
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
        ab_sc_correct = a_shared_secrets == b_shared_secrets
        print("-"*len(f"curve: {type(curve)}"))
        print("             HKDF")
        print(f"curve: {type(curve)}")
        if ab_sc_correct:
            print("-------------SUCCESS-------------")
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
        return self.hkdf_keys

# ECIES Benchmark also verifies the symmetric encryption algorithm used
# as well as HMAC
class Benchmark_Ecies:
    def __init__(self,hkdf_keys,data=None,length=1000,data_maxsize=100,
                 curve=Secp521r1,keylen=66,symm_alg=Aes256,
                 symmkey_sise = 32,hmac_hashf=Sha512,hashf_block_size=128,inp='y'):
        ecies = Ecies(keylen,symm_alg,curve)
        a_sc,b_sc = hkdf_keys[0],hkdf_keys[1]
        tags = []
        if data == None:
            data = self.gen_rand_strings(length,data_maxsize)
        else:
            if not isinstance(data, tuple):
                data = tuple(data)
        tags_time = time()
        
        """ Time Tests """
        # Alice generates tag and sends it to Bob
        for i in range(length):
            tags.append(ecies.gen_hmac(data[i],a_sc[i],hmac_hashf,
                                       hashf_block_size))
        tags_time = time()-tags_time
        ciphertexts = []
        encrypt_time = time()
        # without delimeter data comparssion will be complicated when data length 
        # isn't a multiple of 16 so it is equal to True
        
        # Alice encrypts message
        for i in range(length):
            ciphertexts.append(ecies.encrypt(data[i],a_sc[i], None, True))
        encrypt_time = time()-encrypt_time
        plaintexts = []
        decrypt_time = time()
        
        # Bob decrypts ciphertext
        for i in range(length):
            plaintexts.append(ecies.decrypt(ciphertexts[i],b_sc[i],None, True))
        decrypt_time = time()-decrypt_time
        verify_tags = []
        tag_verifi_time = time()
        
        # Bob verifies Alice's tag
        for i in range(length):
            verify_tags.append(ecies.verify_hmac(plaintexts[i],b_sc[i], tags[i],
                                                 hmac_hashf,hashf_block_size))
        tag_verifi_time = time()-tag_verifi_time

        """ Accuracy Tests """
        wrong_tag_count = 0
        wrong_plaintext_count = 0
        for i in range(length):
            if verify_tags[i] == False:
                print("wrong tag at index: ", i)
                wrong_tag_count+=1
            if plaintexts[i] != data[i]:
                print("wrong plaintext at index: ", i)
                wrong_plaintext_count+=1
        
        self.data = data
        self.plaintexts = plaintexts
        
        print("\n\n---------------- ECIES TESTS ----------------\n")
        print(f"curve: {type(curve)}")
        print(f"\ndata length = {length}\ncurve: {type(curve)}")
        print(f"{length} tags calculation time: {tags_time}")
        print(f"tag calculation time: {Decimal(Decimal(tags_time)/length)}")
        print(f"{length} ciphertexts calculation time: {encrypt_time}")
        print(f"encryption calculation time: ",
              Decimal(Decimal(encrypt_time)/length))
        print(f"{length} plaintexts calculation time: {decrypt_time}")
        print(f"decryption calculation time: ",
              Decimal(Decimal(decrypt_time)/length))
        print(f"{length} tag verifications calculation time: {tag_verifi_time}")
        print(f"tag verifications calculation time: ",
              Decimal(Decimal(tag_verifi_time)/length))
        
        # if asked for specific data or have wrong data
        if wrong_tag_count != 0 or wrong_plaintext_count != 0 or inp == 'y':
            for i in range(length):
                print("\n\t{")
                pprint('i: {}'.format(i))
                pprint("tag: {}".format(tags[i]))
                pprint("secure: {}".format(verify_tags[i]))
                pprint("ct: {}".format(ciphertexts[i]))
                pprint("pt: {}".format(plaintexts[i]))
                pprint("data before encryption: {}".format(data[i]))
                print("\t}\n")
    
    def gen_rand_strings(self, length=1000, maxsize=100):
        data = []
        for i in range(length):
            alp = string.ascii_letters + string.digits
            while True:
                n = secrets.randbelow(maxsize)
                password = ''.join(secrets.choice(alp) for i in range(n))
                if (any(i.islower() for i in password) and any(i.isupper() 
                for i in password) and sum(i.isdigit() for i in password) >= 0):
                    break
            data.append(password)
        return tuple(data)

class Benchmark_Ecdsa:
    def __init__(self,a_pri_keys,a_pub_keys,data,plaintexts,
                 curve=Secp521r1,hashf=Sha512,length=1000,keys = None):
        ecdsa = Ecdsa(curve)
        
        # generate Alice's signatures
        self.signatures = []
        try:
            sign_gen_time = time()
            for i in range(length):
                 self.signatures.append(ecdsa.gen_signature(data[i],
                                                            a_pri_keys[i],
                                                            keys[i], hashf))
            sign_gen_time = time()-sign_gen_time
        except TypeError: # if keys = None
            sign_gen_time = time()
            for i in range(length):
                 self.signatures.append(ecdsa.gen_signature(data[i],
                                                            a_pri_keys[i],
                                                            keys, hashf))
            sign_gen_time = time()-sign_gen_time
        
        # calculate hashes of decrypted data
        hashgentime = time()
        hashes = []
        for i in range(length):
            hashes.append(int(str(hashf(plaintexts[i].encode()).hexdigest()),16))
        hashgentime = time()-hashgentime
        
        # Bob verifies Alice's signatures
        self.unauth_signs = []
        ver_sign_gen_time = time()
        for i in range(length):
            self.unauth_signs.append(ecdsa.verify_signature(self.signatures[i],
                                                            hashes[i],
                                                            a_pub_keys[i]))
        ver_sign_gen_time = time()-ver_sign_gen_time
        
        # potentially recover public keys
        recovered_count = 0
        recover_time = time()
        for i in range(length):
            try: # silence ValueError
                temp = ecdsa.recover_pubkey(hashes[i], self.signatures[i])
            except ValueError:
                continue
            else:
                if temp == a_pub_keys[i]:
                    recovered_count += 1
        recover_time = time()-recover_time

        verified = not (False in self.unauth_signs)
        corr_count = 0
        if not verified:
            for i in range(length):
                corr_count += int(self.unauth_signs[i])
        
        print("\n\n----------- ECDSA TEST -----------\n")
        print(f"curve: {type(curve)}")
        print(f"{length} signatures generation time: {sign_gen_time}")
        print("signature generation time: ", Decimal(Decimal(sign_gen_time) /
                                                     length))
        print(f"{length} messages hash generation time: {hashgentime}")
        print("message hash generation time: ", Decimal(Decimal(hashgentime) /
                                                        length))
        print(f"{length} verification signatures generation time: ",
              ver_sign_gen_time)
        print("verification signature generation time: ",
              Decimal(Decimal(ver_sign_gen_time)/length))
        print(f"{length} public keys recovery time: {recover_time}")
        print(f"public key recovery time: {Decimal(Decimal(recover_time)/length)}")
        print("  ---------- Accuracy ----------")
        print(f"signatures verified: {verified}")
        if corr_count != length and not verified:
            print("\n------------------- FAILURE -------------------")
            print(f"verified {corr_count} signatures out of {length}")
        else:
            print("\n--------- SUCCESS ---------")
            print("all signatures are verified")
        print(f"{recovered_count} public keys recovered out of {length}")
        print("--------- PUBLIC KEY RECOVERY IS NOT ACCURATE ---------\n")

# time, memory, and accuracy tests

# Prime SEC Curves

curve = Secp521r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=Sha512,curve=curve,
                           hashlen=64,hash_block_size=128,
                           size=32,sk_size=66).hkdf_keys
ecies_test =  Benchmark_Ecies(hkdf_test,data=None,length=10,
                              data_maxsize=100,curve=curve,keylen=66,
                              symm_alg=Aes256,symmkey_sise=32,
                              hmac_hashf=Sha512,hashf_block_size=128,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)

curve = Secp384r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=Sha512,curve=curve,
                           hashlen=64,hash_block_size=128,
                           size=32,sk_size=48).hkdf_keys
ecies_test =  Benchmark_Ecies(hkdf_test,data=None,length=10,
                              data_maxsize=100,curve=curve,keylen=48,
                              symm_alg=Aes256,symmkey_sise=32,
                              hmac_hashf=Sha512,hashf_block_size=128,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)

curve = Secp256k1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=sha256,curve=curve,
                           hashlen=32,hash_block_size=64,
                           size=32,sk_size=32).hkdf_keys
ecies_test =  Benchmark_Ecies(hkdf_test,data=None,length=10,
                              data_maxsize=100,curve=curve,keylen=32,
                              symm_alg=Aes256,symmkey_sise=32,
                              hmac_hashf=sha256,hashf_block_size=64,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)

curve = Secp256r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=sha256,curve=curve,
                           hashlen=32,hash_block_size=64,
                           size=32,sk_size=32).hkdf_keys
ecies_test =  Benchmark_Ecies(hkdf_test,data=None,length=10,
                              data_maxsize=100,curve=curve,keylen=32,
                              symm_alg=Aes256,symmkey_sise=32,
                              hmac_hashf=sha256,hashf_block_size=64,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)

curve = Secp224r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=sha256,curve=curve,
                           hashlen=32,hash_block_size=64,
                           size=32,sk_size=28).hkdf_keys
ecies_test = Benchmark_Ecies(hkdf_test,data=None,length=10,
                             data_maxsize=100,curve=curve,keylen=28,
                             symm_alg=Aes256,symmkey_sise=32,
                             hmac_hashf=sha256,hashf_block_size=64,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)

curve = Secp224k1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=sha256,curve=curve,
                           hashlen=32,hash_block_size=64,
                           size=32,sk_size=28).hkdf_keys
ecies_test = Benchmark_Ecies(hkdf_test,data=None,length=10,
                             data_maxsize=100,curve=curve,keylen=28,
                             symm_alg=Aes256,symmkey_sise=32,
                             hmac_hashf=sha256,hashf_block_size=64,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)

curve = Secp192r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=Sha512,curve=curve,
                           hashlen=64,hash_block_size=128,
                           size=16,sk_size=24).hkdf_keys
ecies_test = Benchmark_Ecies(hkdf_test,data=None,length=10,
                             data_maxsize=100,curve=curve,keylen=24,
                             symm_alg=Aes128,symmkey_sise=16,
                             hmac_hashf=sha256,hashf_block_size=64,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)

curve = Secp192k1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=sha256,curve=curve,
                           hashlen=32,hash_block_size=64,
                           size=24,sk_size=24).hkdf_keys
ecies_test = Benchmark_Ecies(hkdf_test,data=None,length=10,
                             data_maxsize=100,curve=curve,keylen=24,
                             symm_alg=Aes192,symmkey_sise=24,
                             hmac_hashf=Sha512,hashf_block_size=128,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)

# Prime Brainpool Curves

curve = Brainpoolp512r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=Sha512,curve=curve,
                           hashlen=64,hash_block_size=128,
                           size=32,sk_size=64).hkdf_keys
ecies_test =  Benchmark_Ecies(hkdf_test,data=None,length=10,
                              data_maxsize=100,curve=curve,keylen=64,
                              symm_alg=Aes256,symmkey_sise=32,
                              hmac_hashf=Sha512,hashf_block_size=128,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)

curve = Brainpoolp384r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=Sha512,curve=curve,
                           hashlen=64,hash_block_size=128,
                           size=32,sk_size=48).hkdf_keys
ecies_test =  Benchmark_Ecies(hkdf_test,data=None,length=10,
                              data_maxsize=100,curve=curve,keylen=48,
                              symm_alg=Aes256,symmkey_sise=32,
                               hmac_hashf=Sha512,hashf_block_size=128,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)


curve = Brainpoolp320r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=Sha512,curve=curve,
                           hashlen=64,hash_block_size=128,
                           size=32,sk_size=40).hkdf_keys
ecies_test =  Benchmark_Ecies(hkdf_test,data=None,length=10,
                              data_maxsize=100,curve=curve,keylen=40,
                              symm_alg=Aes256,symmkey_sise=32,
                               hmac_hashf=Sha512,hashf_block_size=128,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)
 
curve = Brainpoolp256r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=sha256,curve=curve,
                           hashlen=32,hash_block_size=64,
                           size=32,sk_size=32).hkdf_keys
ecies_test =  Benchmark_Ecies(hkdf_test,data=None,length=10,
                              data_maxsize=100,curve=curve,keylen=32,
                              symm_alg=Aes256,symmkey_sise=32,
                               hmac_hashf=sha256,hashf_block_size=64,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=Sha512,length=10,keys=None)


curve = Brainpoolp224r1()
data = Benchmark_Time_Curves(curve=curve,prikey_count=10).pair
data1 = Benchmark_Memory_Curves(curve=curve,prikey_count=10).pair
hkdf_test = Benchmark_Hkdf(data,data1,hashf=sha256,curve=curve,
                           hashlen=32,hash_block_size=64,
                           size=32,sk_size=28).hkdf_keys
ecies_test = Benchmark_Ecies(hkdf_test,data=None,length=10,
                             data_maxsize=100,curve=curve,keylen=28,
                             symm_alg=Aes256,symmkey_sise=32,
                             hmac_hashf=sha256,hashf_block_size=64,inp='n')
ecdsa_test = Benchmark_Ecdsa(a_pri_keys=data[0],a_pub_keys=data[1],
                             data=ecies_test.data,plaintexts=
                             ecies_test.plaintexts,curve=curve,
                             hashf=sha512,length=10,keys=None)

