from hashlib import sha256 # for shared key
import secrets

from sha512 import *
from aes import *
from curves import *
from ecc import *
# import benchmark

# Elliptic Cryptography Diffie Hellman - Elliptic Cryptography Digital 
# Signature Algorithm - 256-bit Advanced Encryption Standard - 
# 512-bit Secure Hashing Algorithm (ecdhe_ecdsa_aes256_sha512)


# Sha512 for hkdf works for any key size as well. sha256 would be more
# efficient for key sizes used by AES but in terms of security
# (not counting side channel attacks), Sha512 implmenetation defined
# on this project would be more secure

""" Constants for encryption """
# Current constants are for aes256-sha256 for HKDF, sha512 for HMAC, aes256 for CMAC
HASHLEN = 32 # length of hash output in octets
HASH_BLOCK_SIZE = 64 # length of single block in octets in hashing algorithm
HKDF_SIZE = 32 # length of HKDF output in octects
HKDF_HASHF = sha256 # hashing algorithm used in HKDF
SHARED_KEY_SIZE = 66 # length of shared key in octets
MSG_SALT = "" # Message Salt
CURVE = Secp521r1 # Elliptic Curve
ECIES_SYMM_ENC_ALG = Aes256 # ECIES Symmetric Encryption Algorithm
ECIES_HMAC_HASHF = Sha512 # ECIES HMAC Hash Function
ECIES_HMAC_HASHF_BLOCK_SIZE = 128

# calculate key size of shared key in octets
# ceil(bitsize / 8)

# message to encrypt
msg = "abcdabcdabcdabcd"

curve = Secp521r1()
weierstrass = Weierstrass(curve.p,curve.a,curve.b)
alice = Curve(curve)
bob = Curve(curve)

# generate private keys of both Alice and Bob
alice.get_prikey(5848086670634336295179241537947744107056560678941168314791178081878633088455617469991013034321652554105110886298371233598544051928031241656197349434021052)
bob.get_prikey(65215690354676615037081482303758947066186667230878659726538709580154848544607330564152279281874441250878379865736772667630609470695976953483213929929888987)

# generate public keys of both Alice and Bob
alice.get_pubkey()
bob.get_pubkey()

print("Alice\'s private key:\t", alice.pri_k)
print("Bobs\'s private key:\t", bob.pri_k)

print("Alice\'s public key:\t", alice.pub_k)
print("Bobs\'s public key:\t", bob.pub_k)

# get compressed points
alice_pubk_comp = '0' + str(2 + alice.pub_k[1] % 2) + \
                  str(hex(alice.pub_k[0])[2:])
bob_pubk_comp = '0' + str(2 + bob.pub_k[1] % 2) + \
                str(hex(bob.pub_k[0])[2:])

# calculate shared secret
# they are equal to each other, shared secret equals x coordinate
a_shared_sec = weierstrass.multiply(bob.pub_k,alice.pri_k)[0]
b_shared_sec = weierstrass.multiply(alice.pub_k,bob.pri_k)[0]

# generate HKDF salt
hkdf_salt = b'p\xc3\xfc\xb7\xb4\xacY\xfeh.^o\xc5\xf4\x05\xc0w\x03\xb9}\x97C\xcf\xadI\x0c\x0f_\x8c\x82@\xe3' # generated using secrets.token_bytes(HASHLEN)
hkdf_info = b"testing"

# use HKDF for choosing size of key
a_shared_sec = hkdf(a_shared_sec, hkdf_salt, HKDF_HASHF, HASHLEN,
                    HASH_BLOCK_SIZE,hkdf_info,HKDF_SIZE,SHARED_KEY_SIZE)

# use HKDF for choosing size of key for encryption
b_shared_sec = hkdf(b_shared_sec, hkdf_salt, HKDF_HASHF, HASHLEN,
                    HASH_BLOCK_SIZE,hkdf_info,HKDF_SIZE,SHARED_KEY_SIZE)

print("shared_secret match:", a_shared_sec == b_shared_sec)

ecdsa = Ecdsa(curve)

# generate Alice's signature with ECDSA
signature = ecdsa.gen_signature(msg, alice.pri_k)

# signature generated for verification is ecdsa.unauth_sign
print("signature gen: ", signature)

ecies = Ecies(SHARED_KEY_SIZE,ECIES_SYMM_ENC_ALG,CURVE)

# Alice generates tag and sends it to Bob
tag = ecies.gen_hmac(msg,a_shared_sec,ECIES_HMAC_HASHF,
                     ECIES_HMAC_HASHF_BLOCK_SIZE)

# no IV in ECIES according to SEC 1, ver 1.9

# Alice encrypts message
ciphertext = ecies.encrypt(msg,a_shared_sec,None,True)

# Bob decrypts ciphertext
plaintext = ecies.decrypt(ciphertext,b_shared_sec,None,True)

# Bob verifies Alice's tag
verify_tag = ecies.verify_hmac(plaintext,b_shared_sec,)

# let Bob verify Alice's signature
m_hash = int(str(Sha512(plaintext.encode()).hexdigest()),16) % curve.n
verify_sign = ecdsa.verify_signature(signature, m_hash,
                                     alice.pub_k)

# Bob Potentionally recovers Alice's signature, doesn't always work
recovered_a_pubk = ecdsa.recover_pubkey(ecdsa.m_hash, signature)

print()
print("tag:\t", tag)
print("ciphertext:\t", ciphertext)
print("plaintext:\t", plaintext)
print("verify_tag:\t", verify_tag)
print("signature sign:", verify_sign)
print("recovered Alice's public key: ", alice.pub_k==recovered_a_pubk)
