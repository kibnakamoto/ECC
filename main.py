from sha512 import *
# from aes import *
from curves import *
from ecc import *
from hashlib import sha256 # for shared key
import secrets

# Sha512 for hkdf works for any key size as well. sha256 would be more efficient for key sizes used by AES but in terms of security(not counting side channel attacks), Sha512 implmenetation defined on this project would be more secure

""" Constants to choose for encryption """
HASHLEN = 32 # length of hash output in octets
HASH_BLOCK_SIZE = 64 # length of single block in octets in hashing algorithm
HKDF_SIZE = 32 # length of HKDF output in octects
HKDF_HASHF = sha256 # hashing algorithm used in HKDF
SHARED_KEY_SIZE = 66 # length of shared key in octets
MSG_SALT = "" # Message Salt

# TODO: test ecc.field_e_to_int function using non-prime fields
# TODO: make ECDSA implementation compatible with non-prime galois field

# calculate key size of shared key in octets
# ceil(bitsize / 8)

curve = Secp521r1()
alice_secp521r1 = Secp521r1()
bob_secp521r1 = Secp521r1()
weierstrass = Weierstrass(bob_secp521r1.p,bob_secp521r1.a,
                          bob_secp521r1.b)
alice = Curve(curve)
bob = Curve(curve)

# generate private keys of both Alice and Bob
alice.get_privkey(5848086670634336295179241537947744107056560678941168314791178081878633088455617469991013034321652554105110886298371233598544051928031241656197349434021052)
bob.get_privkey(65215690354676615037081482303758947066186667230878659726538709580154848544607330564152279281874441250878379865736772667630609470695976953483213929929888987)

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

# TODO: check if HKDF is correct by checking parameters and values outputted

# use HKDF for choosing size of key
a_shared_sec = hkdf(a_shared_sec, hkdf_salt, HKDF_HASHF, HASHLEN,
                    HASH_BLOCK_SIZE,hkdf_info,HKDF_SIZE,SHARED_KEY_SIZE)

# use HKDF for choosing size of key for encryption
b_shared_sec = hkdf(b_shared_sec, hkdf_salt, HKDF_HASHF, HASHLEN,
                    HASH_BLOCK_SIZE,hkdf_info,HKDF_SIZE,SHARED_KEY_SIZE)

if a_shared_sec == b_shared_sec:
    print("same secret key")

ecdsa = Ecdsa(curve)

# generate Alice's signature with ECDSA
signature = ecdsa.gen_signature("abc", alice.pri_k)

# let Bob verify Alice's signature
verify_sign = ecdsa.verify_signature(signature, ecdsa.m_hash,
                                     alice.pub_k)
print("signature gen: ", signature)
print("signature sign:", verify_sign)
