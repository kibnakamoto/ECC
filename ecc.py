from sha512 import *
# from aes import *
from curves import *
from ecc import *

# TODO: test ecc.field_e_to_int function using non-prime fields
# TODO: have hash function where it can be anything and not just sha512
# TODO: make ECDSA implementation compatible with non-prime galois field

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

if a_shared_sec == b_shared_sec:
    print("same secret key")

ecdsa = Ecdsa(curve)

# generate Alice's signature with ECDSA
signature = ecdsa.gen_signature("abc", alice.pri_k)

# let Bob verify Alice's signature
verify_sign = ecdsa.verify_signature(signature, ecdsa.m_hash,
                                     alice.pub_k)
# print("signature gen: ", signature)
print("signature sign:", verify_sign)
