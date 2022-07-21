import galois
from curves import *
from tinyec.ec import Curve, SubGroup

alice_secp521r1 = Secp521r1()
bob_secp521r1 = Secp521r1()
weierstrass = Weierstrass(bob_secp521r1.p,bob_secp521r1.a,
                          bob_secp521r1.b)

# generate private keys of both Alice and Bob
alice_secp521r1.get_privkey(5848086670634336295179241537947744107056560678941168314791178081878633088455617469991013034321652554105110886298371233598544051928031241656197349434021052)
bob_secp521r1.get_privkey(65215690354676615037081482303758947066186667230878659726538709580154848544607330564152279281874441250878379865736772667630609470695976953483213929929888987)

# generate public keys of both Alice and Bob
alice_secp521r1.get_pubkey()
bob_secp521r1.get_pubkey()

print("Alice\'s private key:\t", alice_secp521r1.pri_k)
print("Bobs\'s private key:\t", bob_secp521r1.pri_k)

print("Alice\'s public key:\t", alice_secp521r1.pub_k)
print("Bobs\'s public key:\t", bob_secp521r1.pub_k)

# get compressed points
alice_pubk_comp = '0' + str(2 + alice_secp521r1.pub_k[1] % 2) + \
                  str(hex(alice_secp521r1.pub_k[0])[2:])
bob_pubk_comp = '0' + str(2 + bob_secp521r1.pub_k[1] % 2) + \
                str(hex(bob_secp521r1.pub_k[0])[2:])

# calculate shared secret
# they are equal to each other
a_shared_sec = weierstrass.multiply(bob_secp521r1.pub_k,alice_secp521r1.pri_k)
b_shared_sec = weierstrass.multiply(alice_secp521r1.pub_k,bob_secp521r1.pri_k)
