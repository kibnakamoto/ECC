import secrets

# implementation of ECIAS and secp521r1

class Secp521r1:
    def __init__(self):
        self.p = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        self.h = 1
        self.n = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
        self.tr = 0x5ae79787c40d069948033feb708f65a2fc44a36477663b851449048e16ec79bf7
        self.a = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
        self.b = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
        self.G = (0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
                  0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)
        self.c = 0x0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637
        self.seed = 0xd09e8800291cb85396cc6717393284aaa0da64ba
        self.septuple = (self.p,self.a,self.b,self.G,self.n,self.h)
    
    def get_privkey(self, pri_k=0):
        # numbers from 1 to n-1. But 1 is not given as the starting range
        if(pri_k == 0):
            self.pri_k = secrets.randbelow(n-1)
        else:
            self.pri_k = pri_k
    
    def get_pubkey(self):
        self.pub_k = self.pri_k*self.G
        self.keypair = (self.pri_k,self.pub_k)
    
    
