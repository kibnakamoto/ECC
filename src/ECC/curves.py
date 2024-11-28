import secrets
import math

# implementation of public key generation of weierstrass curves over GF(p)

def gen_key(n):
    key = 0
    while(key == 0):
        key = secrets.randbelow(n)
    return key

def point_add(xp, yp, xq, yq, p, a):
        # equation for private key and pointG
        # find lambda
        if yp == yq or xp == xq:
            __lambda = ((3*(xp**2) + a)*pow(2*yp, -1, 
                                                 p)) % p
        else:
            __lambda = ((yq-yp)*pow(xq-xp, -1, p)) % p
        xr = (__lambda**2 - xp - xq) % p
        yr = (__lambda*(xp-xr) - yp) % p
        return (xr%p, yr%p)

def point_double(x, y, p, a):
    __lambda = ((3*(x**2) + a)*pow(2*y, -1, p)) % p
    xr = __lambda**2 - 2*x
    
    # use ys's negative values
    yr = __lambda*(x - xr) - y
    return (xr%p, yr%p)


def montgomery_ladder(pointG,prikey, p, a):
    r0 = list(pointG)
    r1 = point_double(r0[0],r0[1],p,a)
    bits = bin(prikey)[3:]
    for i in bits:
        if i == '0':
            r1 = point_add(r0[0],r0[1],r1[0],
                                       r1[1],p,a)
            r0 = point_double(r0[0],r0[1],p,a)
        else:
            r0 = point_add(r0[0],r0[1],r1[0],
                           r1[1],p,a)
            r1 = point_double(r1[0],r1[1],p,a)
    return (r0[0],r0[1])


class Weierstrass:
    # x and y coordinates of points should satisfy the following equation:
    # y2 = x3 + Ax + B (mod p)
    """ default class initializer """
    def __init__(self, p: int, a: int, b: int):
        self.p = p
        self.a = a
        self.b = b
    
    def multiply(self,pointG: tuple, prikey: int):
        self.pointG = pointG
        self.prikey = prikey
        
        if prikey == 0:
            return math.inf
        
        if (pointG[1]**2)%self.p == (pointG[0]**3 + 
                                     self.a*pointG[0] + 
                                     self.b) % self.p:
            return montgomery_ladder(self.pointG, self.prikey, self.p, 
                                     self.a)
        else:
            raise Exception("parameters do not satisfy equation")        

class Secp521r1:
    def __init__(self):
        self.p = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        self.h = 0x01
        self.n = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
        self.tr = 0x5ae79787c40d069948033feb708f65a2fc44a36477663b851449048e16ec79bf7
        self.a = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
        self.b = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
        self.G = (0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
                  0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)
        self.c = 0x0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637
        self.seed = 0xd09e8800291cb85396cc6717393284aaa0da64ba

class Secp384r1:
    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
        self.a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC
        self.b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
        self.G = (0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
                  0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F)
        self.h = 0x01

class Secp256r1:
    def __init__(self):
        self.p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        self.n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        self.a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
        self.b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
        self.G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                  0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

        self.h = 0x01

class Secp256k1:
    def __init__(self):
        self.p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
        self.n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        self.a = 0x0000000000000000000000000000000000000000000000000000000000000000
        self.b = 0x0000000000000000000000000000000000000000000000000000000000000007
        self.G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
        self.h = 0x01

class Secp224r1:
    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
        self.a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
        self.b = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
        self.G = (0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
                  0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34)
        self.h = 0x01

class Secp224k1:
    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D
        self.n = 0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7
        self.a = 0x00000000000000000000000000000000000000000000000000000000
        self.b = 0x00000000000000000000000000000000000000000000000000000005
        self.G = (0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C,
                  0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5)
        self.h = 0x01

class Secp192r1:
    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
        self.a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
        self.b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
        self.G = (0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012, 
                  0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811)
        self.h = 0x01

class Secp192k1:
    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D
        self.a = 0x000000000000000000000000000000000000000000000000
        self.b = 0x000000000000000000000000000000000000000000000003
        self.G = (0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D,
                  0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D)
        self.h = 0x01


# random brainpool curves
class Brainpoolp224r1:
    def __init__(self):
       self.p = 0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF
       self.a = 0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43
       self.b = 0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B
       self.G = (0x0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D,
                 0x58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD)
       self.n = 0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F
       self.h = 0x01

class Brainpoolp256r1:
    def __init__(self):
        self.p = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
        self.a = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
        self.b = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
        self.G = (0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262,
                  0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997)
        self.n = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
        self.h = 0x01

class Brainpoolp320r1:
    def __init__(self):
        self.p = 0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27
        self.a = 0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4
        self.b = 0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6
        self.G = (0x43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611, 
                  0x14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1)
        self.n = 0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311
        self.h = 0x01

class Brainpoolp384r1:
    def __init__(self):
        self.p = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53
        self.a = 0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826
        self.b = 0x04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11
        self.G = (0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E,
                  0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315)
        self.n = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565
        self.h = 0x01


class Brainpoolp512r1:
    def __init__(self):
        self.p = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3
        self.a = 0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA
        self.b = 0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723
        self.G = (0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822,
                 0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892)
        self.n = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069
        self.h = 0x01


class Curve:
    def __init__(self,curve=Secp521r1):
        self.curve = curve

    def get_prikey(self, pri_k=0):
        # numbers from 1 to n-1. But 1 is not given as the starting range
        if(pri_k == 0):
            self.pri_k = gen_key(self.curve.n)
        else:
            self.pri_k = pri_k
    
    def get_pubkey(self, pri_k=None):
        if not pri_k == None:
            self.pri_k = pri_k
        
        weierstrass = Weierstrass(self.curve.p,self.curve.a,
                                  self.curve.b)
        self.pub_k = weierstrass.multiply(self.curve.G, self.pri_k)
