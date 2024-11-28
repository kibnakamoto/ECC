# right-rotate
rr = lambda x,n : ((x >> n)|(x << 64-n)) & 0xffffffffffffffff

class Sha512:
    def __init__(self,inp):
        self.K = (
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
            0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
            0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 
            0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
            0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
            0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
            0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
            0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
            0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
            0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
            0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec, 0x6c44198c4a475817)
        
        # initialize hash values
        self.H = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
        
        if isinstance(inp,int):
            inp = str(inp)
        elif isinstance(inp,bytes):
            inp = inp.decode('utf-8')
        
        length = len(inp)
        bitlen = length<<3
        padding = ((1024-(bitlen+1)-128) % 1024)-7
        padding//=8
        block_bytes_len = padding+length+17
        w = []
        for i in range(0,block_bytes_len//8):
            w.append(0)
        if type(inp) == type(""):
            byte_arr = bytearray(inp.encode('charmap'))
        else:
            byte_arr = inp
        byte_arr.append(0x80) # append 1
        
        # padding
        for i in range(0,padding):
            byte_arr.append(0x00);
        
        for i in range(0,length//8+1):
            w[i] = byte_arr[i*8]<<56;
            for j in range(1,7):
                w[i] = w[i]|( byte_arr[i*8+j]<<(7-j)*8)
            w[i] = w[i]|( byte_arr[i*8+7] )
        
        # append length as 128-bit to word
        if bitlen < 0xffffffffffffffff:
            w[len(w)-2] = 0x0000000000000000
            w[len(w)-1] = bitlen
        else:
            w[len(w)-2] = (bitlen >> 64) & 0xffffffffffffffff
            w[len(w)-1] = bitlen & 0xffffffffffffffff
        
        tmp = [0]*80
        for i in range(0,block_bytes_len//128):
            for j in range(0,16):
                tmp[j] = w[j+16*i]
            self.transform(tmp)
        
        self.ret = ""
        for i in range(0,8):
            self.ret += hex(self.H[i])[2:].zfill(16)

    # choice = (x ∧ y) ⊕ (¯x ∧ z)
    def ch(self,e, f, g):
        return ((e & f)^(~e & g))
    
    # majority = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
    def maj(self,a,b,c):
        return ((a & b)^(a & c)^(b & c))
    
    def transform(self,w):
        # a,b,c,d,e,f,g,h variables
        V = []
        for i in range(0,8):
            V.append(self.H[i])
        
        # pre-compression
        for i in range(16,80):
            sigma0 = rr(w[i-15],1) ^ rr(w[i-15],8) ^ (w[i-15] >> 7)
            sigma1 = rr(w[i-2],19) ^ rr(w[i-2], 61) ^ (w[i-2] >> 6)
            w[i] = (w[i-16] + sigma0 + w[i-7] + sigma1) & \
                   0xffffffffffffffff
        
        for i in range(0,80):
            sum0 = rr(V[0],28) ^ rr(V[0],34) ^ rr(V[0],39)
            t2 = (sum0 + self.maj(V[0],V[1],V[2])) & \
                 0xffffffffffffffff
            sum1 = rr(V[4],14) ^ rr(V[4],18) ^ rr(V[4],41)
            t1 = (V[7] + sum1 + self.ch(V[4],V[5],V[6]) + \
                  self.K[i] + w[i]) & 0xffffffffffffffff
            
            # modify hash values
            V[7] = V[6]
            V[6] = V[5]
            V[5] = V[4]
            V[4] = (V[3] + t1) & 0xffffffffffffffff
            V[3] = V[2]
            V[2] = V[1]
            V[1] = V[0]
            V[0] = (t1 + t2) & 0xffffffffffffffff
        
        for i in range(0,8):
            self.H[i] = (self.H[i] + V[i]) & 0xffffffffffffffff
        return self.H;
    
    def digest(self):
        return bytearray.fromhex(self.ret)
    
    def hexdigest(self):
        return self.ret
