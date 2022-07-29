"""
*   Author: Taha Canturk
*   Github: Kibnakamoto
*  Repisotory: ECC
* Start Date: July 21, 2022
* Finalized:  July 22, 2022 
"""

import secrets # for optional key generation for encryption
import numpy as np

class Aes:
    def __init__(self, Nb: int, Nk: int, Nr: int):
        self.Nb = Nb
        self.Nk = Nk
        self.Nr = Nr
        
        # Rijndael's S-box as a 2-dimentional matrix
        self.sbox = (
            (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 
             0x2B, 0xFE, 0xD7, 0xAB, 0x76), (0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59,
             0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0), (0xB7,
             0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 
             0x71, 0xD8, 0x31, 0x15), (0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05,
             0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75), (0x09, 0x83,
             0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29,
             0xE3, 0x2F, 0x84), (0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
             0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF), (0xD0, 0xEF, 0xAA,
             0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
             0x9F, 0xA8), (0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC,
             0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2), (0xCD, 0x0C, 0x13, 0xEC,
             0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
             0x73), (0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,
             0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB), (0xE0, 0x32, 0x3A, 0x0A, 0x49,
             0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79),
            (0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4,
             0xEA, 0x65, 0x7A, 0xAE, 0x08), (0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
             0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A), (0x70,
             0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
             0x86, 0xC1, 0x1D, 0x9E), (0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E,
             0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF), (0x8C, 0xA1,
             0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 
             0x54, 0xBB, 0x16));
                
        # Rijndael's inverse S-box as a 2-dimentional matrix
        self.inv_sbox = (
            (0x52, 0x9, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
             0x9e, 0x81, 0xf3, 0xd7, 0xfb), (0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
             0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb), (0x54,
             0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0xb,
             0x42, 0xfa, 0xc3, 0x4e), (0x8, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
             0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25), (0x72, 0xf8,
             0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
             0x65, 0xb6, 0x92), (0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
             0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84), (0x90, 0xd8, 0xab,
             0x0, 0x8c, 0xbc, 0xd3, 0xa, 0xf7, 0xe4, 0x58, 0x5, 0xb8, 0xb3, 0x45,
             0x6), (0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0xf, 0x2, 0xc1, 0xaf, 
             0xbd, 0x3, 0x1, 0x13, 0x8a, 0x6b), (0x3a, 0x91, 0x11, 0x41, 0x4f,
             0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73),
            (0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37,
             0xe8, 0x1c, 0x75, 0xdf, 0x6e), (0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29,
             0xc5, 0x89, 0x6f, 0xb7, 0x62, 0xe, 0xaa, 0x18, 0xbe, 0x1b), (0xfc,
             0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe,
             0x78, 0xcd, 0x5a, 0xf4), (0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x7, 0xc7,
             0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f), (0x60, 0x51,
             0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0xd, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 
             0xc9, 0x9c, 0xef), (0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
             0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61), (0x17, 0x2b, 0x4,
             0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21,
             0xc, 0x7d));
            
        # round constant array
        self.rcon = (0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
                     0x40, 0x80, 0x1b, 0x36)
    # Operations
    # galois field 2**8 multipication
    def gf256(self,x,y):
        p=0
        for i in range(8):
            p ^= ((y&1)&1)
            x = (x<<1) ^ (0x11b & -((x>>7)&1))
            y>>=1
        return p
    
    # bitwise circular-left-shift operator for rotating by 8 bits.
    def rotword(self,x):
        return (x<<8)|(x>>24)

    # Encryption Operations
    def subbytes(self):
        # seperates hex byte into 2 nibbles and use them as index to
        # sub in values as index of s-box
        for r in range(4):
            for c in range(self.Nb):
                bottom_mask = self.state[r][c] & 0x0f
                top_mask = self.state[r][c] >> 4
                self.state[r][c] = self.sbox[top_mask][bottom_mask]

    def shiftrows(self):
        # to stop values from overriding, use 2 arrays with the same values
        pre_state = self.state
        
        # ShiftRows operation. First row is not changed
        for r in range(1,4):
            for c in range(self.Nb):
                self.state[r][c] = pre_state[r][(r+c)%4];

    def mixcolumns(self):
        # xtime function from AES proposal
        xtime = lambda x : ((x<<1) ^ (((x>>7) & 1) * 0x1b))
        
        for c in range(self.Nb):
            # create temporary array to stop overriding
            tmp_s = [self.state[0][c], self.state[1][c],
                     self.state[2][c], self.state[3][c]]
            
            # mix columns operation
            tmp = (tmp_s[0] ^ tmp_s[1] ^ tmp_s[2] ^ tmp_s[3])
            tm =  (tmp_s[0] ^ tmp_s[1]) ; tm = xtime(tm)
            self.state[0][c] ^= (tm ^ tmp)
            tm =          (tmp_s[1] ^ tmp_s[2]) ; tm = xtime(tm)
            self.state[1][c] ^= (tm ^ tmp)
            tm =          (tmp_s[2] ^ tmp_s[3]) ; tm = xtime(tm)
            self.state[2][c] ^= (tm ^ tmp)
            tm =          (tmp_s[3] ^ tmp_s[0]) ; tm = xtime(tm)
            self.state[3][c] ^= (tm ^ tmp)
    
    def subword(self,x):
        sub_int = lambda y : self.sbox[(y&0xff)>>4][y&0x0f]
        return (sub_int(x>>24)<<24) | \
               (sub_int((x>>16)&0xff)<<16) | \
               (sub_int((x>>8)&0xff)<<8) | \
               (sub_int(x&0xff))
    
    def addroundkey(self,w,rnd):
        for c in range(self.Nb):
            w_index = w[rnd*4+c]
            self.state[0][c] ^= (w_index >> 24) & 0xff
            self.state[1][c] ^= (w_index >> 16) & 0xff
            self.state[2][c] ^= (w_index >> 8) & 0xff
            self.state[3][c] ^= w_index & 0xff
    
    # Decryption
    def inv_subbytes(self):
        for r in range(4):
            for c in range(self.Nb):
                bottom_mask = self.state[r][c] & 0x0f
                top_mask = self.state[r][c] >> 4
                self.state[r][c] = self.inv_sbox[top_mask][bottom_mask]
    
    def inv_shiftrows(self):
         # to stop values from overriding, duplicate matrix
        inv_pre_state = self.state
        for r in range(1,4):
            for c in range(self.Nb):
                self.state[r][(r+c)%4] = inv_pre_state[r][c]
    
    def inv_mixcolumns(self):
        s_mixarr = (0x0e, 0x0b, 0x0d, 0x09)
        for c in range(self.Nb):
            tmp_state = (self.state[0][c], self.state[1][c],
                         self.state[2][c], self.state[3][c])
            self.state[0][c] = (self.gf256(tmp_state[0],s_mixarr[0]) ^
                                self.gf256(tmp_state[1],s_mixarr[1]) ^
                                self.gf256(tmp_state[2],s_mixarr[2]) ^
                                self.gf256(tmp_state[3],s_mixarr[3]))
            self.state[1][c] = (self.gf256(tmp_state[0],s_mixarr[3]) ^
                                self.gf256(tmp_state[1],s_mixarr[0]) ^
                                self.gf256(tmp_state[2],s_mixarr[1]) ^
                                self.gf256(tmp_state[3],s_mixarr[2]))
            self.state[2][c] = (self.gf256(tmp_state[0],s_mixarr[2]) ^
                                self.gf256(tmp_state[1],s_mixarr[3]) ^
                                self.gf256(tmp_state[2],s_mixarr[0]) ^
                                self.gf256(tmp_state[3],s_mixarr[1]))
            self.state[3][c] = (self.gf256(tmp_state[0],s_mixarr[1]) ^
                                self.gf256(tmp_state[1],s_mixarr[2]) ^ 
                                self.gf256(tmp_state[2],s_mixarr[3]) ^
                                self.gf256(tmp_state[3],s_mixarr[0]))
    
    def key_expansion(self,key,w):
        i = 0
        while i < self.Nk:
            w[i] = ((key[4*i]<<24) | (key[4*i+1]<<16) | \
                   (key[4*i+2]<<8) | key[4*i+3]) & 0xffffffff
            i+=1
        i=self.Nk
        
        # rcon values as 32 bit
        tmp_rcon = []
        for j in range(1,11):
            tmp_rcon.append((self.rcon[j] & 0xff) << 24)
        
        while i<self.Nb*(self.Nr+1):
            temp = w[i-1]
            if i%self.Nk == 0:
                temp = self.subword(self.rotword(temp) ^
                                    tmp_rcon[i//self.Nk])
            elif self.Nk>6 and i%self.Nk == 4:
                temp = self.subword(temp)
            w[i] = temp ^ w[i-self.Nk]
            i+=1
            
    def cipher(self,inp,out,w):
        if len(inp)%16 != 0:
            inp = inp.zfill(16)
        self.state = np.eye(4,self.Nb,dtype=np.uint8)
        
        # message to 2-d state matrix
        for r in range(4):
            for c in range(self.Nb):
                self.state[r][c] = ord(inp[r+4*c])
        
        # call functions to manipulate state matrix
        self.addroundkey(w, 0);
        for rnd in range(1,self.Nk):
            self.subbytes();
            self.shiftrows();
            self.mixcolumns();
            self.addroundkey(w, rnd);
        
        self.subbytes();
        self.shiftrows();
        self.addroundkey(w, self.Nr);
        
        # copy state matrix to output
        for r in range(4):
            for c in range(self.Nb):
                out[r+c*4] = self.state[r][c]
    
    def inv_cipher(self,inp,out,w):
        self.state = np.eye(4,self.Nb,dtype=np.uint8)
        
        # message to 2-d state matrix
        for r in range(4):
            for c in range(self.Nb):
                self.state[r][c] = inp[r+4*c]
        
        self.addroundkey(w, self.Nr);
        for rnd in range(self.Nr-1,0,-1):
            self.inv_shiftrows();
            self.inv_subbytes();
            self.addroundkey(w, rnd);
            self.inv_mixcolumns();
        self.inv_shiftrows();
        self.inv_subbytes();
        self.addroundkey(w, 0);
        
        # 2-d matrix to 1d output
        for r in range(4):
            for c in range(self.Nb):
                out[r+4*c] = self.state[r][c]
    
    def encrypt(self,inp,key):
        out = [0]*(4*self.Nb)
        w = [0]*(self.Nb*(self.Nr+1))
        str_out = ""
        
        # call key_expansion and cipher function
        self.key_expansion(key,w)
        self.cipher(inp,out,w)
        
        # output to hex string
        for i in range(4*self.Nb):
            str_out+=hex(out[i])[2:].zfill(2)
        
        return str_out
    
    def decrypt(self,inp,key):
        out = [0]*(4*self.Nb)
        w = [0]*(self.Nb*(self.Nr+1))
        inp = bytearray.fromhex(inp) # hex string to byte array
        
        # create key schedule and decrypt
        self.key_expansion(key, w);
        self.inv_cipher(inp, out, w);
        string = ""
        for i in out:
            string+=str(i)
        
        return string
    
    def multi_block_process_enc(self,inp,key, add_del):        
        # seperate input into 16-byte substrings
        if(len(inp) != 4*self.Nb):
            substr =  [inp[i:i+16] for i in range(0, len(inp), 16)]
            
            # add string delimeter so that in decryption, padding is deleted
            length_substr = len(substr[len(substr)-1])
            if add_del != None:
                if len(substr[len(substr)-1]) != 16:
                    substr[len(substr)-1]+='1'
                else:
                    # if length is 16, add to another index of substr
                    substr.append('1')
            substr[len(substr)-1] = substr[len(substr)-1].ljust(16,'0')
        else:
            substr = inp
        
        final_ct = ""
        for i in substr:
            final_ct+=self.encrypt(i,key)
        return final_ct
    
    def multi_block_process_dec(self,inp,key, rm_del):
        # make the string delimeter optional with input
        # remove string delimeter
        if len(inp)%32 != 0:
            raise Exception("input length has to be a multiple of 32 bytes")
        
        # seperate message into blocks of 32 hex digits
        substr =  [inp[i:i+32] for i in range(0, len(inp), 32)]
        final_val = ""
        for i in range(len(substr)):
            final_val+=self.decrypt(substr[i],key)
        
        # remove final delimeter '1'
        if rm_del != None:
            final_val = final_val.rsplit('1', 1)[0]
        
        return final_val
    
class Aes256:
    def __init__(self):
        self.Nb = 4
        self.Nk = 8
        self.Nr = 14
        self.key = None
        
    def encrypt(self,inp,key=None, delm=None):
        # generate key if key is None
        if key == None:
            self.key = secrets.token_bytes(32)
        aes = Aes(self.Nb,self.Nk,self.Nr)
        return aes.multi_block_process_enc(inp,self.key,delm)
    
    def decrypt(self,inp,key=None,delm=None):
        # check if key exists if no keys are provided as parameter
        if key == None:
            assert self.key != None, "key not provided"
        else:
            self.key = key
        aes = Aes(self.Nb,self.Nk,self.Nr)
        return aes.multi_block_process_dec(inp,self.key,delm)

class Aes192:
    def __init__(self):
        self.Nb = 4
        self.Nk = 6
        self.Nr = 12
        self.key = None
    
    def encrypt(self,inp,key=None, delm=None):
        # generate key if key is None
        if key == None:
            self.key = secrets.token_bytes(24)
        aes = Aes(self.Nb,self.Nk,self.Nr)
        return aes.multi_block_process_enc(inp,self.key,delm)
    
    def decrypt(self,inp,key=None,delm=None):
        # check if key exists if no keys are provided as parameter
        if key == None:
            assert self.key != None, "key not provided"
        else:
            self.key = key
        aes = Aes(self.Nb,self.Nk,self.Nr)
        return aes.multi_block_process_dec(inp,self.key,delm)

class Aes128:
    def __init__(self):
        self.Nb = 4
        self.Nk = 4
        self.Nr = 10
        self.key = None
    
    def encrypt(self,inp,key=None, delm=None):
        # generate key if key is None
        if key == None:
            self.key = secrets.token_bytes(16)
        aes = Aes(self.Nb,self.Nk,self.Nr)
        return aes.multi_block_process_enc(inp,self.key,delm)
    
    def decrypt(self,inp,key=None,delm=None):
        # check if key exists if no keys are provided as parameter
        if key == None:
            assert self.key != None, "key not provided"
        else:
            self.key = key
        aes = Aes(self.Nb,self.Nk,self.Nr)
        return aes.multi_block_process_dec(inp,self.key,delm)

aes256 = Aes256()
cipher = aes256.encrypt("test",None,True)
print(cipher)
print(aes256.decrypt(cipher,aes256.key,True))