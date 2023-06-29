from charm.toolbox.integergroup import IntegerGroup
from charm.schemes.pkenc.pkenc_rsa import RSA_Enc, RSA_Sig
from charm.core.math.integer import integer,randomBits,random,randomPrime,isPrime,encode,decode,hashInt,bitsize,legendre,gcd,lcm,serialize,deserialize,int2Bytes,toInt

class Param():
    def __init__(self):
        pass
    def setParam(self,N2,N,g,k):
        self.N2 = N2
        self.N = N
        self.g = g
        self.k = k
class BCP():
    def __init__(self,secparam=1024,param = None):
            # 安全参数secparam被设置为1024，即默认的位长度是1024
            # 可以指定参数
            if param:
                self.N2 = param.N2
                self.N = param.N
                self.g = param.g
                self.k = param.k   
            # 如果未指定参数         
            else:
                # p,q用randomPrime()函数生成，位长度是512位（N=pq,要求N是1024位，则p,q为512位）
                # 第二个参数设置为True，表示是安全素数，即可以保证(p-1)/2和(q-1)/2也是素数
                self.p, self.q = randomPrime(int(secparam/2),True), randomPrime(int(secparam/2),True) 
                # pp，qq对应p',q'
                self.pp = (self.p -1)/2
                self.qq = (self.q - 1)/2
                # N = pq
                self.N = self.p * self.q
                # 下面这段while逻辑，是要找一个好的N
                while True: 
                    if bitsize(self.N) ==secparam and len(int2Bytes(self.N)) == int(secparam/8) and int2Bytes(self.N)[0] &128 !=0:
                        break
                    self.p, self.q = randomPrime(int(secparam/2),True), randomPrime(int(secparam/2),True) 
                    self.pp = (self.p -1)/2
                    self.qq = (self.q - 1)/2
                    self.N = self.p * self.q
                self.N2 = self.N**2
                self.g = random(self.N2)
                one = integer(1)% self.N2
                # 下面这段逻辑，是找到一个好的g
                while True: 
                    # 经过下面两步，保证g足够随机
                    self.g = random(self.N2)
                    self.g = integer((int(self.g)-1)*(int(self.g)-1))% self.N2
                    # 保证g的阶不是0
                    if self.g == one:
                        continue
                    # 保证g的阶不是p
                    tmp = self.g**self.p %self.N2
                    if tmp == one:
                        continue
                    # 保证g的阶不是p'
                    tmp = self.g**self.pp % self.N2
                    if tmp == one:
                        continue
                    # 保证g的阶不是q
                    tmp = self.g**self.q %self.N2
                    if tmp == one:
                        continue
                    # 保证g的阶不是q'
                    tmp = self.g**self.qq %self.N2
                    if tmp == one:
                        continue
                    # 保证g的阶不是pp'
                    tmp =self.g**(self.p*self.pp) % self.N2
                    if tmp == one:
                        continue 
                    # 保证g的阶不是pq
                    tmp = self.g**(self.p*self.q) %self. N2
                    if tmp== one:
                        continue 
                    # 保证g的阶不是pq'
                    tmp = self.g**(self.p*self.qq) % self.N2
                    if tmp == one:
                        continue 
                    # 保证g的阶不是p'q
                    tmp = self.g**(self.pp*self.q) % self.N2
                    if tmp == one:
                        continue 
                    # 保证g的阶不是p'q'
                    tmp = self.g**(self.pp*self.qq) % self.N2
                    if tmp == one:
                        continue 
                    # 保证g的阶不是qq'
                    tmp = self.g**(self.q*self.qq) % self.N2
                    if tmp == one:
                        continue
                    # 保证g的阶不是pp'q
                    tmp = self.g**(self.p*self.pp*self.q) % self.N2
                    if tmp == one:
                        continue   
                    # 保证g的阶不是pp'q'
                    tmp =self.g**(self.p*self.pp*self.qq) % self.N2
                    if tmp == one:
                        continue
                    # 保证g的阶不是pqq'
                    tmp =self.g**(self.p*self.q*self.qq) % self.N2
                    if tmp == one:
                        continue
                    # 保证g的阶不是p'qq'
                    tmp =self.g**(self.pp*self.q*self.qq) % self.N2
                    if tmp == one:
                        continue  
                    break 
                # 求得k
                self.k = integer((int(self.g**(self.pp*self.qq)) - 1)) / self.N % self.N
                # 获得主密钥
                self.MK ={"pp":self.pp,"qq":self.qq}

    def KeyGen(self):
        tmp = self.N2 /2
        sk = random(tmp) % self.N2
        pk = (self.g**sk) % self.N2
        return pk,sk

    def Encrypt(self,pk,plaintext):
            r = random(self.N/4) % self.N2
            A = (self.g** r ) % self.N2 
            B1 = (self.N*plaintext+1)% (self.N2)
            B2 = (pk**r) % (self.N2)
            B = B1*B2 % self.N2
            ciphertext = {"A":A,"B":B}
            return ciphertext

    def Decrypt(self,ciphertext,sk):
        t1 = integer(int(ciphertext['B']*((ciphertext['A']**-1)**sk)) -1) % self.N2
        m = integer(t1) / self.N
        return m

    def DecryptMK(self,ciphertext,MK,pk):
            k_1 = self.k ** -1
            tmp = (int(pk**(MK['pp']*MK['qq'])) -1) % self.N2
            tmp = integer(tmp) /self.N 
            a = tmp * integer(k_1) % self.N
            
            tmp = (int(ciphertext['A'] **(MK['pp']*MK['qq'])) -1) % self.N2
            tmp = integer(tmp) /self.N 
            r = tmp * integer(k_1) % self.N
            
            gama = a*r %self.N
            sig = ((MK['pp']*MK['qq'])%self.N) **-1
            
            tmp = (self.g **-1)**gama
            tmp = ciphertext['B'] *tmp    
            tmp = (int(tmp**(MK['pp']*MK['qq'])) -1)% self.N2
            tmp = integer(tmp) /self.N
            
            m = integer(tmp) * integer(sig) %self.N
            return integer(m) 


    def multiply(self,ciphertext1,ciphertext2):
        ciphertext={}
        ciphertext['A'] = ciphertext1['A'] * ciphertext2['A']
        ciphertext['B'] = ciphertext1['B'] * ciphertext2['B'] 
        return ciphertext

    def exponentiate(self,ciphertext,m):
        text={}    
        text['A'] = ciphertext['A'] **m % self.N2
        text['B'] = ciphertext['B'] **m % self.N2
        return text  