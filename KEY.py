#coding: utf8
import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from binascii import b2a_hex,a2b_hex
import random

'''
生成TGS的session key, 需要访问服务的session key , TGS的secret key 和 服务的secret key
这里是模拟kerberos秘钥和加密，使用的是AES对称加密算法

'''
class aescrypt():
    def __init__(self,key):
        key_length = 16
        key_count = len(key)
        if (key_count % key_length !=0):
            a = key_length - (key_count % key_length)
        else:
            a = 0
        key = key + ('\0' * a)
        self.key = key 
        self.mode = AES.MODE_CBC 

    def encrypt(self,text):
        length = 16
        cryptor = AES.new(self.key,self.mode,self.key)
        count = len(text)
        if(count%length !=0):
            add = length -(count % length)
        else:
            add = 0
        text = text + ('\0' * add) #AES加密明文，明文字节长度必须要为16字节的整数倍，如果不是16字节的整数倍，需要用空格填充
        self.ciphertext = cryptor.encrypt(text)
        return b2a_hex(self.ciphertext)
    
    def decrypt(self,text):
        cryptor = AES.new(self.key,self.mode,self.key)
        plain_text = cryptor.decrypt(a2b_hex(text)) 
        return plain_text.rstrip('\0')


def User_masterkey(password):
    sha = SHA256.new()
    sha.update(password)
    return sha.hexdigest()[0:16]


def TGS_sessionkey():
    sha = SHA256.new()
    sha.update(str(random.random()))
    return sha.hexdigest()[0:16]


def getservice_secret_key(service_name):
    sha =SHA256.new()
    sha.update(service_name)
    return sha.hexdigest()[0:16]


#if __name__=='__main__':
#    aes = aescrypt('password')
#    e = aes.encrypt('guowei')
#    d = aes.decrypt(e)
#    print(e)
#    print(d)
