import multiprocessing
import socket
import time
import threading
import os
import random
import hashlib
import rsa
import base64
import jpysocket
from OpenSSL import crypto,SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from Crypto.Signature import PKCS1_v1_5
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Random import get_random_bytes
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#KEY with FERNET
masterkey64 =b'HEaV63ebUEAjib07VBqK3/HRq0q/u4y1mLNULYzZgI0='

masterkey64 =b'HEaV63ebUEAjib07VBqK3/HRq0q/u4y1mLNULYzZgI0='
masterkey=base64.b64decode(masterkey64)


salt=get_random_bytes(16)
print("salt: "+str(base64.b64encode(salt)));

salut="stockholm+2h+kth+02-05june"
salut=salut.encode();
print("salt: "+str(base64.b64encode(salut)));

keys=PBKDF2(masterkey64,salut,64,count=1000)
key1=keys[:32]
print(str(key1))
key = base64.b64encode(key1)
print(str((key))+"\n\n")

print("OKKK LETS GOOOOO\n")


dataclear = b"the secret message"
aad = b"ProtocolVersion1"
ciphered64="iHGkeFru6J4UkCzyyIkBf74C5rluCJlI3MrrWdUoaLJto+ImhJq51xoaST8c2g=="
ciphered64="5H6oAxCB82ywSpwx8fUl1n3EQ73F38lMU3bHBTTmceFJaqI6W+0t6mW1cKsAtw=="
ciphered=base64.b64decode(ciphered64)
nonce=ciphered[0:12]
print("nonce is:"+str(base64.b64encode(nonce)))
data=ciphered[12:]
print("data is:"+str(base64.b64encode(data)))
aesgcm = AESGCM(masterkey)
#nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, dataclear, aad)
print("ct:"+str(ct))
print("ENCRYPTION IS: "+str(base64.b64encode(nonce+ct)))
#adecrypt64="AWHWrFT5W8e9Wky+AJHBHucx22QicQurBykS4Mn6OcrD7OPlOUsoqJLa3EXDafpdYw=="
#adecrypt=base64.b64decode(adecrypt64)
res=aesgcm.decrypt(nonce, data, aad)
print(res)

#HMAC VALUE WITH STRING NOT BYTES !
#masterkey = base64.b64decode(masterkey64)
#my="test"
#my=my.encode()
#h = hmac.new( masterkey, my, hashlib.sha256 )
#print(h.hexdigest())


#print(masterkey)
#cipher = Cipher(algorithms.AES(masterkey), modes.ECB())
#encryptor = cipher.encryptor()

#str2hash_encrypted = encryptor.update(str2hash.encode())
#str2hash_encrypted64=base64.b64encode(str2hash_encrypted)
#print(str2hash_encrypted64)
