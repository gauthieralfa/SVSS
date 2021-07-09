import random
import socket
import base64
import rsa
import sys
import threading
import time
import hashlib
import os
import hmac
from OpenSSL import crypto,SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from pbkdf2 import PBKDF2
from Crypto.Hash import SHA512

Nonce=os.urandom(8)
BD="test"
key_file=open("car1/keycar1.txt",'r')
key_car=key_file.read()
key_file.close()
f = Fernet(key_car)
AT=f.encrypt(BD.encode())
print("Access Token: "+str(AT))
session_key=Fernet.generate_key()
#print("keycar: "+str(key_car.encode())

key = PBKDF2(str(key_car), Nonce).read(32) # 256-bit key
print("Session Key created: "+str(key))
print("Session Key created: "+str())
