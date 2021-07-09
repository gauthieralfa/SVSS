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
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet

def generate_keys(name):
    key=crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    #USE FOR SIGNATURE WITH PYTHON
    file1 = open("all_keys/priv_"+name+".pem", 'wb')
    file1.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
    file1.close()

    #NEVER USE (Certificate in Python, and DER file in JAVA)
    file2 = open("all_keys/pub_"+name+".pem", 'wb')
    file2.write(crypto.dump_publickey(crypto.FILETYPE_PEM,key))
    file2.close()

#   USE FOR DECRYPT WITH PYTHON
    file3 = open("all_keys/priv_"+name+".txt", 'wb')
    file3.write(crypto.dump_privatekey(crypto.FILETYPE_ASN1,key))
    file1.close()
    #PKCS-Format

    #CONVERSION FOR JAVA of the private key PEM to DER PKCS8
    os.system("openssl pkcs8 -topk8 -inform PEM -outform DER -in all_keys/priv_"+name+".pem -out all_keys/priv_"+name+".der  -nocrypt")

    #CONVERSION TO PKCS1 for Python (Encryption)
    os.system("openssl rsa -in all_keys/priv_"+name+".pem -out all_keys/priv_"+name+"PKCS1.pem")

    #CONVERSION FOR JAVA of the public key PEM to DER
    os.system("openssl rsa -in all_keys/priv_"+name+".pem -pubout -outform DER -out all_keys/pub_"+name+".der")

    #CONVERSION TO PKCS1 for Python (not used)
    os.system("openssl rsa -pubin -in all_keys/pub_"+name+".pem -RSAPublicKey_out -out all_keys/pub_"+name+"PKCS1.pem")
    return key

def create_certificate(key,name):
    #CERTIFICATE USED FOR Encryption and signature verification in PYTHON. Not used in JAVA
    cert=crypto.X509()
    cert.set_pubkey(key)
    cert.get_subject().ST = "Sweden"
    cert.get_subject().L = "Stockholm"
    cert.get_subject().O = "Service Provider"
    cert.get_subject().OU = "SharingCar"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.get_subject().CN = "test"
    cert.sign(key,"sha256")
    file1=open("all_keys/cert_"+name,'wb')
    file1.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    file1.close()
    return cert

def get_certificate():
    file= open("all_keys/cert_sp", "r")
    certificate_str = file.read()
    file.close()
    certificate=crypto.load_certificate(crypto.FILETYPE_PEM,certificate_str)
    return certificate

def sign(message,key):
    signature=crypto.sign(key,message,"sha256")
    return signature

def verifsign(certificate,signature,data):
    verif=crypto.verify(certificate,signature,data,"sha256")
    return verif

def encrypt(certificat,message):
    pub = crypto.dump_publickey(crypto.FILETYPE_PEM, certificat.get_pubkey())
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pub)
    data = rsa.encrypt(message.encode(), pubkey)
    data = base64.b64encode(data)
    return data

def decrypt(prikey,message):
    #pri = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)
    #prikey = rsa.PrivateKey.load_pkcs1(key, 'DER')
    data = rsa.decrypt(base64.b64decode(message), prikey)
    return data


def recup_keys():
    #key=crypto.PKey()
    #key.generate_key(crypto.TYPE_RSA, 2048)
    file1 = open("all_keys/priv_spPKCS1.pem")
    priv_key=file1.read()
    private_key=rsa.PrivateKey.load_pkcs1(priv_key,'PEM')
    file1.close()

    file2 = open("all_keys/pub_spPKCS1.pem")
    pub_key=file2.read()
    public_key=rsa.PublicKey.load_pkcs1(pub_key)
    file2.close()

    file3 = open("all_keys/priv_sp.txt","rb")
    priv_key=file3.read()
    private_key=rsa.PrivateKey.load_pkcs1(priv_key,'DER')
    file3.close()
    return private_key,public_key


##SERVICE Provider
#key_SP=generate_keys("sp");
#create_certificate(key_SP,"sp");

##CUSTOMER
#key_Customer=generate_keys("customer");
#create_certificate(key_Customer,"customer");

##Owner
key_owner=generate_keys("owner")
create_certificate(key_owner,"owner")

##car
key_car=generate_keys("car")
create_certificate(key_car,"car")


message="the answer to life the universe and everything"
certificatSP=get_certificate();
encrypted=encrypt(certificatSP,message);
print(encrypted);
private_key,public_key=recup_keys();
decrypted=decrypt(private_key,encrypted);
print(decrypted.decode());
