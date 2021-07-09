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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import hmac
import codecs
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '192.168.66.56'  # Standard loopback interface address (localhost)
PORT = 50002  # Port to listen on (non-privileged ports are > 1023)
server_reference_path = "car1/"
key = Fernet.generate_key()

masterkey = os.urandom(32)
file=open(server_reference_path+"keycar1.txt",'wb')
file.write(key)
file.close()
file=open(server_reference_path+"masterkeycar1.txt",'wb')
file.write(masterkey)
file.close()
IdCar="206"

def generate_keys():
    key=crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    file1 = open("car1/priv_s.txt", 'wb')
    file1.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
    file1.close()
    file2 = open("car1/pub_s.txt", 'wb')
    file2.write(crypto.dump_publickey(crypto.FILETYPE_PEM,key))
    file2.close()
    return key

def create_certificate(key):
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
    file1=open("certs/cert_s",'wb')
    file1.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    file1.close()
    return cert

def get_certificate(certif_file):
    file= open("certs/"+certif_file, "r")
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

def decrypt(key,message):
    pri = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)
    prikey = rsa.PrivateKey.load_pkcs1(pri, 'DER')
    data = rsa.decrypt(base64.b64decode(message), prikey)
    return data


def encrypt_aead(key,message,auth_data):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, message, auth_data)
    encrypted64=base64.b64encode(nonce+encrypted)
    return encrypted64

def decrypted_aead(key,ciphered,auth_data):
    nonce=nonce=ciphered[0:12]
    data_enc=data=ciphered[12:]
    aesgcm = AESGCM(key)
    decrypted=aesgcm.decrypt(nonce, data_enc, auth_data)
    return decrypted


class server(object):

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.hostname, self.port))
        self.socket.listen()
        print("Car ready at port 50001")
        while True:
            clientsocket, (ip,port) = self.socket.accept()
            newthread = ClientThread(ip ,port , clientsocket,self)
            newthread.start()


class ClientThread(threading.Thread):

    def __init__(self, ip, port, clientsocket,server):

        print("connection from",ip)
        self.ip = ip
        self.port = port
        self.clientsocket = clientsocket
        self.server = server
        threading.Thread.__init__(self)

    def close(self):

        self.clientsocket.close()
        print("Thread",threading.get_ident(),":connection from",self.ip,"ended\n")

    def receive2(self,m):
        size=self.clientsocket.recv(1024)
        self.clientsocket.send("OK".encode())
        print("Thread",threading.get_ident(),":receiving file:",m)
        recv=self.clientsocket.recv(1024*1024)
        while (len(recv)!=int(size)):
            recv+=self.clientsocket.recv(1024*1024)
        file = open(server_reference_path+"m",'wb')
        file.write(recv)
        file.close()
        print("Thread",threading.get_ident(),":file received")
        #self.close()
        #return m

    def receive(self):
        recv=self.clientsocket.recv(1024)
        #print("Thread",threading.get_ident(),":receiving file:",recv.decode())
        return recv

    def receive_byte(self):
        recv=self.clientsocket.recv(1024)
        #print("Thread",threading.get_ident(),":receiving file:",recv)
        return recv

    def send_text(self,datas):
        ##print("Thread",threading.get_ident(),":sending file:",datas)
        self.clientsocket.send(datas.encode())
        ##print("Thread",threading.get_ident(),":file sent")

    def send_text_java(self,datas):
        ##print("Thread",threading.get_ident(),":sending text java:",datas)
        msg=jpysocket.jpyencode(datas)
        self.clientsocket.sendall(msg)
        ##print("Thread",threading.get_ident(),":sending msg java:",msg)
        #self.close()

    def send_object(self,datas):
        ##print("Thread",threading.get_ident(),":sending object")
        self.clientsocket.sendall(datas)
        ##print("Thread",threading.get_ident(),":object sent")

    def session_key(self):
        AT_uc=self.receive_byte()
        print("AT_uc received")
        self.send_text("OK")
        AT_uc_auth_data=self.receive_byte()
        self.send_text("OK")

        ##print("AT uc is: "+AT_uc.decode())



        Kveh64 =b'HEaV63ebUEAjib07VBqK3/HRq0q/u4y1mLNULYzZgI0='
        Nauth=1000
        #Auth_uc="1\n2\n3\n"+str(Nauth)+"\n"+h_contract_uo+"\n";
        #Auth_uc_byte=Auth_uc.encode();

## SES KVEH Calculated
        keys=PBKDF2(Kveh64,AT_uc_auth_data,32,count=1000)
        Ses_Kveh=keys[:32]
        Ses_Kveh64 = base64.b64encode(Ses_Kveh)
        print("\nSes_Kveh is: "+str(Ses_Kveh64))


##AEAD AT_UC Checked
        AT_uc_dec=decrypted_aead(Ses_Kveh,AT_uc,AT_uc_auth_data)
        print("AT_uc_dec:"+AT_uc_dec.decode())
        BDucTScheck=(AT_uc_dec.decode()).splitlines()[2]+"\n"+(AT_uc_dec.decode()).splitlines()[3]+"\n"+(AT_uc_dec.decode()).splitlines()[4]+"\n"+(AT_uc_dec.decode()).splitlines()[5]+"\n"+(AT_uc_dec.decode()).splitlines()[6]

        print("BDucTScheck: "+BDucTScheck)
        CheckUo_rec=(AT_uc_dec.decode()).splitlines()[1]
        Ses_uc=(AT_uc_dec.decode()).splitlines()[0]
        print("\nCheckUO received is:"+CheckUo_rec)
        print("\nSes_uc received is:"+Ses_uc)

## SES Kuo Calculated
        K_uo64=b'HEaV63ebUEAjib07VBqK3/HRq0q/u4y1mLNULYzZgI0='
        keys=PBKDF2(K_uo64,BDucTScheck.encode(),32,count=1000)
        Ses_uo=keys[:32]
        Ses_uo64 = base64.b64encode(Ses_uo)
        print("Sesuo is: "+str(Ses_uo64.decode()))

        ##CHECKuo checked
        masterkey64 ="lbRLda4CmYbL47BNIsHwz2dMJ8j+MkRo+RBMr1L0LIU="
        masterkey = base64.b64decode(masterkey64)
        ##BDucTScheck="stockholm+2h+kth+02-05june".encode()
        CheckUo = hmac.new( Ses_uo, BDucTScheck.encode(), hashlib.sha256 )
        print(CheckUo.hexdigest())
        CheckUo64 = codecs.encode(codecs.decode(CheckUo.hexdigest(), 'hex'), 'base64').decode()
        print("\nCheckUo calculated is: "+CheckUo64)
        if (CheckUo64.rstrip()==CheckUo_rec):
            print("\n\n!!!CHECKUO OK!!!\n")

        ##Contract_uo saved
        Contract_uo=CheckUo.hexdigest()+BDucTScheck
        result=open(server_reference_path+"SES_uc.txt","w")
        result.write(Ses_uc)
        result.close()

        result=open(server_reference_path+"AT_uc.txt","wb")
        result.write(AT_uc)
        result.close()

        result=open(server_reference_path+"AT_uc_auth_data.txt","wb")
        result.write(AT_uc_auth_data)
        result.close()


    def open_the_car(self):
        result=open(server_reference_path+"SES_uc.txt","r")
        Ses_uc64=result.read()
        result.close()

        result=open(server_reference_path+"AT_uc.txt","rb")
        AT_uc=result.read()
        result.close()

        result=open(server_reference_path+"AT_uc_auth_data.txt","rb")
        AT_uc_auth_data=result.read()
        result.close()

        ##ses_uc64="ZXe9EvH+q1PnjpDhoaXCxkQph9RDOMhk4VJjuLw0M/A=".encode()
        ##ses_uc=base64.b64decode(ses_uc64)
        print("SES_uc64: "+Ses_uc64)
        ses_uc=base64.b64decode(Ses_uc64.encode())

        ##AT_uc_auth_data="1\n2\n3\n1000\n46772972416b518d8eefb83b0761dfa6a1a441eb1054732313f67c0f04e2c14a\n\n02-june\n".encode()
        print("AT_auth_data:"+str(AT_uc_auth_data))
        C_Chall_uc64=self.receive_byte()
        C_Chall_uc=base64.b64decode(C_Chall_uc64)
        print("C_Chall_uc received: "+str(C_Chall_uc64))
        self.send_text_java("OK")

        Chall_uc=decrypted_aead(ses_uc,C_Chall_uc,AT_uc_auth_data)
        print(str(Chall_uc.decode()))


        ##CREATION OF Response
        ##AT_uc64="hysnr1CvXGFaYl29BFjkdRhtzehs1NUQleYAdEj5VTD9wiBALxWjY07ecaEq6o9FGi8cLDkrFNT1e2EH0AKBkZpLsYOQBh83bJYwSqfE14pq1EJTt1BH3MkymXsI68SM0r61NGj86bKHVpUceCNF+lt8WzJ9LBioS7YsY2nVk+jWbXMBMOluGS42KT/6zTlSqw=="
        ##AT_uc64="A5PnzRCJcEivhPF7xDWdOoLijg7LB1cz8kHPti/x+yniSxAciCg8LYnhfGiFlCWWazpzagEJSAdhZFXV5gv6jY+xp6nueeQkqRG7SZWVWS85cjrqRl+ZAbILsIlVd5W+B4IxrdRGYZv9f6WCSJP0x/Eni3mR8NynFyl2LpaOabxGBMmA19nr63+bIuWk/j83hQ=="
        AT_uc64=base64.b64encode(AT_uc)


        Response_uc=Chall_uc.decode()+hashlib.sha256(AT_uc64).hexdigest()
        print("Response_uc:"+Response_uc)

        ##COMPUTATION OF SESuc_prime
        hash_ses_uc=hashlib.sha256(ses_uc).hexdigest()
        print("hash_ses_uc:"+hash_ses_uc)

        keys=PBKDF2(Ses_uc64,hash_ses_uc.encode(),32,count=1000)
        Ses_uc_prime=keys[:32]
        Ses_uc_prime64 = base64.b64encode(Ses_uc_prime)
        print("\nSes_uc_prime64 is: "+str(Ses_uc_prime64))

        ## CREATION OF C_Response_UC
        C_response_uc=encrypt_aead(Ses_uc_prime,Response_uc.encode(),"12".encode())
        print("\nC_response_uc"+str(base64.b64encode(C_response_uc)))

        size = len(C_response_uc)
        print("File bytes:", size)
        self.clientsocket.sendall(size.to_bytes(4, byteorder='big'))
        ACK=self.receive()
        self.clientsocket.sendall(C_response_uc)

        ##SES_uc_seconde computed
        hash_ses_uc_prime=hashlib.sha256(Ses_uc_prime).hexdigest()
        print("\nhash_ses_uc:"+hash_ses_uc_prime)

        C_ACK_uc64=self.receive_byte()
        print("\nC_ACK_uc64:"+str(C_ACK_uc64))
        C_ACK_uc=base64.b64decode(C_ACK_uc64)

        keys=PBKDF2(Ses_uc_prime64,hash_ses_uc_prime.encode(),32,count=1000)
        SES_uc_seconde=keys[:32]
        SES_uc_seconde64 = base64.b64encode(SES_uc_seconde)
        print("\nSES_uc_seconde64 is: "+str(SES_uc_seconde64))

        ##
        ACK_uc=decrypted_aead(SES_uc_seconde,C_ACK_uc,"12".encode())
        print("\nACK_uc is: "+str(ACK_uc))
        ACK_uc_calculated=Response_uc+hashlib.sha256(AT_uc64).hexdigest()
        print("\nACK_uc_calculated: "+ACK_uc_calculated)
        print("\nHASH AT_uc !:"+str(hashlib.sha256(base64.b64decode(AT_uc64)).hexdigest()))
        self.send_text_java("THE CAR IS OPEN")




    def run(self):
        time.sleep(10**-3)
        print("Thread",threading.get_ident(),"started")
        step=self.receive()
        if step=="session_key".encode():
            self.send_text("OK")
            self.session_key()
        elif step=="open".encode():
            self.send_text_java("OK")
            self.open_the_car()



 #SEVER IS NOW READY
server(HOST,PORT)
