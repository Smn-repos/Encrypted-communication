import socket
import threading

import pyDH
import rsa
from Cryptodome.Cipher import AES, DES3
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.backends import default_backend
import pickle

def AES_sifrovanie(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return ct_bytes

def AES_desifrovanie(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt.decode('utf-8')

def receive_aes_key_and_start_communication(c):
    aes_key_encrypted = c.recv(128)
    aes_key = rsa.decrypt(aes_key_encrypted, private_key_rsa)
    iv = c.recv(16)
    threading.Thread(target=send_messages_AES, args=(c, aes_key, iv)).start()
    threading.Thread(target=receive_messages_AES, args=(c, aes_key, iv)).start()

def dh_aes_key_communication(c):
    client_dh=pyDH.DiffieHellman(15)
    client_public_key = client_dh.gen_public_key()
    server_public_key = int(c.recv(1024).decode())
    c.send(str(client_public_key).encode())
    shared_key = client_dh.gen_shared_key(server_public_key)
    des3_key = str(shared_key).encode()[:16]
    iv=c.recv(16)
    threading.Thread(target=send_messages_AES_dh, args=(c, des3_key, iv)).start()
    threading.Thread(target=receive_messages_AES_dh, args=(c, des3_key, iv)).start()
def send_messages_AES(c, aes_key, iv):
    while True:
        message = input("Me (AES): ")
        encrypted_message = AES_sifrovanie(message, aes_key, iv)
        c.sendall(encrypted_message)
def send_messages_AES_dh(c, shared_key, iv):
    while True:
        message = input("Me (AES): ")
        encrypted_message = AES_sifrovanie(message, shared_key, iv)
        c.sendall(encrypted_message)

def receive_messages_AES_dh(c, shared_key, iv):
    while True:
        ciphertext = c.recv(1024)
        decrypted_message = AES_desifrovanie(ciphertext, shared_key, iv)  # Corrected parameter order
        print("Partner (AES): " + decrypted_message)
def receive_messages_AES(c, aes_key, iv):
    while True:
        ciphertext = c.recv(1024)
        decrypted_message = AES_desifrovanie(ciphertext, aes_key, iv)
        print("Partner (AES): " + decrypted_message)

def receive_des3_key_and_start_communication(c):
    des3_key_encrypted = c.recv(192)
    des3_key = rsa.decrypt(des3_key_encrypted, private_key_rsa)
    iv = c.recv(8)
    threading.Thread(target=send_messages_DES3, args=(c, des3_key)).start()
    threading.Thread(target=receive_messages_DES3, args=(c, des3_key)).start()

def dh_des3_key_communication(c):
    client_dh = pyDH.DiffieHellman()
    client_public_key = client_dh.gen_public_key()
    server_public_key = int(c.recv(1024).decode())
    c.send(str(client_public_key).encode())
    shared_key = client_dh.gen_shared_key(server_public_key)
    des3_key = str(shared_key).encode()[:24]
    iv=c.recv(8)
    threading.Thread(target=send_messages_DES3, args=(c, des3_key)).start()
    threading.Thread(target=receive_messages_DES3, args=(c, des3_key)).start()

def DES3_sifrovanie(message, key):
    iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message.encode(), DES3.block_size))
    return iv + ct_bytes


def DES3_desifrovanie(ciphertext, key):
    iv = ciphertext[:8]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext[8:]), DES3.block_size)
    return pt.decode('utf-8')

def send_messages_DES3(c, des3_key):
    while True:
        message = input("Me (DES3): ")
        encrypted_message = DES3_sifrovanie(message, des3_key)
        c.sendall(encrypted_message)

def receive_messages_DES3(c, des3_key):
    while True:
        ciphertext = c.recv(4096)
        decrypted_message = DES3_desifrovanie(ciphertext, des3_key)
        print("Partner (DES3): " + decrypted_message)

# Establish RSA keys
public_key_rsa, private_key_rsa = rsa.newkeys(1024)

# Establish connection with server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 9999))
client.send(public_key_rsa.save_pkcs1())

# Receive encryption and key transfer choice
encryption_choice = client.recv(3).decode()
key_transfer_choice = client.recv(3).decode()

if encryption_choice == 'AES':
    if key_transfer_choice == 'RSA':
        receive_aes_key_and_start_communication(client)
    elif key_transfer_choice=='DH':
        dh_aes_key_communication(client)
elif encryption_choice == 'DES':
   
    if key_transfer_choice == 'RSA':
        receive_des3_key_and_start_communication(client)
    elif key_transfer_choice =='DH':
        dh_des3_key_communication(client)


