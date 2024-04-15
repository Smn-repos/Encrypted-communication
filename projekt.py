import socket
import threading
import pyDH
import rsa
from Cryptodome.Cipher import AES, DES3
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generuj_aes_kluc():
    return get_random_bytes(16)

def AES_sifrovanie(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return ct_bytes

def AES_desifrovanie(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt.decode('utf-8')

def server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 9999))
    server.listen()
    client, _ = server.accept()
    public_key_rsa = rsa.PublicKey.load_pkcs1(client.recv(1024))
    volba_siforvania = input("AES/DES3: ").upper()
    client.send(volba_siforvania.encode())
    volba_prenosu_kluca=input("RSA/DH: ").upper()
    client.send(volba_prenosu_kluca.encode())

    if volba_siforvania == 'AES':
        if volba_prenosu_kluca=='RSA':
            send_aes_key(client, public_key_rsa)
        elif volba_prenosu_kluca=='DH':
            send_aes_key_dh(client)
    elif volba_siforvania == 'DES':
        if volba_prenosu_kluca=='RSA':
            send_des3_key_rsa(client, public_key_rsa)
        elif volba_prenosu_kluca == 'DH':
            send_des3_key_dh(client)


def send_aes_key(c, public_key_rsa):
    aes_key = generuj_aes_kluc()
    aes_key_encrypted = rsa.encrypt(aes_key, public_key_rsa)
    c.sendall(aes_key_encrypted)
    iv = get_random_bytes(16)
    c.sendall(iv)
    threading.Thread(target=send_messages_AES, args=(c, aes_key, iv)).start()
    threading.Thread(target=receive_messages_AES, args=(c, aes_key, iv)).start()

def send_aes_key_dh(c):
    server_dh = pyDH.DiffieHellman(15)
    server_public_key = server_dh.gen_public_key()
    c.send(str(server_public_key).encode())
    client_public_key = int(c.recv(1024).decode())
    shared_key = server_dh.gen_shared_key(client_public_key)
    aes_key = str(shared_key).encode()[:16]
    iv = get_random_bytes(16)
    c.sendall(iv)
    threading.Thread(target=send_messages_AES_dh, args=(c, aes_key, iv)).start()
    threading.Thread(target=receive_messages_AES_dh, args=(c, aes_key, iv)).start()

def send_messages_AES(c, aes_key, iv):
    while True:
        message = input("Ja: ")
        encrypted_message = AES_sifrovanie(message, aes_key, iv)
        c.sendall(encrypted_message)
def receive_messages_AES(c, aes_key, iv):
    while True:
        ciphertext = c.recv(1024)
        decrypted_message = AES_desifrovanie(ciphertext, aes_key, iv)
        print("Partner: " + decrypted_message)


def send_messages_AES_dh(c, shared_key, iv):
    while True:
        message = input("Me (AES): ")
        encrypted_message = AES_sifrovanie(message, shared_key, iv)
        c.sendall(encrypted_message)

def receive_messages_AES_dh(c, shared_key, iv):
    while True:
        ciphertext = c.recv(1024)
        decrypted_message = AES_desifrovanie(ciphertext, shared_key, iv)
        print("Partner (AES): " + decrypted_message)

def generuj_des3_kluc():
    return DES3.adjust_key_parity(get_random_bytes(24))
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

def des3_cipher(message,des3_key,iv):
    cipher=DES3.new(des3_key,DES3.MODE_CBC,iv)
    ct_bytes = cipher.encrypt(pad(message.encode(), DES3.block_size))
    return iv+ct_bytes

def des3_decrypt(ciphertext,key):
    iv=ciphertext[:8]
    cipher=DES3.new(key,DES3.MODE_CBC,iv)
    pt=unpad(cipher.decrypt(ciphertext[:8]),DES3.block_size)
    return pt.decode('utf-8')


def send_des3_key_rsa(c, public_key_rsa):
    des3_key = generuj_des3_kluc()
    des3_key_encrypted = rsa.encrypt(des3_key, public_key_rsa)
    c.send(des3_key_encrypted)
    threading.Thread(target=send_messages_DES3, args=(c, des3_key)).start()
    threading.Thread(target=receive_messages_DES3, args=(c, des3_key)).start()


def send_des3_key_dh(c):
    server_dh = pyDH.DiffieHellman()
    server_public_key = server_dh.gen_public_key()
    c.send(str(server_public_key).encode())
    client_public_key = int(c.recv(1024).decode())
    shared_key = server_dh.gen_shared_key(client_public_key)
    des3_key=str(shared_key).encode()[:24]
    des3_iv = get_random_bytes(8)
    c.sendall(des3_iv)
    threading.Thread(target=send_messages_DES3, args=(c, des3_key)).start()
    threading.Thread(target=receive_messages_DES3, args=(c, des3_key)).start()

def send_messages_DES3(c, des3_key):
    while True:
        message = input("Ja: ")
        encrypted_message = DES3_sifrovanie(message, des3_key)
        c.sendall(encrypted_message)

def receive_messages_DES3(c, des3_key):
    while True:
        ciphertext = c.recv(4096)
        decrypted_message = DES3_desifrovanie(ciphertext, des3_key)
        print("Partner: " + decrypted_message)

def send_messages_DES3_dh(c, des3_key,iv):
    while True:
        message = input("Ja: ")
        encrypted_message = des3_cipher(message, des3_key,iv)
        c.sendall(encrypted_message)

def receive_messages_DES3_dh(c, des3_key):
    while True:
        ciphertext = c.recv(4096)
        decrypted_message = DES3_desifrovanie(ciphertext, des3_key)
        print("Partner: " + decrypted_message)

if __name__ == "__main__":
    server()
