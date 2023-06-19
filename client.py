import os
import random
import socket
import sys
import time
import optparse
import subprocess
# Proxy server bilgileri
import paramiko
import base64
from cryptography.fernet import Fernet

min_wait = 0.5
max_wait = 1.5
def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i","--ip",dest="proxy_ip",help="Enter proxy IP")
    parse_object.add_option("-p", "--port", dest="proxy_port", help="Enter proxy PORT")
    parse_object.add_option("-u","--username",dest="ssh_username",help="Enter SSH username")
    parse_object.add_option("-c", "--password", dest="ssh_password", help="Enter SSH password")

    (user_input,arguments) = parse_object.parse_args()
    if not user_input.proxy_ip:
        print("Enter IP adres")
    elif not user_input.proxy_port:
        print("Enter port number")
    elif not user_input.ssh_username:
        print("Enter port number")
    elif not user_input.ssh_password:
        print("Enter port number")

    return user_input


DH_BASE = 5
DH_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583

def Knocking(HOST, PORT, USERNAME, PASSWORD):
    user_input = get_user_input()
    PROXY_HOST = HOST
    PROXY_PORT = PORT

    # Diffie-Hellman algoritması için private_key ve public_key üret
    private_key = os.urandom(256)#256 byte ya da 2048 bit
    public_key = pow(DH_BASE, int.from_bytes(private_key, "big"), DH_MODULUS)
    print(private_key)
    print(public_key)


    # Port knocking sırası
    KNOCK_SEQUENCE = [1221, 1441, 1771]

    # İsteklerin arasındaki bekleme süresi


    # Port knocking sırasına göre istekleri gönder ve doğru sırada olduğunda SSH bağlantısını aç
    for port in KNOCK_SEQUENCE:
        # Istek gönder
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.connect((PROXY_HOST, port))
        print(f"Istek gönderildi: {port}")

        # Bekle
        #time.sleep(SLEEP_TIME)
        sleep_time = random.uniform(min_wait, max_wait)
        time.sleep(sleep_time)
        #time.sleep(8)
    SLEEP_TIME = 2
    # SSH sunucusu bilgileri
    SSH_HOST = HOST
    SSH_PORT = 9999
    SSH_USERNAME = user_input.ssh_username
    print(SSH_USERNAME)
    SSH_PASSWORD = user_input.ssh_password
    print(SSH_PASSWORD)


    # Proxy server'a bağlan
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.connect((PROXY_HOST, PROXY_PORT))

    # Public key'i Proxy.py'ye gönder
    proxy_socket.sendall(str(public_key).encode())
    time.sleep(SLEEP_TIME)

    # Proxy.py'den gelen public key'i al ve ortak anahtarı hesapla
    proxy_public_key = int(proxy_socket.recv(1024).decode())
    shared_key = pow(proxy_public_key, int.from_bytes(private_key, "big"), DH_MODULUS)
    print(shared_key)

    # Shared key kullanarak şifreleme anahtarını oluştur ve şifrelemeyi gerçekleştir
    cipher_suite = Fernet(base64.urlsafe_b64encode(shared_key.to_bytes(32, "big")))

    proxy_socket.sendall(str(SSH_USERNAME).encode())
    time.sleep(2)

    # Şifrele
    encrypted_password = cipher_suite.encrypt(SSH_PASSWORD.encode())

    # Şifreli şifreyi gönder
    proxy_socket.sendall(encrypted_password)
    print(encrypted_password)
    try:
        while True:
            message = input("Please enter command which will work: ")
            proxy_socket.sendall(message.encode())
            if message == "exit":
                proxy_socket.close()
                break
            time.sleep(3)

            # receive the full response
            full_response = b""
            while True:
                chunk = proxy_socket.recv(1024)
                full_response += chunk
                if len(chunk) < 1024:
                    # we've read all the data
                    break

            decrypted_full_response = cipher_suite.decrypt(full_response).decode()

            print(decrypted_full_response)
            if decrypted_full_response == 'quit':
                print("Exiting...")
                break
    except KeyboardInterrupt:
        proxy_socket.sendall("exit".encode())
        proxy_socket.close()
        print("Exiting...")
        sys.exit(0)


proxy_ipadress = get_user_input()
Knocking(proxy_ipadress.proxy_ip, int(proxy_ipadress.proxy_port), proxy_ipadress.ssh_username, proxy_ipadress.ssh_password)