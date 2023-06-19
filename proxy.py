import logging
import socket
import socketserver
import sys
import threading
import time
import os
import paramiko
import base64
from cryptography.fernet import Fernet

host = '10.0.2.4'
command = ''
response = ''
ssh_username = ''
ssh_password = ''
ssh_client = None
ssh_shell = None
running = True

logging.basicConfig(filename='port_knock.log', level=logging.INFO, format='%(asctime)s - %(message)s')

command_lock = threading.Lock()
response_lock = threading.Lock()


def handle_client(client_socket):
    DH_BASE = 5
    DH_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    global command
    global response
    global running
    with command_lock:
        command = ''
    with response_lock:
        response = ''
    response = ''
    print("[+] New connection from: %s:%d" % client_socket.getpeername())
    received_ports = [1221,1441,1771]
    b = True
    while b:
        try:
            # Diffie-Hellman algoritması için private_key ve public_key üret
            private_key = os.urandom(256)
            public_key = pow(DH_BASE, int.from_bytes(private_key, "big"), DH_MODULUS)

            # Public key'i Client.py'ye gönder
            client_socket.sendall(str(public_key).encode())

            # Client.py'den gelen public_key'i al ve ortak anahtarı hesapla
            client_public_key = int(client_socket.recv(1024).decode())
            shared_key = pow(client_public_key, int.from_bytes(private_key, "big"), DH_MODULUS)

            # Shared key kullanarak şifreleme anahtarını oluştur ve şifrelemeyi gerçekleştir
            cipher_suite = Fernet(base64.urlsafe_b64encode(shared_key.to_bytes(32, "big")))

            receive_credentials(client_socket, cipher_suite)
            while 1:
                command = client_socket.recv(1024).decode('utf-8').strip()
                if command == 'exit':
                    b = False
                    running = False
                    client_socket.sendall("Exiting...".encode('utf-8'))
                    client_socket.close()
                    os.system("systemctl stop ssh")
                    break
                else:
                    print(command)
                    ssh_thread = threading.Thread(target=open_ssh_port)
                    ssh_thread.start()
                    ssh_thread.join()
                    encrypted_response = cipher_suite.encrypt(response.encode('utf-8'))
                    client_socket.sendall(encrypted_response)
                    # Log successful SSH login
                    logging.info("Successful SSH login by user '%s' from: %s:%d", ssh_username,
                                 client_socket.getpeername()[0], client_socket.getpeername()[1])
                    print(response)
                    response = ''

        except socket.timeout:
            print("[!] Timeout occurred while waiting for data from client")
            client_socket.close()
            os.system("systemctl stop ssh")
            break
        except paramiko.AuthenticationException as e:
            print("[!] Authentication failed for user '%s': %s" % (ssh_username, e))
            logging.info("Failed SSH login attempt by user '%s' from: %s:%d", ssh_username,
                         client_socket.getpeername()[0], client_socket.getpeername()[1])
            client_socket.close()
            break
        except KeyboardInterrupt:
            b = False
            client_socket.sendall("exit".encode())
            time.sleep(1)
            client_socket.close()
            os.system("systemctl stop ssh")
            print("Proxy server is shutting down...")
            sys.exit(0)

    client_socket.close()

TIMEOUT = 2  # Define a timeout variable


def open_ssh_port(num_connections=5):
    global command
    global ssh_client
    global ssh_shell
    global ssh_username
    global ssh_password
    global response
    SSH_HOST = "10.0.2.4"
    SSH_PORT = 22
    SSH_USERNAME = ssh_username
    SSH_PASSWORD = ssh_password
    with response_lock:
        response = ''
    os.system("service ssh start")
    with command_lock:
        # Check if SSH connection is already open
        if ssh_client is not None and ssh_client.get_transport().is_active():
            print("Using existing SSH connection")
        else:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=SSH_HOST, port=SSH_PORT, username=SSH_USERNAME, password=SSH_PASSWORD)
            print("[+] Opening SSH port")
            ssh_client = ssh
            ssh_shell = ssh_client.invoke_shell()  # Yeni kabuk oturumunu başlat



        ssh_shell.send(command + '\n')
        start_time = time.time()
        while True:
            if ssh_shell.recv_ready():
                response_chunk = ssh_shell.recv(1024).decode('utf-8')
                response += response_chunk
            elif time.time() - start_time > TIMEOUT:
                break
            else:
                time.sleep(0.1)
        # Ignore the first line (terminal line) in the response
        response = '\n'.join(response.split('\n')[1:])





def check_ssh_server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        s.shutdown(socket.SHUT_RDWR)
        return True
    except:
        return False
    finally:
        s.close()


def receive_credentials(client_socket, cipher_suite):
    global ssh_username
    global ssh_password

    ssh_username = client_socket.recv(1024).decode('utf-8').strip()

    # Şifreli şifreyi al
    encrypted_password = client_socket.recv(1024)

    # Şifreli şifreyi çöz
    ssh_password = cipher_suite.decrypt(encrypted_password).decode('utf-8')

    print("Received credentials:")
    print("Username: ", ssh_username)
    print("Password: ", ssh_password)



KNOCK_TIMEOUT = 7

def check_new_connection(server_socket, timeout):
    server_socket.settimeout(timeout)
    try:
        client_socket, addr = server_socket.accept()
        return client_socket, addr
    except socket.timeout:
        return None, None

def start_proxy_server():
    global host
    received_ports = [1221, 1441, 1771]

    # Önce 1221, 1441, 1771 numaralı portları dinleyin
    for listen_port in received_ports:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, listen_port))
        server_socket.listen(1)
        print("[+] Proxy server started on %s:%d" % server_socket.getsockname())

        start_time = time.time()
        while True:
            client_socket, addr = check_new_connection(server_socket, KNOCK_TIMEOUT)
            elapsed_time = time.time() - start_time

            if client_socket:
                print("[+] New connection from: %s:%d" % (addr[0], addr[1]))
                server_socket.close()
                break  # Bağlantı sağlandığında, sonraki porta geçmek için döngüden çıkar
            elif elapsed_time >= KNOCK_TIMEOUT:
                start_time = time.time()
                server_socket.close()
                break  # Zaman aşımı olduğunda, süreci başa al

        # Zaman aşımı yoksa sonraki portu kontrol et
        if client_socket is not None:
            logging.info("Successful port knock sequence received from: %s:%d", client_socket.getpeername()[0],
                         client_socket.getpeername()[1])
            continue

        # Zaman aşımı olduysa süreci başa al
        else:
            print("[!] Knock timeout: Restarting knock sequence")
            return start_proxy_server()

    # Döngü tamamlandığında, 9999 numaralı portu dinlemeye başlayın
    port = 9999
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print("[+] Proxy server started on %s:%d" % server_socket.getsockname())
    while running:
        try:
            client_socket, address = server_socket.accept()
            client_socket.settimeout(30)

        except socket.error as e:
            print("[!] Error accepting connection: %s" % e)
            break
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()
        client_thread.join()

    print("Proxy server is shutting down...")



if __name__ == '__main__':
    start_proxy_server()