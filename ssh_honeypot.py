import socket
import threading
import paramiko
import datetime
import os

HOST = '0.0.0.0'
PORT = 22
LOG_FILE = 'logs/ssh_honeypot.log'

# Generate or load host key
HOST_KEY_FILE = 'honeypot_rsa.key'
if not os.path.exists(HOST_KEY_FILE):
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file(HOST_KEY_FILE)
else:
    host_key = paramiko.RSAKey(filename=HOST_KEY_FILE)

def log(message):
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(LOG_FILE, 'a') as f:
        f.write(entry + '\n')

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log(f"SSH attempt | IP: {self.client_ip} | Username: {username} | Password: {password}")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

def handle_connection(client_socket, client_ip):
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        fake_server = FakeSSHServer(client_ip)
        transport.start_server(server=fake_server)
        chan = transport.accept(30)
    except Exception as e:
        log(f"SSH error | IP: {client_ip} | Error: {str(e)}")
    finally:
        try:
            if transport:
                transport.close()
        except:
            pass

def start_ssh_honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)
    log(f"SSH Honeypot listening on port {PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        client_ip = addr[0]
        log(f"SSH connection received from {client_ip}")
        thread = threading.Thread(target=handle_connection, args=(client_socket, client_ip))
        thread.daemon = True
        thread.start()

if __name__ == '__main__':
    start_ssh_honeypot()
