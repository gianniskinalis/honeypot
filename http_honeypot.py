import socket
import threading
import datetime
import os

HOST = '0.0.0.0'
PORT = 80
LOG_FILE = 'logs/http_honeypot.log'

def log(message):
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(LOG_FILE, 'a') as f:
        f.write(entry + '\n')

def parse_http_request(data):
    try:
        lines = data.decode('utf-8', errors='ignore').split('\r\n')
        request_line = lines[0]
        headers = {}
        for line in lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        return request_line, headers
    except Exception:
        return data[:200], {}

def send_fake_response(client_socket):
    response_body = """<!DOCTYPE html>
<html>
<head><title>Apache2 Ubuntu Default Page</title></head>
<body>
<h1>Apache2 Ubuntu Default Page</h1>
<p>It works!</p>
</body>
</html>"""
    response = (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.41 (Ubuntu)\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(response_body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
        + response_body
    )
    client_socket.sendall(response.encode('utf-8'))

def handle_connection(client_socket, client_ip):
    try:
        data = client_socket.recv(4096)
        if data:
            request_line, headers = parse_http_request(data)
            user_agent = headers.get('User-Agent', 'Unknown')
            host_header = headers.get('Host', 'Unknown')
            log(f"HTTP request | IP: {client_ip} | Request: {request_line} | User-Agent: {user_agent} | Host: {host_header}")
            send_fake_response(client_socket)
    except Exception as e:
        log(f"HTTP error | IP: {client_ip} | Error: {str(e)}")
    finally:
        client_socket.close()

def start_http_honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)
    log(f"HTTP Honeypot listening on port {PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        client_ip = addr[0]
        log(f"HTTP connection received from {client_ip}")
        thread = threading.Thread(target=handle_connection, args=(client_socket, client_ip))
        thread.daemon = True
        thread.start()

if __name__ == '__main__':
    start_http_honeypot()
