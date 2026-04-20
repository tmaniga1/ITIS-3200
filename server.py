import socket
import hashlib
 
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)
 
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server is listening on {HOST}:{PORT}...")
    conn, addr = s.accept()
    with conn:
        print(f"Connection established with {addr}")
        data = conn.recv(1024).decode()
        print(f"Received from client: {data}")
        
        # Server logic check
        if "robux" in data.lower():
            tx_hash = hashlib.md5(data.encode()).hexdigest()
            response = f"SERVER_ACK: Transaction Approved. TX_ID: {tx_hash}"
        else:
            response = "SERVER_ERR: Invalid request format."
        conn.sendall(response.encode())