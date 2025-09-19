import socket

HOST = "127.0.0.1"
PORT = 55555

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SQL_SOCKET, socket.SO_REUSEADDR,1);    
    server.bind(HOST, PORT)
    server.listen(1)
    print(f"Server đã sẳn sàng")
    
    conn, addr=server.accept()
    
    with conn:
        print("connect by", addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
                text= data.decode("utf-8")
                print(text)
                conn.