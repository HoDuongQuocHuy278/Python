# server_udp.py
import socket

HOST = "0.0.0.0"   # lắng nghe mọi interface; để localhost dùng "127.0.0.1"
PORT = 56577

def run_server(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, port))
        print(f"UDP server listening on {host}:{port}")
        while True:
            data, addr = s.recvfrom(4096)   # buffer size 4096 bytes
            if not data:
                continue
            # data là bytes; ta echo lại như cũ (có thể thêm xử lý)
            print(f"Received {len(data)} bytes from {addr}")
            # bạn có thể sửa đổi trả về, ví dụ thêm server timestamp, nhưng đơn giản echo:
            s.sendto(data, addr)

if __name__ == "__main__":
    run_server()
