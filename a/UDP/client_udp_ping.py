# client_udp_ping.py
import socket
import time
import argparse

def run_ping(host, port, count=10, interval=1.0, timeout=1.0):
    addr = (host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    stats = {
        "sent": 0,
        "received": 0,
        "rtts": []
    }

    for seq in range(1, count+1):
        # gửi: "SEQ|timestamp_ns"
        ts_send = time.time_ns()
        payload = f"{seq}|{ts_send}".encode("utf-8")
        try:
            sock.sendto(payload, addr)
            stats["sent"] += 1
        except Exception as e:
            print(f"[{seq}] Send failed: {e}")
            time.sleep(interval)
            continue

        try:
            data, _ = sock.recvfrom(4096)
            ts_recv = time.time_ns()
            # parse nhận về
            try:
                text = data.decode("utf-8")
                seq_recv_str, sent_ts_str = text.split("|", 1)
                seq_recv = int(seq_recv_str)
                sent_ts = int(sent_ts_str)
            except Exception:
                # nếu format khác, bỏ qua
                print(f"[{seq}] Unexpected reply: {data!r}")
                continue

            rtt_ms = (ts_recv - sent_ts) / 1_000_000  # ms
            stats["received"] += 1
            stats["rtts"].append(rtt_ms)
            print(f"[{seq}] Reply seq={seq_recv} RTT={rtt_ms:.3f} ms")
        except socket.timeout:
            print(f"[{seq}] Request timed out (no reply within {timeout}s)")
        except Exception as e:
            print(f"[{seq}] Error receiving: {e}")

        time.sleep(interval)

    # tóm tắt
    sent = stats["sent"]
    rcv = stats["received"]
    lost = sent - rcv
    loss_pct = (lost / sent * 100) if sent else 0
    print("\n--- Ping statistics ---")
    print(f"Sent = {sent}, Received = {rcv}, Lost = {lost} ({loss_pct:.1f}% loss)")
    if stats["rtts"]:
        rtts = stats["rtts"]
        print(f"RTT min/avg/max = {min(rtts):.3f}/{(sum(rtts)/len(rtts)):.3f}/{max(rtts):.3f} ms")
    sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UDP ping client")
    parser.add_argument("host", help="server host (IP or hostname)")
    parser.add_argument("--port", type=int, default=56565, help="server port")
    parser.add_argument("--count", type=int, default=10, help="number of pings")
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between sends")
    parser.add_argument("--timeout", type=float, default=1.0, help="recv timeout seconds")
    args = parser.parse_args()

    run_ping(args.host, args.port, count=args.count, interval=args.interval, timeout=args.timeout)
