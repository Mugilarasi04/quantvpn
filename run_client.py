import sys
sys.path.insert(0, '.')

from src.crypto.kem import KEM, encapsulate
from src.tunnel.tunnel import Tunnel
from src.tunnel.utun import Utun
from src.tunnel.forwarder import TunnelForwarder


def send_framed(sock, data: bytes):
    sock.sendall(len(data).to_bytes(4, 'big') + data)


def recv_framed(sock) -> bytes:
    length_bytes = sock.recv(4)
    length = int.from_bytes(length_bytes, 'big')
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket closed during handshake")
        data += chunk
    return data


def main():
    server_host = input("Server host (localhost): ") or "localhost"

    print("Connecting to server...")
    tunnel = Tunnel(server_host, 9999, shared_secret=None)
    tunnel.connect()
    print("Connected. Waiting for server's public key...")

    server_pub = recv_framed(tunnel.sock)
    print("Received public key. Performing handshake...")

    ciphertext, shared_secret = encapsulate(server_pub)
    send_framed(tunnel.sock, ciphertext)

    tunnel.shared_secret = shared_secret
    print("Handshake complete, shared secret established.")

    utun = Utun()
    ifname = utun.open()
    print(f"Opened {ifname} — run in another terminal:")
    print(f"  sudo ifconfig {ifname} 10.10.10.2 10.10.10.1 up")

    forwarder = TunnelForwarder(tunnel, utun)
    forwarder.start()

    print("Forwarding active. Press Enter to stop.")
    input()

    forwarder.stop()
    utun.close()
    tunnel.close()


if __name__ == "__main__":
    main()
