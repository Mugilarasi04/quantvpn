import sys
sys.path.insert(0, '.')

from src.crypto.kem import KEM
from src.tunnel.tunnel import Tunnel, TunnelServer
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
    server_kem = KEM()
    server_pub = server_kem.generate_keypair()

    print("Server waiting for client connection on port 9999...")
    server = TunnelServer('0.0.0.0', 9999)
    server.start()

    peer_tunnel = server.accept()
    print("Client connected. Sending public key...")

    send_framed(peer_tunnel.sock, server_pub)

    kem_ciphertext = recv_framed(peer_tunnel.sock)
    shared_secret = server_kem.decapsulate(kem_ciphertext)
    print("Handshake complete, shared secret established.")

    peer_tunnel.shared_secret = shared_secret
    peer_tunnel.kem = server_kem

    utun = Utun()
    ifname = utun.open()
    print(f"Opened {ifname} — run in another terminal:")
    print(f"  sudo ifconfig {ifname} 10.10.10.1 10.10.10.2 up")

    forwarder = TunnelForwarder(peer_tunnel, utun)
    forwarder.start()

    print("Forwarding active. Press Enter to stop.")
    input()

    forwarder.stop()
    utun.close()
    peer_tunnel.close()
    server.stop()


if __name__ == "__main__":
    main()
