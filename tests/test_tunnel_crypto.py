import socket
import threading
from src.crypto.kem import KEM, encapsulate
from src.tunnel.tunnel import Tunnel


def test_encrypted_send_receive():
    receiver_kem = KEM()
    public_key = receiver_kem.generate_keypair()
    ciphertext, sender_secret = encapsulate(public_key)
    receiver_secret = receiver_kem.decapsulate(ciphertext)

    assert sender_secret == receiver_secret

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 0))
    server_socket.listen(1)
    port = server_socket.getsockname()[1]

    received_data = {}

    def server_thread_fn():
        conn, addr = server_socket.accept()
        server_tunnel = Tunnel.__new__(Tunnel)
        server_tunnel.sock = conn
        server_tunnel.connected = True
        server_tunnel.shared_secret = receiver_secret
        server_tunnel.monitor = None
        received_data['msg'] = server_tunnel.receive()
        conn.close()

    thread = threading.Thread(target=server_thread_fn)
    thread.start()

    client = Tunnel('localhost', port, shared_secret=sender_secret)
    client.connect()
    client.send(b"hello quantum tunnel")

    thread.join()
    server_socket.close()
    client.close()

    assert received_data['msg'] == b"hello quantum tunnel"