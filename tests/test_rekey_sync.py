import socket
import threading
import time
from src.crypto.kem import KEM, encapsulate
from src.tunnel.tunnel import Tunnel
from src.entropy_monitor.entropy_monitor import EntropyMonitor


def test_rekey_sync_after_anomaly():
    client_kem = KEM()
    client_pub = client_kem.generate_keypair()

    server_kem = KEM()
    server_pub = server_kem.generate_keypair()
    rekey_ct, secret_a = encapsulate(server_pub)
    server_secret_a = server_kem.decapsulate(rekey_ct)
    assert secret_a == server_secret_a

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 0))
    server_socket.listen(1)
    port = server_socket.getsockname()[1]

    server_state = {'received': []}

    def run_server():
        conn, addr = server_socket.accept()
        server_tunnel = Tunnel.__new__(Tunnel)
        server_tunnel.sock = conn
        server_tunnel.connected = True
        server_tunnel.shared_secret = secret_a
        server_tunnel.peer_public_key = client_pub
        server_tunnel.kem = None
        server_tunnel._responder = None
        server_tunnel._in_anomaly = False
        server_tunnel.monitor = EntropyMonitor(window_size=5, threshold=0.2)

        for _ in range(5):
            msg = server_tunnel.receive()
            server_state['received'].append(msg)
        server_state['final_secret'] = server_tunnel.shared_secret
        conn.close()

    server_thread = threading.Thread(target=run_server)
    server_thread.start()

    client = Tunnel('localhost', port, shared_secret=secret_a, kem=client_kem)
    client.connect()

    def client_reader():
        while client.connected:
            client.receive()

    reader_thread = threading.Thread(target=client_reader, daemon=True)
    reader_thread.start()

    client.send(bytes(range(10)))
    client.send(bytes(range(10, 20)))
    client.send(bytes(range(20, 30)))
    client.send(bytes([0] * 10))

    time.sleep(0.3)

    client.send(b"post-rotation message")

    server_thread.join(timeout=5)
    server_socket.close()
    client.close()

    assert server_state['received'][-1] == b"post-rotation message"
    assert server_state['final_secret'] == client.shared_secret
