import threading
import time
from src.tunnel.tunnel import Tunnel, TunnelServer
from src.entropy_monitor.entropy_monitor import EntropyMonitor


def test_rekey_sync_after_anomaly():
    def make_monitor():
        return EntropyMonitor(window_size=5, threshold=0.2)

    server = TunnelServer('localhost', 0, monitor_factory=make_monitor)
    server.start()
    port = server.listen_sock.getsockname()[1]

    server_state = {'received': []}

    def run_server():
        peer = server.accept()
        for _ in range(5):
            msg = peer.receive()
            server_state['received'].append(msg)
        server_state['final_secret'] = peer.shared_secret
        peer.close()

    server_thread = threading.Thread(target=run_server)
    server_thread.start()

    client = Tunnel('localhost', port)
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
    server.stop()
    client.close()

    assert server_state['received'][-1] == b"post-rotation message"
    assert server_state['final_secret'] == client.shared_secret
