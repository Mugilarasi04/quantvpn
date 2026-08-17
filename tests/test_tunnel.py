import threading
from src.tunnel.tunnel import Tunnel, TunnelServer


def test_connect_performs_handshake():
    server = TunnelServer('localhost', 0)
    server.start()
    port = server.listen_sock.getsockname()[1]

    server_state = {}

    def run_server():
        peer = server.accept()
        server_state['tunnel'] = peer

    thread = threading.Thread(target=run_server)
    thread.start()

    client = Tunnel('localhost', port)
    result = client.connect()

    thread.join()
    server.stop()

    assert result is True
    assert client.connected is True
    assert client.shared_secret is not None
    assert server_state['tunnel'].shared_secret == client.shared_secret

    client.close()
    server_state['tunnel'].close()
