import threading
from src.tunnel.tunnel import Tunnel, TunnelServer


def test_server_accepts_and_receives():
    server = TunnelServer('localhost', 0)
    server.start()
    port = server.listen_sock.getsockname()[1]

    received = {}

    def run_server():
        peer = server.accept()
        received['msg'] = peer.receive()
        peer.close()

    thread = threading.Thread(target=run_server)
    thread.start()

    client = Tunnel('localhost', port)
    client.connect()
    client.send(b"hello from client")

    thread.join()
    server.stop()
    client.close()

    assert received['msg'] == b"hello from client"
