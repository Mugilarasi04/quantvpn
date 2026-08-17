import threading
from src.tunnel.tunnel import Tunnel, TunnelServer


def test_encrypted_send_receive():
    server = TunnelServer('localhost', 0)
    server.start()
    port = server.listen_sock.getsockname()[1]

    received_data = {}

    def server_thread_fn():
        peer = server.accept()
        received_data['msg'] = peer.receive()
        peer.close()

    thread = threading.Thread(target=server_thread_fn)
    thread.start()

    client = Tunnel('localhost', port)
    client.connect()
    client.send(b"hello quantum tunnel")

    thread.join()
    server.stop()
    client.close()

    assert received_data['msg'] == b"hello quantum tunnel"
