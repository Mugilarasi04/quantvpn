import socket
import threading
from src.tunnel.tunnel import Tunnel


def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    s.listen(1)
    port = s.getsockname()[1]
    return s, port


def test_connect_to_real_server():
    server_socket, port = start_server()

    def accept_connection():
        conn, addr = server_socket.accept()
        conn.close()

    server_thread = threading.Thread(target=accept_connection)
    server_thread.start()

    t = Tunnel('localhost', port)
    result = t.connect()

    server_thread.join()
    server_socket.close()

    assert result is True
    assert t.connected is True