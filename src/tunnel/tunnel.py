import socket
from src.crypto.aead import encrypt, decrypt


class Tunnel:
    def __init__(self, host: str, port: int, shared_secret: bytes = None, peer_public_key: bytes = None):
        self.host = host
        self.port = port
        self.connected = False
        self.sock = None
        self.shared_secret = shared_secret
        self.peer_public_key = peer_public_key
        
        self.monitor = None
    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.connected = True
        except (socket.error, ConnectionRefusedError):
            self.connected = False
        return self.connected

    def send(self, data: bytes) -> bool:
        if not self.connected:
            raise ConnectionError("Tunnel is not connected")
        if self.shared_secret is None:
            raise ValueError("No shared secret set for encryption")
        try:
            encrypted = encrypt(self.shared_secret, data)
            self.sock.sendall(encrypted)
            return True
        except socket.error:
            self.connected = False
            return False

    def receive(self, buffer_size: int = 4096) -> bytes:
        if not self.connected:
            raise ConnectionError("Tunnel is not connected")
        if self.shared_secret is None:
            raise ValueError("No shared secret set for decryption")
        try:
            raw = self.sock.recv(buffer_size)
            if not raw:
                return b""
            plaintext = decrypt(self.shared_secret, raw)

            if self.monitor is not None:
                for byte in plaintext:
                    result = self.monitor.update(byte)
                    if result["anomaly"] and self.peer_public_key is not None:
                        from src.entropy_monitor.response import KeyRotationResponder
                        if not hasattr(self, "_responder"):
                            self._responder = KeyRotationResponder()
                        _, new_secret = self._responder.respond(result, self.peer_public_key)
                        self.shared_secret = new_secret

            return plaintext
        except socket.error:
            self.connected = False
            return b""

            return plaintext
        except socket.error:
            self.connected = False
            return b""

    def close(self) -> None:
        if self.sock:
            self.sock.close()
        self.connected = False


class TunnelServer:
    def __init__(self, host: str, port: int, shared_secret: bytes = None, monitor_factory=None):
        self.host = host
        self.port = port
        self.shared_secret = shared_secret
        self.listen_sock = None
        self.monitor_factory = monitor_factory

    def start(self) -> None:
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind((self.host, self.port))
        self.listen_sock.listen(5)

    def accept(self) -> "Tunnel":
        conn, addr = self.listen_sock.accept()
        peer_tunnel = Tunnel(host=addr[0], port=addr[1], shared_secret=self.shared_secret)
        peer_tunnel.sock = conn
        peer_tunnel.connected = True
        if self.monitor_factory is not None:
            peer_tunnel.monitor = self.monitor_factory()
        return peer_tunnel

    def stop(self) -> None:
        if self.listen_sock:
            self.listen_sock.close()