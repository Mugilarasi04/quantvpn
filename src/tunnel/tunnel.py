import socket
from src.crypto.aead import encrypt, decrypt


class Tunnel:
    def __init__(self, host: str, port: int, shared_secret: bytes = None):
        self.host = host
        self.port = port
        self.connected = False
        self.sock = None
        self.shared_secret = shared_secret

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
            return decrypt(self.shared_secret, raw)
        except socket.error:
            self.connected = False
            return b""

    def close(self) -> None:
        if self.sock:
            self.sock.close()
        self.connected = False