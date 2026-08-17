import socket
import struct
from src.crypto.aead import encrypt, decrypt
from src.crypto.kem import KEM, encapsulate

MSG_TYPE_DATA = b'D'
MSG_TYPE_REKEY = b'R'
MSG_TYPE_HANDSHAKE = b'H'


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed while reading")
        data += chunk
    return data


def _send_framed(sock, msg_type: bytes, payload: bytes):
    header = msg_type + struct.pack(">I", len(payload))
    sock.sendall(header + payload)


def _recv_framed(sock):
    header = _recv_exact(sock, 5)
    msg_type = header[0:1]
    length = struct.unpack(">I", header[1:5])[0]
    payload = _recv_exact(sock, length)
    return msg_type, payload


class Tunnel:
    def __init__(self, host: str, port: int, shared_secret: bytes = None,
                 peer_public_key: bytes = None, kem=None):
        self.host = host
        self.port = port
        self.connected = False
        self.sock = None
        self.shared_secret = shared_secret
        self.peer_public_key = peer_public_key
        self.kem = kem
        self.monitor = None
        self._responder = None
        self._in_anomaly = False

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.connected = True
            self._handshake_as_client()
        except (socket.error, ConnectionRefusedError, ConnectionError):
            self.connected = False
        return self.connected

    def _handshake_as_client(self):
        self.kem = KEM()
        own_pub = self.kem.generate_keypair()

        _send_framed(self.sock, MSG_TYPE_HANDSHAKE, own_pub)
        _, peer_pub = _recv_framed(self.sock)
        self.peer_public_key = peer_pub

        ciphertext, shared_secret = encapsulate(peer_pub)
        _send_framed(self.sock, MSG_TYPE_HANDSHAKE, ciphertext)
        self.shared_secret = shared_secret

    def _handshake_as_server(self):
        self.kem = KEM()
        own_pub = self.kem.generate_keypair()

        _, peer_pub = _recv_framed(self.sock)
        self.peer_public_key = peer_pub
        _send_framed(self.sock, MSG_TYPE_HANDSHAKE, own_pub)

        _, ciphertext = _recv_framed(self.sock)
        self.shared_secret = self.kem.decapsulate(ciphertext)

    def send(self, data: bytes) -> bool:
        if not self.connected:
            raise ConnectionError("Tunnel is not connected")
        if self.shared_secret is None:
            raise ValueError("No shared secret set for encryption")
        try:
            encrypted = encrypt(self.shared_secret, data)
            _send_framed(self.sock, MSG_TYPE_DATA, encrypted)
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
            msg_type, payload = _recv_framed(self.sock)

            if msg_type == MSG_TYPE_REKEY:
                if self.kem is None:
                    raise ValueError("Received rekey message but no KEM keypair to decapsulate it")
                self.shared_secret = self.kem.decapsulate(payload)
                return b""

            plaintext = decrypt(self.shared_secret, payload)

            if self.monitor is not None:
                for byte in plaintext:
                    result = self.monitor.update(byte)
                    if result["anomaly"] and not self._in_anomaly:
                        self._in_anomaly = True
                        if self.peer_public_key is not None:
                            from src.entropy_monitor.response import KeyRotationResponder
                            if self._responder is None:
                                self._responder = KeyRotationResponder()
                            rekey_ciphertext, new_secret = self._responder.respond(result, self.peer_public_key)
                            _send_framed(self.sock, MSG_TYPE_REKEY, rekey_ciphertext)
                            self.shared_secret = new_secret
                    elif not result["anomaly"]:
                        self._in_anomaly = False

            return plaintext
        except (socket.error, ConnectionError):
            self.connected = False
            return b""

    def close(self) -> None:
        if self.sock:
            self.sock.close()
        self.connected = False


class TunnelServer:
    def __init__(self, host: str, port: int, monitor_factory=None):
        self.host = host
        self.port = port
        self.listen_sock = None
        self.monitor_factory = monitor_factory

    def start(self) -> None:
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind((self.host, self.port))
        self.listen_sock.listen(5)

    def accept(self) -> "Tunnel":
        conn, addr = self.listen_sock.accept()
        peer_tunnel = Tunnel(host=addr[0], port=addr[1])
        peer_tunnel.sock = conn
        peer_tunnel.connected = True
        peer_tunnel._handshake_as_server()
        if self.monitor_factory is not None:
            peer_tunnel.monitor = self.monitor_factory()
        return peer_tunnel

    def stop(self) -> None:
        if self.listen_sock:
            self.listen_sock.close()
