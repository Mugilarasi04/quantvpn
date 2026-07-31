class Tunnel:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.connected = False

    def connect(self) -> bool:
        self.connected = True
        return self.connected

    def send(self, data: bytes) -> bool:
        if not self.connected:
            raise ConnectionError("Tunnel is not connected")
        return True

    def receive(self) -> bytes:
        if not self.connected:
            raise ConnectionError("Tunnel is not connected")
        return b""

    def close(self) -> None:
        self.connected = False