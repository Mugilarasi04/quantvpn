import threading
from src.tunnel.utun import Utun


class TunnelForwarder:
    def __init__(self, tunnel, utun_device: Utun):
        self.tunnel = tunnel
        self.utun = utun_device
        self.running = False
        self._utun_to_tunnel_thread = None
        self._tunnel_to_utun_thread = None

    def _utun_to_tunnel_loop(self):
        while self.running:
            try:
                packet = self.utun.read_packet()
                if packet:
                    self.tunnel.send(packet)
            except Exception:
                break

    def _tunnel_to_utun_loop(self):
        while self.running:
            try:
                packet = self.tunnel.receive()
                if packet:
                    self.utun.write_packet(packet)
            except Exception:
                break

    def start(self):
        self.running = True
        self._utun_to_tunnel_thread = threading.Thread(target=self._utun_to_tunnel_loop, daemon=True)
        self._tunnel_to_utun_thread = threading.Thread(target=self._tunnel_to_utun_loop, daemon=True)
        self._utun_to_tunnel_thread.start()
        self._tunnel_to_utun_thread.start()

    def stop(self):
        self.running = False
