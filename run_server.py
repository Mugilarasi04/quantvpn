import sys
sys.path.insert(0, '.')

from src.tunnel.tunnel import TunnelServer
from src.tunnel.utun import Utun
from src.tunnel.forwarder import TunnelForwarder
from src.entropy_monitor.entropy_monitor import EntropyMonitor


def make_monitor():
    return EntropyMonitor(window_size=50, threshold=0.5)


def main():
    print("Server waiting for client connection on port 9999...")
    server = TunnelServer('0.0.0.0', 9999, monitor_factory=make_monitor)
    server.start()

    peer_tunnel = server.accept()
    print("Client connected. Handshake complete, shared secret established.")

    utun = Utun()
    ifname = utun.open()
    print(f"Opened {ifname} — run in another terminal:")
    print(f"  sudo ifconfig {ifname} 10.10.10.1 10.10.10.2 up")

    forwarder = TunnelForwarder(peer_tunnel, utun)
    forwarder.start()

    print("Forwarding active. Press Enter to stop.")
    input()

    forwarder.stop()
    utun.close()
    peer_tunnel.close()
    server.stop()


if __name__ == "__main__":
    main()
