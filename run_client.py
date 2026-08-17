import sys
sys.path.insert(0, '.')

from src.tunnel.tunnel import Tunnel
from src.tunnel.utun import Utun
from src.tunnel.forwarder import TunnelForwarder


def main():
    server_host = input("Server host (localhost): ") or "localhost"

    print("Connecting to server...")
    tunnel = Tunnel(server_host, 9999)
    if not tunnel.connect():
        print("Failed to connect to server.")
        return
    print("Connected. Handshake complete, shared secret established.")

    utun = Utun()
    ifname = utun.open()
    print(f"Opened {ifname} — run in another terminal:")
    print(f"  sudo ifconfig {ifname} 10.10.10.2 10.10.10.1 up")

    forwarder = TunnelForwarder(tunnel, utun)
    forwarder.start()

    print("Forwarding active. Press Enter to stop.")
    input()

    forwarder.stop()
    utun.close()
    tunnel.close()


if __name__ == "__main__":
    main()
