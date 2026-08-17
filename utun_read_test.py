import socket
import struct
import ctypes
import fcntl

SYSPROTO_CONTROL = 2
AF_SYSTEM = 32
UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
CTLIOCGINFO = 0xC0644E03

class ctl_info(ctypes.Structure):
    _fields_ = [("ctl_id", ctypes.c_uint32), ("ctl_name", ctypes.c_char * 96)]

def open_utun():
    sock = socket.socket(AF_SYSTEM, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
    info = ctl_info()
    info.ctl_name = UTUN_CONTROL_NAME
    fcntl.ioctl(sock.fileno(), CTLIOCGINFO, info)
    sock.connect((info.ctl_id, 0))
    ifname = sock.getsockopt(SYSPROTO_CONTROL, 2, 128)
    ifname = ifname.split(b'\x00', 1)[0].decode()
    return sock, ifname

def read_packet(sock):
    raw = sock.recv(4096)
    proto_header = raw[:4]
    packet = raw[4:]
    return proto_header, packet

if __name__ == "__main__":
    sock, name = open_utun()
    print(f"Opened utun device: {name}")
    print(f"Now run in another terminal: sudo ifconfig {name} 10.10.10.1 10.10.10.2 up")
    print("Then try: ping 10.10.10.2")
    print("Listening for packets... (Ctrl+C to stop)")

    try:
        while True:
            proto_header, packet = read_packet(sock)
            print(f"Got packet: {len(packet)} bytes, proto_header={proto_header.hex()}")
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()
