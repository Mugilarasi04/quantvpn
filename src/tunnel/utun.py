import socket
import struct
import ctypes
import fcntl

SYSPROTO_CONTROL = 2
AF_SYSTEM = 32
UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
CTLIOCGINFO = 0xC0644E03

PROTO_IPV4 = 0x02
PROTO_IPV6 = 0x1E


class ctl_info(ctypes.Structure):
    _fields_ = [("ctl_id", ctypes.c_uint32), ("ctl_name", ctypes.c_char * 96)]


class Utun:
    def __init__(self):
        self.sock = None
        self.name = None

    def open(self) -> str:
        self.sock = socket.socket(AF_SYSTEM, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
        info = ctl_info()
        info.ctl_name = UTUN_CONTROL_NAME
        fcntl.ioctl(self.sock.fileno(), CTLIOCGINFO, info)
        self.sock.connect((info.ctl_id, 0))
        raw_name = self.sock.getsockopt(SYSPROTO_CONTROL, 2, 128)
        self.name = raw_name.split(b'\x00', 1)[0].decode()
        return self.name

    def read_packet(self, buffer_size: int = 4096) -> bytes:
        raw = self.sock.recv(buffer_size)
        return raw[4:]

    def write_packet(self, packet: bytes, is_ipv6: bool = False) -> None:
        proto = PROTO_IPV6 if is_ipv6 else PROTO_IPV4
        proto_header = struct.pack(">I", proto)
        self.sock.send(proto_header + packet)

    def close(self) -> None:
        if self.sock:
            self.sock.close()
