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
    return raw[:4], raw[4:]

def write_packet(sock, packet: bytes, is_ipv6: bool = False):
    proto_header = struct.pack(">I", 0x1E if is_ipv6 else 0x02)
    sock.send(proto_header + packet)

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF

if __name__ == "__main__":
    sock, name = open_utun()
    print(f"Opened utun device: {name}")
    print(f"Now run in another terminal: sudo ifconfig {name} 10.10.10.1 10.10.10.2 up")
    print("Then try: ping 10.10.10.2")
    print("Listening... (Ctrl+C to stop)")

    try:
        while True:
            proto_header, packet = read_packet(sock)

            if len(packet) < 20:
                continue
            if (packet[0] >> 4) != 4:
                continue
            if packet[9] != 1:
                continue
            if packet[20] != 8:
                continue

            print(f"Got ICMP echo request, {len(packet)} bytes — building reply")

            reply = bytearray(packet)

            src_ip = reply[12:16]
            dst_ip = reply[16:20]
            reply[12:16] = dst_ip
            reply[16:20] = src_ip

            reply[20] = 0  # ICMP type 0 = echo reply

            reply[22:24] = b'\x00\x00'
            icmp_csum = checksum(bytes(reply[20:]))
            reply[22:24] = struct.pack(">H", icmp_csum)

            reply[10:12] = b'\x00\x00'
            ip_csum = checksum(bytes(reply[0:20]))
            reply[10:12] = struct.pack(">H", ip_csum)

            write_packet(sock, bytes(reply))
            print("Sent ICMP echo reply")

    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()
