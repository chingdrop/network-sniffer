import socket
import fcntl
import struct
from ipaddress import IPv4Network


def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't have to be reachable, error assigns localhost
        s.connect(("1.1.1.1", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_local_subnet(iface: str):
    return socket.inet_ntoa(
        fcntl.ioctl(
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
            35099,
            struct.pack(b"256s", iface.encode()),
        )[20:24]
    )


def get_network_ip(iface: str):
    ip = get_local_ip()
    subnet = get_local_subnet(iface)
    network = ip[: ip.rfind(".") + 1] + "0"
    return IPv4Network(network + "/" + subnet)
