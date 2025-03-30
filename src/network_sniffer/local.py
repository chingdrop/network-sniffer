import socket
import psutil
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
    
    s.close()
    return ip


def get_local_subnet(iface: str):
    for name, addrs in psutil.net_if_addrs().items():
        if name == iface:
            for addr in addrs:
                if addr.family == psutil.AF_INET:
                    ip_address = addr.address
                    netmask = addr.netmask
                    network = IPv4Network(f"{ip_address}/{netmask}", strict=False)
                    return str(network.network_address)


def get_network_ip(iface: str):
    ip = get_local_ip()
    subnet = get_local_subnet(iface)
    network = ip[: ip.rfind(".") + 1] + "0"
    return IPv4Network(network + "/" + subnet)
