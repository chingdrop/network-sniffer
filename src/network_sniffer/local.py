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


def get_lan_info(iface: str):
    for name, addrs in psutil.net_if_addrs().items():
        if name == iface:
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    address = addr.address
                    netmask = addr.netmask
                    network = IPv4Network(f"{address}/{netmask}", strict=False)
                    res = {
                        "address": address,
                        "netmask": netmask,
                        "network": network.compressed,
                        "hosts": list(network.hosts()),
                    }
                    return res
