from ipaddress import IPv4Address, IPv4Network
from scapy.all import ARP, Ether, IP, ICMP, TCP, UDP

from scapy_endpoint.my_commands.sr_controller import SRController
from scapy_endpoint.my_commands.raspi_controller import RaspiController


class HostDiscovery:

    def __init__(self) -> None:
        ip = RaspiController.get_local_ip()
        self.local_ip = IPv4Address(ip)

        network = ip[:ip.rfind('.')+1] + '0'
        subnet = RaspiController.get_local_subnet()
        self.network_ip = IPv4Network(network + '/' + subnet)