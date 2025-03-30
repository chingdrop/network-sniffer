from network_sniffer.commands.local_network import LocalNetwork
from src.network_sniffer.pings import arp_ping, icmp_ping, tcp_ping, udp_ping


def quick_discover(iface):
    network_ip = LocalNetwork.get_network_ip(iface)
    arp_list = arp_ping(str(network_ip))


def full_discover(iface):
    network_ip = LocalNetwork.get_network_ip(iface)
    arp_list = arp_ping(str(network_ip))
    icmp_list = icmp_ping(str(network_ip))
    tcp_list = tcp_ping(str(network_ip))
    udp_list = udp_ping(str(network_ip))
