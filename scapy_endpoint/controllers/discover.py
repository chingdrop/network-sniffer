from cement import Controller, ex
from scapy.all import sr, ARP, Ether, IP, ICMP

from commands.host_discovery import HostDiscovery
from commands.raspi_controller import RaspiController


class Discover(Controller):
    class Meta:
        label = 'discover'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='starts an ARP ping to discover live hosts',
        arguments=[
            (['iface'], 
             {'help': 'target interface',
              'action': 'store'})
        ],
    )
    def quick_discover(self):
        iface = self.app.pargs.iface
        network_ip = RaspiController.get_network_ip(iface)
        arp_list = HostDiscovery.arp_ping(str(network_ip))

    @ex(
        help='starts an ARP ping to discover live hosts',
        arguments=[
            (['iface'], 
             {'help': 'target interface',
              'action': 'store'})
        ],
    )
    def full_discover(self):
        iface = self.app.pargs.iface
        network_ip = RaspiController.get_network_ip(iface)
        arp_list = HostDiscovery.arp_ping(str(network_ip))
        icmp_list = HostDiscovery.icmp_ping(str(network_ip))
        tcp_list = HostDiscovery.tcp_ping(str(network_ip))
        udp_list = HostDiscovery.udp_ping(str(network_ip))
