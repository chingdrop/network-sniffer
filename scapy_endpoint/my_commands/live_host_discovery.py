import socket
from scapy.all import ARP, Ether

from scapy_endpoint.my_commands.sr_controller import SRController


class LiveHostDiscovery:

    def get_my_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)

        try:
            # doesn't have to be reachable
            s.connect(('1.1.1.1', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()

        return ip

    def search_hosts(self):
        hosts_list = []
        ip = self.get_my_ip()
        network = ip[:ip.rfind('.')+1] + '0/24'

        ans, unans = SRController.layer_2_sr(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network))

        for s,r in ans:
            host = {
                "MAC": r[Ether].dst,
                "IP": r[ARP].psrc
            }
            hosts_list.append(host)

        return hosts_list