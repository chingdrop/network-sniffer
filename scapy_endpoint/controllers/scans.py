import socket
import fcntl
import struct
from ipaddress import IPv4Network

from cement import Controller, ex
from scapy.all import sr, srp, ARP, Ether, hexdump, IP, ICMP, TCP


class LocalNetwork:

    def get_local_ip(self):
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

    def get_local_subnet(self, iface):
        return socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack(b'256s', iface.encode()))[20:24])

    def get_network_ip(self, iface):
        ip = self.get_local_ip()
        subnet = self.get_local_subnet(iface)
        network = ip[:ip.rfind('.')+1] + '0'
        return IPv4Network(network + '/' + subnet)


class Scans:

    def ack_scan(self, target, ports):
        open_ports = [port for port in ports if not sr(IP(dst=target)/TCP(dport=port, flags="A"), timeout=5, verbose=0)[0].haslayer(ICMP)]
        if open_ports:
            print(f"{target}: {' '.join(map(str, open_ports))} is unfiltered.")
        else:
            print(f"{target} has no unfiltered ports.")
        return open_ports

    def xmas_scan(self, target, ports):
        open_ports = [port for port in ports if not sr(IP(dst=target)/TCP(dport=port, flags="FPU"), timeout=5, verbose=0)[0].haslayer(ICMP)]
        if open_ports:
            print(f"{target}: {' '.join(map(str, open_ports))} is open.")
        else:
            print(f"{target} has no open ports.")
        return open_ports

    def protocol_scan(self, target):
        open_protos = []
        ans, unans = sr(IP(dst=target,proto=[i for i in range(256)])/"SCAPY", timeout=3, verbose=0)
        ans.summary(lambda s,r: r.sprintf("%IP.src% : %IP.proto% is listening."))
        for s,r in ans:
            open_protos.append(r[IP].proto)
        if open_protos:
            print(f"{target}: {' '.join(map(str, open_protos))} is listening.")
        else:
            print(f"{target} has no protocols listening.")
        return open_protos


class Pings:
    def arp_ping(self, targets):
        host_list = [
            {
                "HOSTNAME": socket.gethostbyaddr(r[ARP].psrc)[0] if not isinstance(socket.gethostbyaddr(r[ARP].psrc)[0], socket.herror) else '',
                "MAC": r[Ether].dst,
                "IP": r[ARP].psrc
            }
            for target in targets
            for s,r in srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3, verbose=0)[0]
        ]
        for host in host_list:
            print(f'{host["MAC"]} : {host["IP"]} : {host["HOSTNAME"] or "No hostname record found"}')

        if not host_list:
            print(f'No active hosts found.')
        return host_list


class LANEnumeration(Controller):
    class Meta:
        label = 'lan_enumeration'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(help='Enumerates possible targets on the detected LAN.',
         arguments=[(['iface'], {'help': 'Interface connected to LAN.','action': 'store'})])
    def quick_enumeration(self):
        try:
            iface = self.app.pargs.iface
            target_list = []
            lan = LocalNetwork().get_network_ip(iface)
            live_hosts = Pings().arp_ping(str(lan))

            if not live_hosts:
                raise Exception('No live hosts found.')
            
            print(f'{len(live_hosts)} found, moving to scan the ports of the host.\n')

            scans = Scans()
            for host in live_hosts:
                ack_ports = scans.ack_scan(host["IP"])
                xmas_ports = scans.xmas_scan(host["IP"])
                proto_ports = scans.protocol_scan(host["IP"])

                if ack_ports or xmas_ports or proto_ports:
                    target_list.append(host)
                    print(f'{host["IP"]} : {host["MAC"]} could be a potential target.\n')
        except Exception as e:
            print(f"An error has occurred during LAN enumeration: {str(e)}")
            return []

        return target_list 
