import socket
import fcntl
import struct
from ipaddress import IPv4Network

from cement import Controller, ex
from scapy.all import sr, sr1, srp, RandShort, ARP, Ether, hexdump, IP, ICMP, TCP


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

    def ack_scan(self, target, port=80):
        src_port = RandShort()

        try:
            resp = sr(IP(dst=target)/TCP(sport=src_port, dport=port,flags="A", seq=12345), timeout=3, verbose=0)
            if resp:
                if resp.getlayer(TCP).flags == 0x4:
                    res = False
                elif int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    res = True
            else:
                res = True
            return res
        
        except Exception as e:
            print(e)

    def xmas_scan(self, target, ports):
        open_ports = []
        filtered_ports = []
        src_port = RandShort()

        try:
            ans, unans = sr(IP(dst=target)/TCP(sport=src_port, dport=ports, flags="FPU"), timeout=5, verbose=0)
            if ans:
                for s,r in ans:
                    if r[TCP].flags == 0x14:
                        open_ports.append(s[TCP].dport)
                    elif r[ICMP].type == 3 and r[ICMP].code in [1,2,3,9,10,13]:
                        filtered_ports.append(s[TCP].dport)
            return open_ports, filtered_ports
        
        except Exception as e:
            print(e)

    def protocol_scan(self, target):
        open_protos = []

        try:
            ans, unans = sr(IP(dst=target, proto=[i for i in range(256)])/"SCAPY", timeout=3, verbose=0)
            if ans:
                for s,r in ans:
                    open_protos.append(r[IP].proto)
            return open_protos
        
        except Exception as e:
            print(e)
    

class Pings:

    def arp_ping(self, target):
        host_list = []
        # This definitely could be done better, but I don't want to nest try/excepts

        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3, verbose=0)
        except Exception as e:
            print(e)

        for s,r in ans:
            ip_addr = r[ARP].psrc

            try:
                hostname = socket.gethostbyaddr(ip_addr)[0]
            except socket.herror:
                hostname = ''

            host_list.append({
                "HOSTNAME": hostname,
                "MAC": r[Ether].dst,
                "IP": ip_addr
            })
        
        return host_list


class LANEnumeration(Controller):
    
    class Meta:
        label = 'lan_enumeration'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='enumerates possible targets on the detected LAN.',
        arguments=[
            (['iface'], 
             {'help': 'interface connected to LAN',
              'action': 'store'})
        ],
    )
    def quick_enumeration(self):
        iface = self.app.pargs.iface
        target_list = []
        scans = Scans()
        lan = LocalNetwork().get_network_ip(iface)

        live_hosts = Pings().arp_ping(str(lan))
        if live_hosts:
            for host in live_hosts:
                print(f'{host["MAC"]} : {host["IP"]} : {host["HOSTNAME"] or "No hostname record found"}')
        else:
            print(f'No active hosts found.')

        for host in live_hosts:
            print(f'\nBeginning port scan for {host["IP"]}!')

            print('\nACK Scan...')
            ack_port = scans.ack_scan(host["IP"])
            if ack_port:
                print('Filtered : Stateful firewall present')
            else:
                print('Unfiltered : No stateful firewall present')

            print('\nXmas Scan...')
            xmas_open, xmas_filtered = scans.xmas_scan(host["IP"], [i for i in range(1024)])
            if xmas_open:
                for port in xmas_open:
                    print(f'Port {port} is open')
            elif xmas_filtered:
                for port in xmas_filtered:
                    print(f'Port {port} is filtered')
            else:
                print('No open or filtered ports')

            print('\nProtocol Scan...')
            open_protos = scans.protocol_scan(host["IP"])
            if open_protos:
                for proto in open_protos:
                    print(f'Protocol {proto} is listening')
            else:
                print("No protocols are listening")

            if ack_port or xmas_open or open_protos:
                target_list.append(host)

        for target in target_list:
            print(f'{target["IP"]} : {target["MAC"]} could be a potential target')