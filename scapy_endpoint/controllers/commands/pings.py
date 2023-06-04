import socket
from scapy.all import srp, ARP, Ether


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