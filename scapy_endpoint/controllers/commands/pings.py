import socket
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


class Pings:

    def arp_ping(self, target, verbose=True) -> list:
        host_list = []
        # This definitely could be done better, but I don't want to nest try/excepts
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3, verbose=0)
        except Exception as e:
            print(e)

        for s,r in ans:
            try:
                hostname = socket.gethostbyaddr(r[ARP].psrc)[0]
            except socket.herror:
                hostname = ''
            host_list.append({
                "HOSTNAME": hostname,
                "MAC": r[Ether].src,
                "IP": r[ARP].psrc})
        
        if verbose:
            message = '\n'.join(f'{host["MAC"]} : {host["IP"]} : {host["HOSTNAME"] or "No hostname record found"}' for host in host_list) \
                                if host_list else 'No active hosts found.'
            print(message)
        
        return host_list