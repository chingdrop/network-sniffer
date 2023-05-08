#! /usr/bin/env python

from scapy.all import sr, sr1, sniff, ARP, IP, TCP, Ether, ICMP, UDP, RandShort

class ScanOperator():

    def start_ACKscan(self, target):
        ans, unans = sr(IP(dst=target)/TCP(dport=[80,666],flags="A"))
        for s,r in ans:
            if s[TCP].dport == r[TCP].sport:
               print(f"Port {s[TCP].dport} is unfiltered.")

    def start_XMASscan(self, target):
        ans, unans = sr(IP(dst=target)/TCP(dport=666,flags="FPU"))
        for s,r in ans:
            if s[TCP].dport is not None:
                 print(f"{s[TCP].dport} is open.")

    def start_IPscan(self, target):
        ans, unans = sr(IP(dst=target,proto=(0,255))/"SCAPY",retry=2)
        ans.summary(lambda s,r: r.sprintf("%IP.proto% is listening."))

class PingOperator():

    def start_ARPping(self, target):
        ans, unans = sr(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target),timeout=2)
        ans.summary(lambda s,r: r.sprintf("%Ether.src% | %ARP.psrc%"))

    def start_ICMPping(self, range):
        ans, unans = sr(IP(dst=range)/ICMP())
        ans.summary(lambda s,r: r.sprintf("%IP.src% is alive"))

class DnsOperator():

    def start_resolveA(self, domain, server='8.8.8.8'):
        ans = sr1(IP(dst=server)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="A")))
        print(f'{domain} is {ans.an.rdata}.')

    def start_resolveSOA(self, domain, server='8.8.8.8'):
        ans = sr1(IP(dst=server)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="SOA")))
        print(f'Primary name server is {ans.an.mname}, contact at {ans.an.rname}')

    def start_resolveMX(self, domain, server='8.8.8.8'):
        ans = sr1(IP(dst=server)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="MX")))
        ret = [x.exchange for x in ans.an.iterpayloads()]
        for i in ret:
            print(f'MX {i}')

class WlanOperator():

    def start_WLANsniff(self, intf='wlan0'):
        sniff(iface=intf, \
        prn=lambda x:x.sprintf( \
        "{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%\t%PrismHeader.channel%\t%Dot11Beacon.cap%}"))
