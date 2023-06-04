from scapy.all import sr, RandShort, ICMP, IP, TCP


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