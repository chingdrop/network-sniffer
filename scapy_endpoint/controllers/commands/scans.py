from scapy.all import sr, sr1, RandShort, ICMP, IP, TCP


class Scans:

    def ack_scan(self, target, port=80):
        src_port = RandShort()
        try:
            ans = sr1(IP(dst=target)/TCP(sport=src_port, dport=port,flags="A", seq=12345), timeout=3, verbose=0)
            if ans:
                if ans.haslayer(TCP) and ans.getlayer(TCP).flags == 0x4:
                    res = False
                elif ans.haslayer(ICMP) and int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    res = True
            else:
                res = True

            if res:
                print('Filtered : Stateful firewall present')
            else:
                print('Unfiltered : No stateful firewall present')
            return res
        
        except Exception as e:
            print(e)

    def xmas_scan(self, target, ports):
        src_port = RandShort()
        try:
            ans, unans = sr(IP(dst=target)/TCP(sport=src_port, dport=ports, flags="FPU"), timeout=5, verbose=0)
            open_ports = [s[TCP].dport for s,r in ans if r.haslayer(TCP) and r[TCP].flags == 0x14]
            filtered_ports = [s[TCP].dport for s,r in ans if r.haslayer(ICMP) and r[ICMP].type == 3 and r[ICMP].code in [1, 2, 3, 9, 10, 13]]
            
            if open_ports:
                print('\n'.join(f'Port {port} is open' for port in open_ports))
            elif filtered_ports:
                print('\n'.join(f'Port {port} is filtered' for port in filtered_ports))
            else:
                print('No open or filtered ports')
            return open_ports, filtered_ports
        
        except Exception as e:
            print(e)

    def protocol_scan(self, target):
        try:
            ans, unans = sr(IP(dst=target, proto=[i for i in range(256)])/"SCAPY", timeout=3, verbose=0)
            open_protos = [s[IP].proto for s,r in ans]

            if open_protos:
                print('\n'.join(f'Protocol {proto} is listening' for proto in open_protos))
            else:
                print("No protocols are listening")
            return open_protos
        
        except Exception as e:
            print(e)