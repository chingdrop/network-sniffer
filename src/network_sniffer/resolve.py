from network_sniffer.packet import BroadcastAdapter, create_dns_pkt


bca = BroadcastAdapter()


def resolve_a_record(name_server, target_domain):
    pkt = create_dns_pkt(name_server, target_domain, qtype="A")
    ans = bca.send1(pkt, timeout=3, verbose=0)
    return ans.an.rdata


def resolve_soa_record(name_server, target_domain):
    pkt = create_dns_pkt(name_server, target_domain, qtype="SOA")
    ans = bca.send1(pkt, timeout=3, verbose=0)
    return ans.an.mname, ans.an.rname


def resolve_mx_record(name_server, target_domain):
    pkt = create_dns_pkt(name_server, target_domain, qtype="SOA")
    ans = bca.send1(pkt, timeout=3, verbose=0)
    return [x.exchange for x in ans.an.iterpayloads()]
