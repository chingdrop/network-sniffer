from scapy.all import sr1, RandShort, DNS, DNSQR, IP, UDP


def resolve_a_record(target_domain, name_server):
    try:
        ans = sr1(
            IP(dst=name_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=target_domain, qtype="A"))
        )
    except Exception as e:
        print(e.message, e.args)

    print(f"{target_domain} is {ans.an.rdata}.")


def resolve_soa_record(target_domain, name_server):
    try:
        ans = sr1(
            IP(dst=name_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=target_domain, qtype="SOA"))
        )
    except Exception as e:
        print(e.message, e.args)

    print(f"Primary name server is {ans.an.mname}, contact at {ans.an.rname}")


def resolve_mx_record(target_domain, name_server):
    try:
        ans = sr1(
            IP(dst=name_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=target_domain, qtype="MX"))
        )
    except Exception as e:
        print(e.message, e.args)

    ret = [x.exchange for x in ans.an.iterpayloads()]
    for i in ret:
        print(f"MX {i}")
