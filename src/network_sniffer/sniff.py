from scapy.all import sniff


class Sniff:

    def wlan_sniff(self, wlan_iface):
        try:
            sniff(
                iface=wlan_iface,
                prn=lambda x: x.sprintf(
                    "{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%\t%PrismHeader.channel%\t%Dot11Beacon.cap%}"
                ),
            )
        except Exception as e:
            print(e.message, e.args)
