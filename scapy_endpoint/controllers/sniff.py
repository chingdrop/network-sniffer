from cement import Controller, ex
from scapy.all import sniff


class Sniff(Controller):
    class Meta:
        label = 'sniff'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='starts sniffing on the specified interface.',
        arguments=[
            (['wlan_interface'], 
             {'help': 'wlan interface',
              'action': 'sniff'})
        ],
    )
    def wlan_sniff(self):
        interface = self.app.pargs.wlan_interface
        sniff(iface=interface, \
        prn=lambda x:x.sprintf( \
        "{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%\t%PrismHeader.channel%\t%Dot11Beacon.cap%}"))