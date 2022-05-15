#! /usr/bin/env python

from cement import App, Controller, ex
import re
from one_liners import *

class WifiAnalController(Controller):
	class Meta:
		label = 'WifiAnalController'


	@ex(help='starts network scan of a target IP address.')
	def start_scan(self):
		target = '172.20.105.49'

		scanOp = ScanOperator()
		scanOp.start_ACKscan(target)
		scanOp.start_XMASscan(target)
		scanOp.start_IPscan(target)

	@ex(help='starts network ping of a target IP address.')
	def start_ping(self):
		target = '172.20.105.49'

		pingOp = PingOperator()
		pingOp.start_ARPping(target)
		pingOp.start_ICMPping(range)

	@ex(help='starts name resolution of a target IP address.')
	def start_resolve(self):
		target = 'google.com'

		dnsop = DnsOperator()
		dnsop.start_resolveA(target)
		dnsop.start_resolveSOA(target)
		dnsop.start_resolveMX(target)

class WifiAnalApp(App):
	class Meta:
		label = 'WifiAnalController'
		handlers = [
			WifiAnalController,
		]

with WifiAnalApp() as app:
	app.run()
