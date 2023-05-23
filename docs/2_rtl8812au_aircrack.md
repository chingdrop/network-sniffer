## Installing RTL8812AU Drivers and AirCrack
1. Install the prereq packages for RTL8812AU and aircrack.
	`sudo apt install -y dkms iw rfkill`
3. Create the src directory and clone the repo for the RTL8812AU driver.
	`mkdir -p ~/src`
	`cd ~/src`
	`git clone https://github.com/morrownr/8812au-20210629.git`
5. Go inside the src directory and run the install script.
	`cd ~/src/8812au-20210629`
	`sudo ./install-driver.sh`
7. Install the aircrack package.
	`sudo apt-get install -y aircrack-ng`
9. Create a service to automatically enable monitor mode for the USB.
	1. Change to the systemmd directory.
		`cd /etc/systemd/system/`
	3. Find the name of your new wireless adapter.
		`iwconfig`
	5. Create a new one-shot service to fire after the network manager. We are using Ubuntu 22.04 so that would be the dbus-fi.w1.wpa_supplicant1.service.
		`sudo nano wlan-promisc.service`
		```
		[Unit]
		Description=Makes wlan1 interface run in promiscuous mode at boot
		After=dbus-fi.w1.wpa_supplicant1.service

		[Service]
		Type=oneshot
		ExecStart=/usr/sbin/airmon-ng check kill
		ExecStart=/usr/sbin/airmon-ng start wlx00c0caaff82e
		TimeoutStartSec=0
		RemainAfterExit=yes

		[Install]
		WantedBy=default.target
		```
	7. Enable your new wireless monitor service.
		`sudo systemctl enable wlan-promisc.service`
11. Reboot your Raspi. Once it is back online, check to see if the adapter is in monitor mode.
	`sudo reboot`
	`iwconfig`
