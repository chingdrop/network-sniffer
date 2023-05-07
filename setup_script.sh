#!/bin/bash

sudo apt-get update -y && \
sudo apt-get upgrade -y && \

sudo apt install python python3-venv python3-pip network-manager net-tools wireless-tools tshark -y && \

sudo chmod +x /usr/bin/dumpcap && \

#python3 -m venv ~/wifi_analyzer && \
#source ~/wifi_analyzer/bin/activate && \

#pip install wheel cement scapy pyshark netifaces
