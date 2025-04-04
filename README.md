# Network Sniffer

Repository: [network-sniffer - GitHub](https://github.com/chingdrop/network-sniffer)

Network Sniffer is an educational project designed to explore the practical applications of a computer network interface using Python.

## Scope

Network Sniffer will offer an interface for scanning and enumerating computer networks. This Python project will be installed on a Raspberry Pi, using a powerful wireless adapter to function as an endpoint on the network. This project leverages Scapy, a powerful framework for crafting, sending, and receiving network packets across various layers of the OSI model. The Click framework will be used to provide a command-line interface (CLI) for the custom Python functions.

## Process

Follow the instructions in [[RASPI]] (under `/docs`) for setting up the Raspberry Pi.

Work in Progress

## Materials

### Requirements

- **libpcap**: A Unix library for capturing network packets.
- **Scapy**: A Python library for crafting and manipulating network packets.
- **Click**: A Python package for creating command-line interfaces (CLI).
- **Celery**: An asynchronous task queue for handling background tasks.
  - **Redis**: Used as the message broker for Celery.
