# Raspi

## Creating Boot Media for Raspi

1. Take your Micro SD card and plug it into your working PC.
2. Use the Raspi image writer to create the boot media for the Raspi.
3. Select Ubuntu Server 22.04 64-bit as the image.
4. In the options, set your SSH public key to log in.
5. Write the image to the Micro SD.
6. Eject it from your working PC and plug it into the Raspi.
7. Boot up the Raspi and wait a few seconds before trying to SSH into the device.
  
## Ubuntu First Steps for Raspi

1. Update and Upgrade for the fresh OS install.  
    `sudo apt update && sudo apt dist-upgrade -y`
2. Set the proper permission for the SSH folder.  
    `mkdir -p ~/.ssh`  
    `sudo chmod 700 ~/.ssh/`  
    `sudo chmod 600 ~/.ssh/*`  
    `sudo chown -R ${USER} ~/.ssh/`  
    `sudo chgrp -R ${USER} ~/.ssh/`
3. Create a new SSH key for the Raspi. Follow the instructions and tie the credentials with a password.  
    `ssh-keygen -t rsa -b 4096`
4. Install the basic network utility packages.  
    `sudo apt install -y net-tools dnsutils git python3 python3-pip build-essential wireless-tools`
