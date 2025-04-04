# Raspberry Pi Setup

## Ubuntu

### Creating Boot Media

[Raspberry Pi - Software](https://www.raspberrypi.com/software/)

1. Use a USB Micro SD card reader to access the storage of your Raspberry Pi.
2. Use Raspberry Pi Imager to flash the Micro SD card.
3. From Raspberry Pi Imager's menu, select Ubuntu Server 24.04 64-bit as the image.
4. Configure the Ubuntu install.
    1. Set the hostname.
    2. Add a new user and set the password.
    3. Configure the WLAN settings. (*optional*)
    4. Set Time zone and localization.
    5. Enable SSH access.
        1. Use password authentication.
        2. Add your public SSH key for access. (*optional*)
5. Flash Ubuntu Server to the Micro SD.
6. Eject the Micro SD card from your PC and plug it back into the Raspberry Pi.
7. Boot up the Raspberry Pi.

### First Steps

1. Upgrade the OS build.
    `sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove -y`
2. Install necessary packages.
    `sudo apt install -y curl git python3 python3-pip build-essential`
3. Perform a reboot of the system.
    `sudo shutdown -r now`
4. Create a downloads directory.
    ``

* * *

## SSH

### Secure Key Directory

1. Create a private directory for the SSH files.
    `mkdir -p ~/.ssh`
2. Enable all permissions for the owner of the directory.
    `sudo chmod 700 ~/.ssh/`
3. Enable read and write permissions for the owner of all files in the directory.
    `sudo chmod 600 ~/.ssh/*`
4. Recursively change the ownership of the directory to the current user.
    `sudo chown -R ${USER} ~/.ssh/`
5. Recursively change the group ownership of the directory to the current user.
    `sudo chgrp -R ${USER} ~/.ssh/`

### Creating New Keys

1. Use OpenSSH to create new keys.
    `ssh-keygen -t ed25519 -C <example@email.com>`
2. Choose the name of the key file.
3. Add a password to the creation of the private key.
4. Follow the steps in the below section.

### Configure OpenSSH

*Note - Password authentication must be enabled on OpenSSH for accessing Git.*

1. Edit the configuration file for OpenSSH.
    `nano /etc/ssh/sshd_config`
2. Use the code example below to copy settings to the file.
    1. Change the port as you wish.
3. Restart the OpenSSH service.
    `sudo systemctl restart ssh`

```ini
# Disable root login
# The root login is allowed by default. If you want to disable root login, set this to 'no'.
PermitRootLogin no

# Change default SSH port
# The default port is 22. You may wish to change it for security reasons.
Port 22

# Prevent empty passwords
# If set to 'yes', users with empty passwords will be allowed to log in.
PermitEmptyPasswords no

# Use SSH Protocol 2
# SSH Protocol 1 is outdated and should not be used. This option should always be set to '2'.
Protocol 2

# Timeout for idle sessions
# The server will disconnect idle sessions after this many seconds. 
# A value of '0' disables the feature.
ClientAliveInterval 300
ClientAliveCountMax 0

# Limit authentication attempts
# Set the maximum number of authentication attempts per connection.
MaxAuthTries 3

# Increase log verbosity
# LogLevel VERBOSE will log detailed information about authentication failures, useful for debugging.
LogLevel VERBOSE

# Disable TCP forwarding
# This option prevents users from forwarding ports or making other TCP connections through the SSH server.
AllowTcpForwarding no

# Use strong host keys
# The following lines define the host key files. These keys are used to identify the server.
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Enforce strong ciphers and algorithms
# You can specify which ciphers, MACs, and key exchange algorithms to use.
# These settings enforce stronger security standards.
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
```

* * *

## Git

### Configuring SSH keys

1. Go to [GitHub](https://github.com) and navigate to your account settings.
2. Go to the SSH keys section and add a new key.
3. Print the contents of the public key file to stdout.
    `cat ~/.ssh/id_ed25519.pub`
4. Copy and paste the public key into GitHub.
5. Save the new SSH key.

### Configuring the Repository

*Note - Pip packages must be installed in root in order to use socket commands.*

1. Create the code directory.
    `mkdir -p ~/code`
2. Go to the new directory and clone the repository.
    `cd ~/code`  
    `git clone git@github.com:chingdrop/wifi_analyzer.git`
3. Install required python packages.
    `sudo pip install -r requirements.txt && sudo pip install .`
4. Configure the user name and email for commits.
    `git config --global user.name "John Warhammer"`
    `git config --global user.email <example@email.com>`

* * *

## Docker

### Install Package

1. Use the code example below to add the base docker package repositories.
2. Install the newly added packages.
    `sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin`
3. Create the docker group.
    `sudo groupadd docker`
4. Add your user to the docker group.
    `sudo usermod -aG docker $USER`

``` bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
```

* * *

## Wireless Adapter

[RTL8812AU Linux Driver - GitHub](https://github.com/morrownr/8812au-20210820)

### Install Linux Driver

1. Install the dependent packages.
    `sudo apt-get install -y gcc make bc kernel-headers`
2. Install highly recommended packages.
    `sudo apt-get install -y dkms rfkill iw ip`
3. Clone the GitHub repository.
    `git clone https://github.com/morrownr/8812au-20210820.git`
4. Move to the newly created directory and execute the installation script.
    `cd 8812au-20210820 && ./install-driver.sh`
5. Respond to the command prompts and finalize installation.
