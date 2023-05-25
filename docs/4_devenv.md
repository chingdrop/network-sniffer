# Development Environment

## Setting up Github SSH keys

An alternative is setting up key forwarding on your working PC's SSH agent.

1. Go to github.com and navigate to your account settings.
2. Go to the SSH keys section and add a new key.
3. Check your ssh id's public key.  
    `cat ~/.ssh/id_rsa.pub`
4. Copy the public key and paste it into github.
5. Configure the name and email for github.  
    `git config --global user.name "x"`  
    `git config --global user.email "x"`

**Note** - Make sure to enable SSH password use in order to open the directory in VS Code.
  
## Installing the Codebase

Pip packages must be installed in root in order to use socket commands.

1. Create the code directory.  
    `mkdir -p ~/code`
2. Go to the code directory and clone the repo.  
    `cd ~/code`  
    `git clone git@github.com:chingdrop/wifi_analyzer.git`
3. Install python package requirements.  
    `sudo pip install -r requirements.txt`  
    `sudo pip install .`
