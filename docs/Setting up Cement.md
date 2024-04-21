

## Creating the Cement Project
I created the cement project in a virtual environment on my working PC in WSL.  

1. Make a new virtual environment.  
    `mkvirtualenv scapy_endpoint`
2. Install cement using pip.  
    `pip install cement`
3. Create a directory and generate the cement project. There will be a few questions to initialize the project.  
    `mkdir -p ~/code/scapy_endpoint`  
    `cd ~/code/scapy_endpoint`  
    `cement generate project .`
4. Install the Scapy Python Package.  
    `pip install scapy`
5. Freeze pip and save to requirements.txt.  
    `pip freeze > requirements.txt`

## Starting the Git Repository
The repository will be cloned to the Raspi where most of the development will be done.

1. Go to github.com and create a new private repository.
2. Once created, click under the green **Code** button.
3. Collect the repository's SSH address. An example is:  
    `git@github.com:chingdrop/wifi_analyzer.git`
4. Go to the project directory and initialize a repository.  
    `cd ~/code/scapy_endpoint`  
    `git init`
5. Add the main remote branch to the repository.  
    `git remote add git@github.com:chingdrop/wifi_analyzer.git`
6. Fetch and pull the latest changes to the repository. (should be none)  
    `git fetch`  
    `git pull origin main`
7. Check the status of the working branch and add any changes to a new commit.  
    `git status`  
    `git add .`
8. Commit the new changes and push to GitHub.  
    `git commit -m "started cement project"`  
    `git push origin main`

* * *

## Links

- [Cement - Installation](https://docs.builtoncement.com/getting-started/installation)
- [Cement - Beginner Tutorial Part 1](https://docs.builtoncement.com/getting-started/beginner-tutorial/part-1-creating-your-first-project)