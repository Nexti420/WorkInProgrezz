# 🚧 WorkInProgrezz 🚧
<a href = "https://github.com/Nexti420/WorkInProgrezz/graphs/contributors"> 
<img src = "https://contrib.rocks/image?repo=Nexti420/WorkInProgrezz"/> 
</a> 
<img src="https://github-readme-stats.vercel.app/api/top-langs?username=Nexti420&show_icons=true&locale=en&layout=compact&theme=chartreuse-dark" alt="ovi" />

## 🚀 Development Repository
This is a development repository. The code is still in development and may be unstable.


This repository tracks the progress of implementing our new portal and backend infrastructure.


We are migrating old services to a new, containerized architecture (Docker) and integrating them with new monitoring tools (such as aws-monitor).

Our main goal is to fully deprecate the legacy monolithic backend by Q4. This repo serves as the central hub for all development related to "Project Onion" (our internal name for the new architecture). Please follow the branching strategy (feature/..., hotfix/...) and submit Pull Requests for review.

## ⚙️ Usage
To set up a new development environment, clone this repository and run the **initial_setup.sh** script as root. This script will provision the necessary services (Apache, FTP, Docker) and configure the users.

Note: This script is designed for fresh VM instances for testing. Do not run on production machines.

## 📝 HTML files
This directory contains the static front-end assets for the new portal.

**index.html**: The main landing page. (WIP)

**check/index.html**: Under development.

**status/index.html**: Service status dashboard.

## 🛥️ Docker
For security and stability reasons, direct access to the Docker socket is disabled. All Docker operations must be performed through the approved sudo wrappers. This is to prevent container escapes and ensure all containers are run with the correct, secure runtime options.

    Available Docker Commands:

    docker-history <image>     - Analyze image layers
    docker-inspect <image>     - Read image metadata
    docker-images              - List images
    docker-run <image> [args]  - Run containers (restricted)
## 🥷 SSH
All developers must use encrypted SSH keys. The command below shows the company-approved standard for key generation (ED25519 with a strong passphrase).

    Keys should be encrypted using passphrase:
    ssh-keygen -t ed25519 -f /toor/.ssh/toor_key -N "HasloDoOdszyfrowania123"
## 🔥 FTP
[TEMPORARY] - Using these shared credentials for testing purposes. This user is heavily sandboxed. Will be removed once the new file upload service is deployed.

    User: ftpuser
    Password: FtpUser123

