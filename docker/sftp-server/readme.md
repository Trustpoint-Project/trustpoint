# SFTP Server (Docker)

This document explains how to build, start, and log in to a Docker-based SFTP server. Follow these instructions from within the `docker/sftp-server/` directory.

---

## Table of Contents

1. [Prerequisites](#prerequisites)  
2. [Directory Structure](#directory-structure)  
3. [Build Instructions](#build-instructions)  
4. [Run Instructions](#run-instructions)  
5. [Login Instructions](#login-instructions)  
6. [Known Hosts Warning](#known-hosts-warning)  
7. [Customization](#customization)  
8. [File Storage](#file-storage)  
9. [Common Commands](#common-commands)  

---

## Prerequisites

- **Docker Engine** (version 20.10 or newer recommended) installed on your host.  
- **SSH key pair** (public and private) to use key-based authentication.  
- Basic familiarity with `docker build`, `docker run`, and SSH/SFTP commands.  

---

## Directory Structure

Your project root (`docker/sftp-server/`) should contain:

docker/sftp-server/
├── dockerfile
├── readme.md
└── ssh
├── sftp_ssh ← private key (keep this file secure)
└── sftp_ssh.pub ← public key to be installed into the container

- **`dockerfile`** (lowercase) is the Dockerfile that builds the SFTP image.  
- **`ssh/sftp_ssh.pub`** is the public key that will be added to the container’s `authorized_keys`.  
- **`ssh/sftp_ssh`** is the matching private key (used locally to connect). Do not commit this file to any public repository.  
- **`readme.md`** (this file) contains all instructions.

---

## Build Instructions

1. Open a terminal and change into the `docker/sftp-server/` directory:

   ```bash
   cd docker/sftp-server
   ```

2. (Optional) You can override two build-time arguments:

    SFTP_USER – username inside the container (default: admin)

    UID – numeric user ID inside the container (default: 1001)

3. Run the build command. Use the -f flag to point to the lowercase dockerfile:
    ```bash
    docker build -t custom-sftp -f dockerfile .
    ```
    If you need to change the default user or UID, add --build-arg. For example:
    ```bash
    docker build \
    --build-arg SFTP_USER=youruser \
    --build-arg UID=2000 \
    -t custom-sftp \
    -f dockerfile .
    ```
4. After a successful build, you will have a Docker image named custom-sftp.

# Run Instructions
1. Create or choose a directory on the host where uploaded files will be stored. For example:
    ```bash
    mkdir -p /path/to/sftp-data
    ```

2. Start a new container from the custom-sftp image. Map host port 2222 to container port 22, and bind-mount the host directory to /home/admin/upload inside the container:

    ```bash
    docker run -d \
    --name my-sftp \
    -p 2222:22 \
    -v /path/to/sftp-data:/home/admin/upload \
    custom-sftp
    ```
    * -d runs the container in detached mode.
    * --name my-sftp gives the container the name my-sftp.
    * -p 2222:22 exposes container’s SSH port 22 on host port 2222.
    * -v /path/to/sftp-data:/home/admin/upload mounts the host directory into the container’s upload directory.

# Login Instructions
There are two supported authentication methods:

1. Key-Based Authentication

    The Dockerfile copies ssh/sftp_ssh.pub into /home/admin/.ssh/authorized_keys. To connect using the private key:

    ```bash
    sftp -i ssh/sftp_ssh -P 2222 admin@localhost
    ```
    * -i ssh/sftp_ssh points to your private key file on the host.
    * -P 2222 specifies the host port (which is forwarded to container’s port 22).
    * admin@localhost is the username (admin) and the host (localhost).

2. Password-Based Authentication

    A User admin with password testing321 and UID 1001 was created. To connect with a password instead of a key (NOT RECOMMENDED):
    ```bash
    sftp -P 2222 admin@localhost
    ```


# Known Hosts Warning
If you see a warning like:
```bash
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
```
it indicates that the server’s host key for port 2222 changed since your last connection. To remove the old entry, run:

```bash
ssh-keygen -f "~/.ssh/known_hosts" -R "[localhost]:2222"
```
