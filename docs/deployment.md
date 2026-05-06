# Deployment Guide

This project is configured with a GitHub Actions workflow that automatically builds and deploys the `dnssh-server` to your remote server via SSH when changes are pushed to the `main` branch.

## Prerequisites

To enable deployment, you need to configure specific Repository Secrets in your GitHub repository. The workflow handles different authentication methods automatically depending on which secrets you provide.

### Required Setting to Enable Deployment

*   `DEPLOY_FLAG`: Must be set to `true` or `1`. If this secret is not set, or set to anything else, the deployment job will be skipped.

### Server Connection Secrets

You must provide the connection details for your remote server:

*   `SSH_HOST`: The IP address or domain name of your target server.
*   `SSH_USERNAME`: The SSH user responsible for deployment (e.g., `root` or a user with `sudo` privileges).
*   `SSH_PORT`: (Optional) The SSH port, defaults to `22` if not provided.

### Authentication Secrets

You can authenticate using a password, an SSH key, or an SSH key with a passphrase. Provide the relevant secrets for your chosen method:

**Option 1: Password Authentication**
*   `SSH_PASSWORD`: The password for the SSH user.

**Option 2: SSH Key Authentication**
*   `SSH_KEY`: The private SSH key (e.g., the contents of your `id_rsa` or `id_ed25519` file).

**Option 3: SSH Key with Passphrase**
*   `SSH_KEY`: The private SSH key.
*   `SSH_PASSPHRASE`: The passphrase for the provided SSH key.

### Application Configuration Secrets

These secrets define the runtime configuration of your `dnssh-server`:

*   `DEPLOY_DOMAIN`: (Required) The base domain used for DNS tunneling (e.g., `d.dnstt.bond`).
*   `DEPLOY_KEY`: (Required) A 64-character hexadecimal pre-shared key used for payload encryption.
*   `DEPLOY_PORT`: (Optional) The UDP listen port for the DNS server. Defaults to `53`.
*   `DEPLOY_DIR`: (Optional) The target installation directory on the server. Defaults to `/opt/dnssh`.

## Deployment Process

When the workflow is triggered and `DEPLOY_FLAG` is true, the following steps happen:

1.  **Code Transfer**: Source files (`dnssh.c`, `makefile`, and `dnssh-server.service`) are securely copied from the GitHub runner to a temporary build directory (`/opt/dnssh-build`) on the server.
2.  **Dependencies Installation**: The script automatically checks for and installs missing dependencies (`build-essential`, `libsodium-dev`, `zlib1g-dev`) via `apt-get`.
3.  **Build**: The application is compiled directly on the server by running `make clean` and `make`.
4.  **Installation**: The newly compiled `dnssh-server` binary is moved to the target installation directory (specified by `DEPLOY_DIR`).
5.  **Service Setup**: The systemd service file is dynamically updated with your `DEPLOY_DOMAIN`, `DEPLOY_KEY`, `DEPLOY_PORT`, and directory path, then written to `/etc/systemd/system/dnssh-server.service`.
6.  **Service Restart**: The systemd daemon is reloaded, and the `dnssh-server` service is unmasked, enabled, and restarted to apply the new configuration.
7.  **Cleanup**: The temporary source code build directory (`/opt/dnssh-build`) is deleted, leaving only the compiled binary and the systemd configuration on the server.
