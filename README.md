# DNSSH - DNS Shell

**DNSSH** (DNS Shell) is a specialized, interactive shell designed to bypass severely restricted networks where only DNS queries to public recursive resolvers are permitted. 

It provides interactive terminal access over DNS with minimal overhead by dropping the TCP/IP stack requirements and instead piping compressed, authenticated, and encrypted input/output directly through DNS queries and TXT records.

## 🌟 Architecture & Traffic Flow

The client encapsulates shell commands inside the DNS query labels, and the server returns the shell output encoded inside DNS response records.

```text
.---------.                 .-----------.               .--------.
| local   |                 | public    |               | remote |
| machine |<--- DoH/DoT --->| recursive |<---UDP DNS--->| server |
'---------'       ||        | resolver  |               '--------'
                  ||        '-----------'
               Firewall
```

## 🚀 Core Features

* **E2E Encryption & Authentication**: Uses `libsodium` (XChaCha20-Poly1305 + MAC) for security with a pre-shared 32-byte key.
* **Extreme Compression**: Utilizes `zlib` to compress terminal I/O, maximizing the effective payload per transmission.
* **Blackout Resilience**: Features 128-bit session IDs to keep the shell alive across resolver flips and outages. Built-in routing and fallback rotation for up to 10 public DNS resolvers.
* **Native Interactive PTY Shell**: Full raw TTY support including byte-by-byte command detection.
* **Privilege Dropping**: Operates in user-space. Native client doesn't need root. Server automatically drops root privileges to the restricted user as soon as port 53 is bound.
* **Automated CI/CD Deployment**: Includes a GitHub Action workflow to automatically build, setup systemd services, and deploy `dnssh-server` to a remote host.

## 🛠️ Build & Installation

**Dependencies:** `libsodium-dev`, `zlib1g-dev`, `make`, `gcc`

```bash
# Debian / Ubuntu (Install Dependencies)
sudo apt-get update && sudo apt-get install -y build-essential libsodium-dev zlib1g-dev

# Compile
make
```

The binaries will be placed in the `build/` directory:
- `build/dnssh` (Client)
- `build/dnssh-server` (Server)

## 📖 Usage

### 1. DNS Configuration
Point an `NS` record or a wildcard `A` record for your subdomain to the IP address of the machine running `dnssh-server`.  
*Example:* `t.example.com NS ns.example.com`

### 2. Start the Server
Run the server on your authoritative machine. It will automatically bind to UDP port 53.

```bash
sudo ./build/dnssh-server 53 tunnel.example.com [optional_64_char_hex_key]
```
*(If no hex key is provided, a secure one-time key is printed to the console for the current run).*

### 3. Connect via Client
Execute the client from the restricted network, providing your authoritative domain, the 64-character hex key, and a list of public recursive resolvers (e.g., 8.8.8.8, 1.1.1.1).

```bash
./build/dnssh tunnel.example.com <64_character_hex_key> 8.8.8.8 1.1.1.1 9.9.9.9
```

Once connected, you will be piped into a standard interactive `dnssh$` prompt.

## 📄 Documentation

For automated server deployments, please refer to the [Deployment Guide](docs/deployment.md).
