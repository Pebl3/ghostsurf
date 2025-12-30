# IIS Kernel Auth Relay

NTLM Relay tool specifically designed for attacking IIS servers with kernel mode authentication enabled (HTTP.sys).

## Features

- **IIS Kernel Mode Auth Workaround**: Try-and-fallback approach that probes targets anonymously first to avoid resetting the NTLM auth context
- **Session Picker HTML UI**: Interactive selection when multiple relayed sessions are available
- **Thread-Safe Socket Locking**: Supports concurrent browser proxy sessions
- **Keep-Alive Fixes**: Raw socket operations to preserve NTLM session binding

## Installation

```bash
./setup.sh
```

This creates a virtual environment and installs impacket from PyPI.

## Usage

Basic usage with SOCKS proxy and kernel auth:

```bash
./run.sh -t https://target-iis-server/ -socks --kernel-auth
```

### Key Options

| Option | Description |
|--------|-------------|
| `-t TARGET` | Target URL to relay to |
| `-socks` | Enable SOCKS proxy for relayed connections |
| `--kernel-auth` | Enable IIS kernel mode auth workaround |
| `-debug` | Verbose output |

### Example Attack Flow

1. Start the relay with kernel auth enabled:
   ```bash
   ./run.sh -t https://iis.target.local/ -socks --kernel-auth -debug
   ```

2. Configure browser to use SOCKS proxy at `127.0.0.1:1080`

3. Trigger NTLM authentication (e.g., via coerced auth, phishing link)

4. When session is captured, browse to target through proxy

5. If multiple sessions available, session picker UI appears

## How Kernel Auth Workaround Works

IIS with kernel mode authentication binds the NTLM context to the TCP connection at the kernel level (HTTP.sys). This means:

1. Standard relay approaches fail because anonymous requests reset the auth context
2. Our workaround probes the target path anonymously FIRST with a fresh connection
3. If path requires auth (401), we use the relayed session on a separate connection
4. If path is anonymous (200), we return the response directly

This preserves the NTLM session for authenticated requests while still supporting anonymous endpoints.

## Credits

Based on [impacket](https://github.com/fortra/impacket) ntlmrelayx by:
- Fortra, LLC
- Dirk-jan Mollema / Fox-IT
- Alberto Solino

Kernel mode auth research and implementation by the tool author.
