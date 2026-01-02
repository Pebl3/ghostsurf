# Vendored SOCKS plugins for ghostsurf
from lib.relay.servers.socksplugins.http import HTTPSocksRelay
from lib.relay.servers.socksplugins.https import HTTPSSocksRelay

# Register available SOCKS relay plugins
SOCKS_RELAYS = [HTTPSocksRelay, HTTPSSocksRelay]
