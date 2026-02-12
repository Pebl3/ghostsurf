# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Socks Proxy for the HTTPS Protocol
#
#   A simple SOCKS server that proxies a connection to relayed HTTPS connections
#
# Author:
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#   senderend - inherits kernel-mode auth workaround from http.py, thread-safe socket locking for browser req serialization
#
from impacket import LOG
from lib.relay.servers.socksplugins.http import HTTPSocksRelay
from lib.relay.utils.ssl import SSLServerMixin
from OpenSSL import SSL

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "HTTPSSocksRelay"
EOL = '\r\n'

class HTTPSSocksRelay(SSLServerMixin, HTTPSocksRelay):
    PLUGIN_NAME = 'HTTPS Socks Plugin'
    PLUGIN_SCHEME = 'HTTPS'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        HTTPSocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)

    @staticmethod
    def getProtocolPort():
        return 443

    def skipAuthentication(self):
        LOG.debug('Wrapping client connection in TLS/SSL')
        self.wrapClientConnection()
        if not HTTPSocksRelay.skipAuthentication(self):
            # Shut down TLS connection
            self.socksSocket.shutdown()
            return False
        return True

    def tunnelConnection(self):
        # Get the socket lock for this session
        try:
            socketLock = self.activeRelays[self.username]['socketLock']
        except KeyError:
            LOG.error('HTTPS: Socket lock not found for %s in tunnel' % self.username)
            return

        buffer = b''
        while True:
            try:
                data = self.socksSocket.recv(self.packetSize)
                if not data:
                    LOG.debug('HTTPS: Client closed connection')
                    return
                
                buffer += data

                # Check if we have a complete header block
                if b'\r\n\r\n' not in buffer:
                    # Keep reading
                    continue

                # Check for WebSocket upgrade requests in tunnel mode
                try:
                    headers = self.getHeaders(buffer)
                    if headers.get('upgrade', '').lower() == 'websocket':
                        LOG.debug('HTTPS: WebSocket upgrade in tunnel - rejecting')
                        response = b'HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\nWebSocket not supported'
                        try:
                            self.socksSocket.send(response)
                        except Exception:
                            pass
                        return
                except Exception:
                    # Continue with normal processing if header parsing fails
                    pass

                # Process request with kernel-mode auth probe logic (inherited from parent)
                self._processRequestWithProbe(buffer, socketLock, protocol='HTTPS')
                
                # Reset buffer after processing a full request-response cycle
                buffer = b''

            except SSL.ZeroReturnError:
                # The SSL connection was closed, return
                LOG.debug('HTTPS: SSL connection closed by client')
                return
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                LOG.debug('HTTPS: Connection error in tunnel: %s' % str(e))
                return
            except Exception as e:
                LOG.debug('HTTPS: Unexpected error in tunnel: %s' % str(e))
                return
