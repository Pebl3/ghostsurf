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
#   Socks Proxy for the HTTP Protocol
#
#  A simple SOCKS server that proxies a connection to relayed HTTP connections
#
# Author:
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
import base64

from impacket import LOG
from lib.relay.servers.socksserver import SocksRelay

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "HTTPSocksRelay"
EOL = b'\r\n'

# === DEBUG FLAG: Set to True to enable verbose auth debugging ===
# REMOVE THIS BLOCK AFTER DEBUGGING
HTTP_AUTH_DEBUG = True
def _dbg(msg):
    if HTTP_AUTH_DEBUG:
        LOG.info('[HTTP-DBG] %s' % msg)
# === END DEBUG FLAG ===

class HTTPSocksRelay(SocksRelay):
    PLUGIN_NAME = 'HTTP Socks Plugin'
    PLUGIN_SCHEME = 'HTTP'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.packetSize = 8192
        self.relaySocket = None
        self.session = None

    @staticmethod
    def getProtocolPort():
        return 80

    def initConnection(self):
        pass
        
    def isConnectionAlive(self):
        """Check if the relay connection is still alive"""
        if not self.relaySocket or not self.session:
            return False
        try:
            # For HTTPS connections, use simple socket check
            from http.client import HTTPSConnection
            if isinstance(self.session, HTTPSConnection):
                return hasattr(self.session, 'sock') and self.session.sock is not None
            else:
                # Original logic for HTTP - try to peek at the socket without consuming data
                import socket
                self.relaySocket.settimeout(0.1)
                self.relaySocket.recv(1, socket.MSG_PEEK)
                self.relaySocket.settimeout(None)
                return True
        except (socket.timeout, socket.error, OSError):
            return True  # Assume alive if we can't determine
        except Exception:
            return False

    def skipAuthentication(self):
        # See if the user provided authentication
        try:
            data = self.socksSocket.recv(self.packetSize)
            if not data:
                LOG.debug('HTTP: No data received from client')
                return False
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            LOG.debug('HTTP: Client connection error: %s' % str(e))
            return False

        # Check if this is a session selection request
        try:
            request_line = data.split(EOL)[0].decode("ascii")
            LOG.info('HTTP: [DIAGNOSTIC] skipAuthentication called for: %s' % request_line)
        except (UnicodeDecodeError, IndexError):
            LOG.debug('HTTP: Invalid request format')
            return False
            
        # Check for WebSocket upgrade requests and reject them
        headers = self.getHeaders(data)
        if headers.get('upgrade', '').lower() == 'websocket':
            LOG.debug('HTTP: WebSocket upgrade request detected - rejecting')
            response = b'HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nWebSocket not supported'
            try:
                self.socksSocket.send(response)
            except:
                pass
            return False
            
        if '?session=' in request_line:
            # Extract the original path and session parameter
            path_with_params = request_line.split(' ')[1]  # GET /path?session=user HTTP/1.1
            original_path = path_with_params.split('?')[0]  # /path
            session_param = request_line.split('?session=')[1].split(' ')[0]
            
            # URL decode
            import urllib.parse
            selected_session = urllib.parse.unquote(session_param).upper()
            
            # Check if this session exists
            if selected_session in self.activeRelays:
                self.username = selected_session
                LOG.info('HTTP: Session selected via form: %s@%s(%s)' % (
                    self.username, self.targetHost, self.targetPort))
                self.session = self.activeRelays[self.username]['protocolClient'].session
                
                # Point our socket to the sock attribute of HTTPConnection
                self.relaySocket = self.session.sock
                LOG.info('HTTP: Request for %s using relaySocket ID: %s' % (original_path, id(self.relaySocket)))
                
                # Check if connection is still alive
                if not self.isConnectionAlive():
                    LOG.error('HTTP: Relay connection is dead for session %s' % selected_session)
                    return False
                    
                # Create a clean request to the original path without the parameter
                clean_request = ('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n' % (original_path, self.targetHost)).encode()
                # Send the request to the server
                try:
                    self.relaySocket.send(clean_request)
                    # Send the response back to the client
                    self.transferResponse()
                    return True
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    LOG.error('HTTP: Failed to send request for session %s: %s' % (selected_session, str(e)))
                    return False
            else:
                # Invalid session, show picker again  
                LOG.error('HTTP: Invalid session selected: %s' % selected_session)
        
        # Get headers from data
        headerDict = self.getHeaders(data)
        try:
            creds = headerDict['authorization']
            if 'Basic' not in creds:
                raise KeyError()
            basicAuth = base64.b64decode(creds[6:]).decode("ascii")
            self.username = basicAuth.split(':')[0].upper()
            if '@' in self.username:
                # Workaround for clients which specify users with the full FQDN
                # such as ruler
                user, domain = self.username.split('@', 1)
                # Currently we only use the first part of the FQDN
                # this might break stuff on tools that do use an FQDN
                # where the domain NETBIOS name is not equal to the part
                # before the first .
                self.username = '%s/%s' % (domain.split('.')[0], user)

            # Check if we have a connection for the user
            if self.username in self.activeRelays:
                # HTTP is stateless - disable inUse check to allow concurrent browser sessions
                # IIS handles session persistence server-side via cookies
                # if self.activeRelays[self.username]['inUse'] is True:
                #     LOG.error('HTTP: Connection for %s@%s(%s) is being used at the moment!' % (
                #         self.username, self.targetHost, self.targetPort))
                #     return False
                # else:
                LOG.info('HTTP: Proxying client session for %s@%s(%s)' % (
                    self.username, self.targetHost, self.targetPort))
                self.session = self.activeRelays[self.username]['protocolClient'].session
            else:
                LOG.error('HTTP: No session for %s@%s(%s) available' % (
                    self.username, self.targetHost, self.targetPort))
                return False

        except KeyError:
            # User didn't provide authentication, check available sessions
            LOG.debug('No authentication provided, checking available sessions')
            
            # Find available sessions for this target
            available_users = []
            for user in self.activeRelays.keys():
                # HTTP allows concurrent sessions - ignore inUse flag (likely inherited from other stateful protocols)
                if user not in ['data', 'scheme']: # and not self.activeRelays[user]['inUse']:
                    available_users.append(user)
            
            if len(available_users) == 0:
                # No available sessions, return error
                LOG.error('HTTP: No available sessions for %s(%s)' % (self.targetHost, self.targetPort))
                reply = [b'HTTP/1.1 503 Service Unavailable',b'Connection: close',b'',b'No relayed sessions available for this target']
                self.socksSocket.send(EOL.join(reply))
                return False
            elif len(available_users) == 1:
                # Only one session, auto-select it
                self.username = available_users[0]
                LOG.info('HTTP: Auto-selecting single session for %s@%s(%s)' % (
                    self.username, self.targetHost, self.targetPort))
                self.session = self.activeRelays[self.username]['protocolClient'].session

                # Point our socket to the sock attribute of HTTPConnection
                self.relaySocket = self.session.sock
            else:
                # Multiple sessions, show selection page
                LOG.info('HTTP: Multiple sessions available, showing selection page')
                self.showSessionSelection(available_users)
                return False

        # When we are here, we have a session
        # Point our socket to the sock attribute of HTTPConnection
        # (contained in the session), which contains the socket
        self.relaySocket = self.session.sock

        # Get the socket lock to prevent concurrent access from multiple threads
        try:
            socketLock = self.activeRelays[self.username]['socketLock']
        except KeyError:
            LOG.error('HTTP: Socket lock not found for %s' % self.username)
            return False

        # Check if connection is still alive
        if not self.isConnectionAlive():
            LOG.error('HTTP: Relay connection is dead for session %s' % self.username)
            return False

        # Send the initial request to the server
        try:
            # Kernel auth workaround: check if we should route through anonymous connection
            use_anon = False
            LOG.info('HTTP: [DIAGNOSTIC] Starting skipAuthentication probe logic check')
            probe_check = self.shouldProbeAnonymous()
            LOG.info('HTTP: [DIAGNOSTIC] shouldProbeAnonymous returned: %s' % probe_check)
            if probe_check:
                path = self.extractRequestPath(data)
                LOG.info('HTTP: [DIAGNOSTIC] Extracted path: %s' % path)
                if path:
                    relayClient = self.activeRelays[self.username]['protocolClient']
                    needs_auth, status = relayClient.probePathAnonymous(path)

                    if not needs_auth:
                        # This path doesn't require auth - use anonymous connection to avoid
                        # resetting kernel auth context on the authenticated relay
                        use_anon = True
                        LOG.info('HTTP: Routing %s through anonymous connection (avoids kernel auth reset)' % path)
                    else:
                        LOG.debug('HTTP: Path %s requires auth, using authenticated relay' % path)

            if use_anon:
                # Send through anonymous connection to avoid resetting kernel auth context
                relayClient = self.activeRelays[self.username]['protocolClient']
                anonConn = relayClient.getAnonConnection()

                # Ensure socket exists - connect() creates it if needed
                if not anonConn.sock:
                    try:
                        anonConn.connect()
                    except Exception as e:
                        LOG.error('HTTP: Failed to establish anonymous connection: %s' % str(e))
                        return False

                # Send through anonymous socket using same flow as authenticated relay
                tosend = self.prepareRequest(data)
                self.relaySocket = anonConn.sock  # Point to anon socket for transferResponse()
                anonConn.sock.send(tosend)
                self.transferResponse()  # Reuse existing response transfer logic
            else:
                # Use lock to prevent concurrent socket access from multiple threads
                # Only one thread can send/receive at a time to prevent socket state corruption
                import threading
                with socketLock:
                    tosend = self.prepareRequest(data)
                    self.relaySocket.send(tosend)
                    # Send the response back to the client
                    self.transferResponse()
            return True
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            LOG.error('HTTP: Failed to send initial request for session %s: %s' % (self.username, str(e)))
            return False
    def showSessionSelection(self, available_users):
        """Show HTML page with available session choices that generate Basic Auth headers"""
        
        # Build HTML page with session options
        html = """<!DOCTYPE html>
<html>
<head>
    <title>ntlmrelayx - Select Session</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { color: #333; margin-bottom: 20px; }
        .session { padding: 15px; margin: 10px 0; border: 2px solid #ddd; border-radius: 5px; cursor: pointer; transition: all 0.3s; }
        .session:hover { background-color: #f0f8ff; border-color: #4CAF50; }
        .username { font-weight: bold; font-size: 16px; color: #2c3e50; }
        .admin { font-size: 14px; color: #666; margin-top: 5px; }
        .admin.true { color: #e74c3c; font-weight: bold; }
        .info { color: #666; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Select Relayed Session</h2>
        <div class="info">Multiple sessions available for <strong>%s:%s</strong><br>
        Click a session to proceed with those credentials:</div>
""" % (self.targetHost, self.targetPort)
        
        # Add each available session as a form
        for user in available_users:
            admin_status = self.activeRelays[user].get('isAdmin', 'N/A')
            admin_class = 'true' if admin_status == True else 'false'
            html += '''
        <form method="GET" action="" style="margin: 0;">
            <input type="hidden" name="session" value="%s">
            <div class="session" onclick="this.parentNode.submit()" style="cursor: pointer;">
                <div class="username">%s</div>
                <div class="admin %s">Admin privileges: %s</div>
            </div>
        </form>''' % (user, user, admin_class, admin_status)
        
        html += """
    </div>
</body>
</html>"""
        
        # Send HTTP response with session selection page
        response_body = html.encode('utf-8')
        response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(response_body)
        
        self.socksSocket.send(response + response_body)

    def getHeaders(self, data):
        # Get the headers from the request, ignore first "header"
        # since this is the HTTP method, identifier, version
        headerSize = data.find(EOL+EOL)
        headers = data[:headerSize].split(EOL)[1:]
        headerDict = {}
        for header in headers:
            try:
                hdrKey = header.decode("ascii")
                if ':' in hdrKey:
                    parts = hdrKey.split(':', 1)
                    if len(parts) == 2:
                        headerDict[parts[0].lower()] = parts[1][1:]  # Remove leading space
            except UnicodeDecodeError:
                # Skip headers with non-ASCII characters
                continue
        return headerDict

    def transferResponse(self):
        try:
            data = self.relaySocket.recv(self.packetSize)
            if not data:
                LOG.debug('HTTP: No data received from relay socket - connection may be closed')
                return

            # === DEBUG: Log response details ===
            try:
                status_line = data.split(b'\r\n')[0].decode('utf-8', errors='replace')
                _dbg('<<< RESPONSE: %s' % status_line)

                # Log key headers for ALL responses
                headers = self.getHeaders(data)
                if 'www-authenticate' in headers:
                    _dbg('<<< WWW-Authenticate: %s' % headers['www-authenticate'])
                if 'set-cookie' in headers:
                    _dbg('<<< Set-Cookie: %s' % headers['set-cookie'])

                # Check for 401 Unauthorized or 400 Bad Request
                if ' 401 ' in status_line or ' 400 ' in status_line:
                    headerSize = data.find(EOL+EOL)
                    if headerSize != -1:
                        try:
                            resp_headers = data[:headerSize].decode('utf-8', errors='replace')
                            LOG.info('HTTP: Error Response Headers (%s):\n%s' % (status_line.strip(), resp_headers))
                        except:
                            pass
            except:
                pass
            # === END DEBUG ===

            headerSize = data.find(EOL+EOL)
            if headerSize == -1:
                LOG.debug('HTTP: No complete headers found in response')
                self.socksSocket.send(data)
                return

            headers = self.getHeaders(data)
            content_length = headers.get('content-length', 'none')
            transfer_encoding = headers.get('transfer-encoding', 'none')

            try:
                bodySize = int(headers.get('content-length', 0))
                if bodySize > 0:
                    readSize = len(data)
                    expectedTotal = bodySize + headerSize + 4

                    # Make sure we send the entire response, but don't keep it in memory
                    self.socksSocket.send(data)
                    while readSize < expectedTotal:
                        try:
                            data = self.relaySocket.recv(self.packetSize)
                            if not data:
                                LOG.debug('HTTP: Connection closed while reading body (read %d of %d)' % (readSize, expectedTotal))
                                break
                            readSize += len(data)
                            self.socksSocket.send(data)
                        except (ConnectionResetError, BrokenPipeError, OSError) as e:
                            LOG.debug('HTTP: Connection error while reading response body: %s' % str(e))
                            break
                    LOG.debug('HTTP: Finished reading response - read %d of %d expected bytes' % (readSize, expectedTotal))
                else:
                    # No content-length, check for chunked encoding
                    if headers.get('transfer-encoding', '').lower() == 'chunked':
                        # Chunked transfer-encoding
                        self.transferChunked(data, headers)
                    else:
                        # No body in the response, send as-is
                        self.socksSocket.send(data)
            except (ValueError, KeyError):
                # Error parsing content-length or other header issues
                self.socksSocket.send(data)
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            LOG.debug('HTTP: Socket error in transferResponse: %s' % str(e))
            # Don't re-raise, let the caller handle the connection cleanup

    def transferChunked(self, data, _headers):
        try:
            headerSize = data.find(EOL+EOL)
            if headerSize == -1:
                LOG.debug('HTTP: Invalid chunked response - no headers')
                return
            self.socksSocket.send(data[:headerSize + 4])
            body = data[headerSize + 4:]
            if not body:
                LOG.debug('HTTP: No body data for chunked response')
                return
                
            # Size of the chunk
            try:
                eol_pos = body.find(EOL)
                if eol_pos == -1:
                    LOG.debug('HTTP: Invalid chunk size format')
                    return
                datasize = int(body[:eol_pos], 16)
            except ValueError:
                LOG.debug('HTTP: Cannot parse chunk size')
                return
                
            while datasize > 0:
                try:
                    # Size of the total body
                    bodySize = body.find(EOL) + 2 + datasize + 2
                    readSize = len(body)
                    # Make sure we send the entire response, but don't keep it in memory
                    self.socksSocket.send(body)
                    while readSize < bodySize:
                        maxReadSize = bodySize - readSize
                        try:
                            body = self.relaySocket.recv(min(self.packetSize, maxReadSize))
                            if not body:
                                LOG.debug('HTTP: Connection closed during chunked transfer')
                                return
                            readSize += len(body)
                            self.socksSocket.send(body)
                        except (ConnectionResetError, BrokenPipeError, OSError) as e:
                            LOG.debug('HTTP: Connection error during chunk read: %s' % str(e))
                            return
                    
                    try:
                        body = self.relaySocket.recv(self.packetSize)
                        if not body:
                            LOG.debug('HTTP: Connection closed while reading next chunk')
                            return
                        eol_pos = body.find(EOL)
                        if eol_pos == -1:
                            datasize = 0  # Exit loop if no EOL found
                        else:
                            datasize = int(body[:eol_pos], 16)
                    except (ValueError, ConnectionResetError, BrokenPipeError, OSError) as e:
                        LOG.debug('HTTP: Error reading chunk size: %s' % str(e))
                        return
                except Exception as e:
                    LOG.debug('HTTP: Error in chunked transfer loop: %s' % str(e))
                    return
                    
            LOG.debug('Last chunk received - exiting chunked transfer')
            try:
                self.socksSocket.send(body)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                LOG.debug('HTTP: Error sending final chunk: %s' % str(e))
                
        except Exception as e:
            LOG.debug('HTTP: Unexpected error in transferChunked: %s' % str(e))

    def extractRequestPath(self, data):
        """Extract the path from HTTP request data"""
        try:
            request_line = data.split(EOL)[0].decode('utf-8', errors='replace')
            parts = request_line.split(' ')
            if len(parts) >= 2:
                return parts[1]  # The path is the second element
        except:
            pass
        return None

    def shouldProbeAnonymous(self):
        """Check if kernel auth mode is enabled and we have access to probe"""
        LOG.info('HTTP: [DIAGNOSTIC] shouldProbeAnonymous: username=%s' % self.username)
        if not self.username:
            LOG.info('HTTP: [DIAGNOSTIC] shouldProbeAnonymous: No username, returning False')
            return False
        if self.username not in self.activeRelays:
            LOG.info('HTTP: [DIAGNOSTIC] shouldProbeAnonymous: Username not in activeRelays, returning False')
            return False
        relayClient = self.activeRelays[self.username]['protocolClient']
        kernel_auth_enabled = relayClient.serverConfig.kernelAuth
        LOG.info('HTTP: [DIAGNOSTIC] shouldProbeAnonymous: kernelAuth=%s' % kernel_auth_enabled)
        return kernel_auth_enabled

    def _processRequestWithProbe(self, buffer, socketLock, protocol='HTTP'):
        """
        Process request with try-anonymous-first, fallback-to-auth strategy.
        Tries sending request through anonymous connection first. If we get 401,
        fallback to authenticated relay for NTLM.

        Args:
            buffer: Request data (includes cookies from browser)
            socketLock: Threading lock for socket access
            protocol: Protocol name for logging ('HTTP' or 'HTTPS')
        """
        if not self.shouldProbeAnonymous():
            # Kernel auth mode not enabled, use authenticated relay normally
            with socketLock:
                tosend = self.prepareRequest(buffer)
                self.relaySocket.send(tosend)
                self.transferResponse()
            return

        # Try anonymous connection first (with cookies from browser request)
        # Create fresh connection for each request to avoid race conditions
        relayClient = self.activeRelays[self.username]['protocolClient']

        # Create a fresh anonymous connection (don't use cached one)
        try:
            import ssl
            try:
                from http.client import HTTPSConnection
            except ImportError:
                from httplib import HTTPSConnection

            try:
                uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                anonConn = HTTPSConnection(relayClient.targetHost, relayClient.targetPort, context=uv_context)
            except AttributeError:
                anonConn = HTTPSConnection(relayClient.targetHost, relayClient.targetPort)

            # Establish connection
            anonConn.connect()
        except Exception as e:
            LOG.error('%s: Failed to establish anonymous connection: %s' % (protocol, str(e)))
            # Fallback to authenticated relay
            with socketLock:
                tosend = self.prepareRequest(buffer)
                self.relaySocket.send(tosend)
                self.transferResponse()
            return

        # Send browser request (with cookies) through anonymous connection
        tosend = self.prepareRequest(buffer)
        path = self.extractRequestPath(buffer)

        try:
            anonConn.sock.send(tosend)

            # Read response status to check if NTLM auth required
            response_data = anonConn.sock.recv(self.packetSize)

            if not response_data:
                LOG.debug('%s: No response from anonymous connection' % protocol)
                # Fallback to authenticated relay
                anonConn.close()
                with socketLock:
                    self.relaySocket.send(tosend)
                    self.transferResponse()
                return

            # Check response status
            status_line = response_data.split(b'\r\n')[0].decode('utf-8', errors='replace')

            if '401' in status_line and b'WWW-Authenticate' in response_data:
                # Got 401 with auth challenge - path requires NTLM
                LOG.info('%s: Path %s requires NTLM auth, retrying through authenticated relay' % (protocol, path))

                # Close anonymous connection
                anonConn.close()

                with socketLock:
                    self.relaySocket.send(tosend)
                    self.transferResponse()
            else:
                # Success! Path works with just cookies
                LOG.info('%s: Path %s succeeded through anonymous connection (cookie-based auth)' % (protocol, path))

                # Forward the response we already received to client
                self.socksSocket.send(response_data)

                # Continue forwarding rest of response if needed
                # (Response might be larger than initial buffer)
                self.relaySocket = anonConn.sock
                while True:
                    more_data = anonConn.sock.recv(self.packetSize)
                    if not more_data:
                        break
                    self.socksSocket.send(more_data)

                # Close after successful use
                anonConn.close()

        except Exception as e:
            LOG.debug('%s: Anonymous connection error: %s, falling back to authenticated relay' % (protocol, str(e)))
            try:
                anonConn.close()
            except:
                pass
            with socketLock:
                self.relaySocket.send(tosend)
                self.transferResponse()

    def prepareRequest(self, data):
        # Parse the HTTP data, removing headers that break stuff
        response = []

        # === DEBUG: Log request line ===
        try:
            req_line = data.split(EOL)[0].decode('utf-8', errors='replace')
            _dbg('>>> REQUEST: %s' % req_line)
        except: pass
        # === END DEBUG ===

        for part in data.split(EOL):
            # This means end of headers, stop parsing here
            if part == b'':
                break
            # Remove the Basic authentication header
            if b'authorization' in part.lower():
                _dbg('>>> Stripped: %s' % part.decode('utf-8', errors='replace'))  # DEBUG
                continue
            # Don't close the connection
            if b'connection: close' in part.lower():
                response.append(b'Connection: Keep-Alive')
                continue
            # === DEBUG: Log cookie ===
            if b'cookie' in part.lower():
                _dbg('>>> Cookie: %s' % part.decode('utf-8', errors='replace'))
            # === END DEBUG ===
            # If we are here it means we want to keep the header
            response.append(part)
        # Append the body
        response.append(b'')
        body_parts = data.split(EOL+EOL)
        if len(body_parts) > 1:
            response.append(body_parts[1])
        else:
            response.append(b'')  # No body for GET requests
        senddata = EOL.join(response)

        # Check if the body is larger than 1 packet
        headerSize = data.find(EOL+EOL)
        headers = self.getHeaders(data)
        try:
            bodySize = int(headers.get('content-length', 0))
            if bodySize > 0:
                readSize = len(data)
                while readSize < bodySize + headerSize + 4:
                    try:
                        additional_data = self.socksSocket.recv(self.packetSize)
                        if not additional_data:
                            LOG.debug('HTTP: Client closed connection while reading request body')
                            break
                        readSize += len(additional_data)
                        senddata += additional_data
                    except (ConnectionResetError, BrokenPipeError, OSError) as e:
                        LOG.debug('HTTP: Connection error while reading request body: %s' % str(e))
                        break
        except (KeyError, ValueError):
            # No body or invalid content-length, could be a simple GET or a POST without body
            # no need to check if we already have the full packet
            pass
        return senddata


    def tunnelConnection(self):
        # Get the socket lock for this session
        try:
            socketLock = self.activeRelays[self.username]['socketLock']
        except KeyError:
            LOG.error('HTTP: Socket lock not found for %s in tunnel' % self.username)
            return

        buffer = b''
        while True:
            LOG.info('HTTP: [DIAGNOSTIC-TUNNEL] While loop iteration started')
            try:
                data = self.socksSocket.recv(self.packetSize)
                # If this returns with an empty string, it means the socket was closed
                if not data:
                    LOG.debug('HTTP: Client closed connection')
                    return
                
                buffer += data

                # Check if we have a complete header block
                if b'\r\n\r\n' not in buffer:
                    # Keep reading
                    continue

                LOG.info('HTTP: [DIAGNOSTIC-TUNNEL] Complete header block detected, buffer length: %d' % len(buffer))

                # Check for WebSocket upgrade requests in tunnel mode
                try:
                    headers = self.getHeaders(buffer)
                    if headers.get('upgrade', '').lower() == 'websocket':
                        LOG.debug('HTTP: WebSocket upgrade in tunnel - rejecting')
                        response = b'HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nWebSocket not supported'
                        try:
                            self.socksSocket.send(response)
                        except:
                            pass
                        return
                except:
                    # Continue with normal processing if header parsing fails
                    pass

                LOG.info('HTTP: [DIAGNOSTIC-TUNNEL] Reached probe logic section')
                # Kernel auth workaround: check if we should route through anonymous connection
                use_anon = False
                LOG.info('HTTP: [DIAGNOSTIC-TUNNEL] Checking probe logic in tunnelConnection')
                if self.shouldProbeAnonymous():
                    LOG.info('HTTP: [DIAGNOSTIC-TUNNEL] shouldProbeAnonymous returned True')
                    path = self.extractRequestPath(buffer)
                    LOG.info('HTTP: [DIAGNOSTIC-TUNNEL] Extracted path: %s' % path)
                    if path:
                        relayClient = self.activeRelays[self.username]['protocolClient']
                        needs_auth, status = relayClient.probePathAnonymous(path)

                        if not needs_auth:
                            use_anon = True
                            LOG.info('HTTP: Tunnel routing %s through anonymous connection' % path)
                        else:
                            LOG.info('HTTP: [DIAGNOSTIC-TUNNEL] Path %s requires auth' % path)
                else:
                    LOG.info('HTTP: [DIAGNOSTIC-TUNNEL] shouldProbeAnonymous returned False')

                if use_anon:
                    # Route through anonymous connection
                    relayClient = self.activeRelays[self.username]['protocolClient']
                    anonConn = relayClient.getAnonConnection()

                    if not anonConn.sock:
                        try:
                            anonConn.connect()
                        except Exception as e:
                            LOG.error('HTTP: Failed to establish anonymous connection: %s' % str(e))
                            return

                    tosend = self.prepareRequest(buffer)
                    self.relaySocket = anonConn.sock
                    anonConn.sock.send(tosend)
                    self.transferResponse()
                else:
                    # Use lock to prevent concurrent socket access from multiple threads
                    with socketLock:
                        # Pass the request to the server
                        # prepareRequest handles reading the rest of the body if needed
                        tosend = self.prepareRequest(buffer)
                        self.relaySocket.send(tosend)
                        # Send the response back to the client
                        self.transferResponse()

                # Reset buffer after processing a full request-response cycle
                buffer = b''
                
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                LOG.debug('HTTP: Connection error in tunnel: %s' % str(e))
                return
            except Exception as e:
                LOG.debug('HTTP: Unexpected error in tunnel: %s' % str(e))
                return
