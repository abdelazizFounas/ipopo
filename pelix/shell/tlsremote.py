#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
iPOPO TLS remote shell

Provides a remote interface for the Pelix shell that can be accessed using
.

:author: Rémi Gattaz
:copyright: Copyright 2015, Thomas Calmant
:license: Apache License 2.0
:version: 0.6.4

..

    Copyright 2015 Thomas Calmant

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""
# Standard library
from select import select
import logging
import threading
import socket
import sys
import ssl

try:
    # Python 3
    # pylint: disable=F0401
    import socketserver
except ImportError:
    # Python 2
    # pylint: disable=F0401
    import SocketServer as socketserver

# iPOPO decorators
from pelix.ipopo.decorators import ComponentFactory, Requires, Property, \
    Validate, Invalidate, Provides

# Shell constants
import pelix.shell
import pelix.shell.beans as beans
import pelix.ipv6utils

# Import pelix.shell.remote's content to extend it
from pelix.shell.remote import SharedBoolean, RemoteConsole, \
    ThreadingTCPServerFamily, IPopoRemoteShell

# ------------------------------------------------------------------------------

# Module version
__version_info__ = (0, 6, 4)
__version__ = ".".join(str(x) for x in __version_info__)

# Documentation strings format
__docformat__ = "restructuredtext en"

# ------------------------------------------------------------------------------

_logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


class TLS_TCPServer(socketserver.TCPServer):
    def __init__(self,
                 server_address,
                 certfile,
                 keyfile,
                 ca_certs,
                 RequestHandlerClass,
                 ssl_version=ssl.PROTOCOL_TLSv1,
                 bind_and_activate=True):
        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ca_certs = ca_certs
        self.ssl_version = ssl_version

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket(newsocket,
                                 server_side = True,
                                 certfile = self.certfile,
                                 keyfile = self.keyfile,
                                 cert_reqs = ssl.CERT_REQUIRED,
                                 ca_certs=self.ca_certs,
                                 ssl_version = self.ssl_version
                                 )
        return connstream, fromaddr

# ------------------------------------------------------------------------------

class TLS_ThreadingTCPServerFamily(socketserver.ThreadingMixIn, TLS_TCPServer):
    """
    Threaded TCP Server handling different address families
    """
    def __init__(self, server_address, certfile, keyfile, ca_certs, request_handler_class, ssl_version=ssl.PROTOCOL_TLSv1):
        """
        Sets up the TCP server. Doesn't bind nor activate it.
        """
        # Determine the address family
        addr_info = socket.getaddrinfo(server_address[0], server_address[1],
                                       0, 0, socket.SOL_TCP)

        # Change the address family before the socket is created
        # Get the family of the first possibility
        self.address_family = addr_info[0][0]

        # Call the super constructor
        TLS_TCPServer.__init__(self, server_address,
                                        certfile, keyfile, ca_certs,
                                        request_handler_class,
                                        ssl_version, False)
        if self.address_family == socket.AF_INET6:
            # Explicitly ask to be accessible both by IPv4 and IPv6
            try:
                pelix.ipv6utils.set_double_stack(self.socket)
            except AttributeError as ex:
                _logger.exception("System misses IPv6 constant: %s", ex)
            except socket.error as ex:
                _logger.exception("Error setting up IPv6 double stack: %s", ex)

    def process_request(self, request, client_address):
        """
        Starts a new thread to process the request, adding the client address
        in its name.
        """
        thread = threading.Thread(
            name="RemoteShell-{0}-Client-{1}".format(self.server_address[1],
                                                     client_address[:2]),
            target=self.process_request_thread,
            args=(request, client_address))
        thread.daemon = self.daemon_threads
        thread.start()

# ------------------------------------------------------------------------------

@ComponentFactory(pelix.shell.FACTORY_TLS_REMOTE_SHELL)
@Provides(pelix.shell.TLS_SERVICE_SHELL_REMOTE)
@Requires("_shell", pelix.shell.SERVICE_SHELL)
# TODO: Add a _keystore service to retrieve certfile and keyfile
@Property("_address", "pelix.shell.tlsremote.address", "localhost")
@Property("_port", "pelix.shell.tlsremote.port", 9001)
@Property("_ssl_version", "pelix.shell.tlsremote.sslversion", ssl.PROTOCOL_TLSv1)
class TLS_IPopoRemoteShell(IPopoRemoteShell):

    def _create_server(self):
        """
        Creates the TCP console on the given address and port

        :param shell: The remote shell handler
        :param server_address: Server bound address
        :param port: Server port
        :return: server thread, TCP server object
        """
        # Set up the request handler creator
        active_flag = SharedBoolean(True)

        def request_handler(*rh_args):
            """
            Constructs a RemoteConsole as TCP request handler
            """
            return RemoteConsole(self, active_flag, *rh_args)

        # TODO: used a service to retrieve cert files
        certfile = "/tmp/ipopo/server/certificat.pem"
        keyfile = "/tmp/ipopo/server/cle-privee.key"
        ca_certs = "/tmp/ipopo/server/core_ca.pem"


        # Set up the server
        server = TLS_ThreadingTCPServerFamily((self._address, self._port), certfile, keyfile, ca_certs, request_handler, self._ssl_version)

        # Set flags
        server.daemon_threads = True
        server.allow_reuse_address = True

        # Activate the server
        server.server_bind()
        server.server_activate()

        # Serve clients
        server_thread = threading.Thread(target=server.serve_forever,
                                         name="RemoteShell-{0}".format(self._port))
        server_thread.daemon = True
        server_thread.start()

        return server_thread, server, active_flag


# ------------------------------------------------------------------------------


def main(address="localhost", port=9001):
    """
    Starts a framework with a remote shell and starts an interactive console.

    :param address: Shell binding address
    :param port: Shell binding port
    """
    from pelix.ipopo.constants import use_ipopo
    import pelix.framework

    # Start a Pelix framework
    framework = pelix.framework.create_framework(('pelix.ipopo.core',
                                                  'pelix.shell.core',
                                                  'pelix.shell.ipopo',
                                                  'pelix.shell.tlsremote'))
    framework.start()
    context = framework.get_bundle_context()

    # Instantiate a Remote Shell
    with use_ipopo(context) as ipopo:
        # TODO: use contant (for factory name)
        rshell = ipopo.instantiate("ipopo-tlsremote-shell-factory",
                                   "remote-shell",
                                   {"pelix.shell.tlsremote.address": address,
                                    "pelix.shell.tlsremote.port": port,
                                    "pelix.shell.tlsremote.sslversion": ssl.PROTOCOL_TLSv1})
    # Prepare interpreter variables
    variables = {'__name__': '__console__',
                 '__doc__': None,
                 '__package__': None,
                 'framework': framework,
                 'context': context,
                 'use_ipopo': use_ipopo}

    # Prepare a banner
    host, port = rshell.get_access()
    banner = "{lines}\nPython interpreter with Pelix TLS Remote Shell\n" \
        "Remote shell bound to: {host}:{port}\n{lines}\n" \
        "Python version: {version}\n" \
        .format(lines='-' * 80, version=sys.version,
                host=host, port=port)

    try:
        # Run an interpreter
        _run_interpreter(variables, banner)
    finally:
        # Stop the framework
        framework.stop()


def _run_interpreter(variables, banner):
    """
    Runs a Python interpreter console and blocks until the user exits it.

    :param variables: Interpreters variables (locals)
    :param banner: Start-up banners
    """
    # Script-only imports
    import code
    try:
        import readline
        import rlcompleter
        readline.set_completer(rlcompleter.Completer(variables).complete)
        readline.parse_and_bind("tab: complete")

    except ImportError:
        # readline is not available: ignore
        pass

    # Start the console
    shell = code.InteractiveConsole(variables)
    shell.interact(banner)

# ------------------------------------------------------------------------------

if __name__ == '__main__':
    # Prepare arguments
    import argparse
    parser = argparse.ArgumentParser(description="Pelix Remote Shell")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose",
                        help="Set loggers at debug level")
    parser.add_argument("-a", "--address", dest="address", default="localhost",
                        help="The remote shell binding address")
    parser.add_argument("-p", "--port", dest="port", type=int, default=9001,
                        help="The remote shell binding port")
    # TODO: Add argument for TLS version

    # Parse them
    args = parser.parse_args()

    # Prepare the logger
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    # Run the entry point
    main(args.address, args.port)
