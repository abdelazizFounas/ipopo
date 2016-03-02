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

# TODO: use constants
@ComponentFactory("ipopo-tlsremote-shell-factory")
@Provides("pelix.shell.tlsremote")
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
