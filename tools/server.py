#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Clips - Proxy server.

    Clipboard Server Project
    Copyright (C) 2019  Sepalani

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import base64
import random
import string
import struct
import sys
import traceback

from contextlib import closing
from select import select
from socket import inet_ntoa, socket, create_connection, AF_INET, SOCK_STREAM

try:
    from Queue import Queue
    from SocketServer import ThreadingTCPServer, StreamRequestHandler
except ImportError:
    from queue import Queue
    from socketserver import ThreadingTCPServer, StreamRequestHandler


class SocksMethod(object):
    NO_AUTHENTICATION_REQUIRED = 0
    GSS_API = 1
    USERNAME_PASSWORD = 2
    NO_ACCEPTABLE_METHODS = 255


class AddressType(object):
    IPV4 = 1
    DOMAIN_NAME = 3
    IPV6 = 4


class SocksCommand(object):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class ReplyType(object):
    SUCCEEDED = 0
    GENERAL_SOCKS_SERVER_FAILURE = 1
    CONNECTION_NOT_ALLOWED_BY_RULESET = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_TYPE_NOT_SUPPORTED = 8


class Socks5RequestHandler(StreamRequestHandler):
    SOCKS_VERSION = 5

    def recv(self, size):
        return self.rfile.read(size)

    def send(self, data):
        return self.wfile.write(data)

    def handle(self):
        # Methods handling
        version, method_num = struct.unpack('bb', self.recv(2))
        methods = struct.unpack('b' * method_num, self.recv(method_num))
        if SocksMethod.NO_AUTHENTICATION_REQUIRED in methods:
            self.send(bytearray([
                self.SOCKS_VERSION,
                SocksMethod.NO_AUTHENTICATION_REQUIRED
            ]))
        else:
            self.send(bytearray([
                self.SOCKS_VERSION,
                SocksMethod.NO_ACCEPTABLE_METHODS
            ]))
            return

        # Address handling
        version, command, reserved, address_type = struct.unpack('bbbb', self.recv(4))
        if address_type == AddressType.IPV4:
            host = inet_ntoa(self.recv(4))
            port = struct.unpack("!H", self.recv(2))[0]
        elif address_type == AddressType.DOMAIN_NAME:
            host = self.recv(struct.unpack('b', self.recv(1))[0])
            port = struct.unpack("!H", self.recv(2))[0]
        else:
            host, port = None, None
            self.send_response(ReplyType.ADDRESS_TYPE_NOT_SUPPORTED)

        # Command handling
        address = host, port
        if command == SocksCommand.CONNECT:
            session = self.server.session_manager.create_session()
            session.connect(self, address)
            session.close()
        else:
            self.send_response(ReplyType.COMMAND_NOT_SUPPORTED)

    def send_response(self, reply_type):
        response = bytearray(10)
        response[0] = self.SOCKS_VERSION
        response[1] = reply_type
        response[3] = 1
        return self.send(response)


class Session(object):
    BUFFER_SIZE = 1024

    def __init__(self, session_id):
        self._session_id = session_id
        self._is_alive = True

    def get_id(self):
        return self._session_id

    def is_alive(self):
        return self._is_alive

    def connect(self, handler, address):
        print("[ID:{}] TCP CONNECT {}:{}".format(self.get_id(), *address))
        with closing(socket(AF_INET, SOCK_STREAM)) as proxy_socket:
            result = proxy_socket.connect_ex(address)
            if result == 0:
                handler.send_response(ReplyType.SUCCEEDED)
                fd_list = [handler.connection, proxy_socket]
                while self.is_alive():
                    rlist, wlist, xlist = select(fd_list, [], [], 0.5)
                    for fd in rlist:
                        try:
                            data = fd.recv(self.BUFFER_SIZE)
                            if not data:
                                self.close()
                                break
                            dest = fd_list[(fd_list.index(fd) + 1) % 2]
                            dest.sendall(data)
                        except IOError:
                            self.close()
            elif result == 60:
                handler.send_response(ReplyType.TTL_EXPIRED)
            elif result == 61:
                handler.send_response(ReplyType.NETWORK_UNREACHABLE)
            else:
                handler.send_response(ReplyType.NETWORK_UNREACHABLE)

    def close(self):
        print("[ID:{}] SESSION CLOSE".format(self.get_id()))
        self._is_alive = False


class ClipsSession(Session):
    def connect(self, handler, address):
        self.handler = handler
        self.proxy_socket = None
        fd_list = [handler.connection]
        message = b"$BASE64${}$${}${}\n".format(
            self.get_id(), address[1], address[0]
        )
        handler.server._mq.put(message)
        while self.is_alive():
            rlist, wlist, xlist = select(fd_list, [], [], 0.5)
            for fd in rlist:
                try:
                    data = fd.recv(self.BUFFER_SIZE)
                    message = b"$BASE64${}${}\n".format(
                        self.get_id(), base64.b64encode(data)
                    )
                    handler.server._mq.put(message)
                    if not data:
                        self.close()
                except IOError:
                    self.close()

    def get_response(self, data):
        """Send data to the client."""
        if not data:
            return self.close()
        if self.proxy_socket is not None:
            return self.handler.connection.sendall(data)
        self.proxy_socket = int(bytearray(data).decode())
        if self.proxy_socket == 0:
            return self.handler.send_response(ReplyType.SUCCEEDED)
        self.handler.send_response(ReplyType.NETWORK_UNREACHABLE)
        return self.close()


    def close(self):
        self._is_alive = False


class SessionManager(object):
    ID_CHARSET = string.letters + string.digits
    ID_SIZE = 8
    SESSION_CLASS = Session

    def __init__(self, server):
        self._sessions = {}
        self._server = server
        self._server.session_manager = self

    def _create_session_id(self):
        session_id = "".join([
            random.choice(self.ID_CHARSET)
            for _ in range(self.ID_SIZE)
        ])
        while session_id in self._sessions:
            session_id = "".join([
                random.choice(self.ID_CHARSET)
                for _ in range(self.ID_SIZE)
            ])
        return session_id

    def create_session(self):
        session_id = self._create_session_id()
        self._sessions[session_id] = self.SESSION_CLASS(session_id)
        return self._sessions[session_id]

    def get_session(self, session_id):
        return self._sessions[session_id]

    def close_session(self, session_id):
        session = self._sessions[session_id]
        session.close()
        del self._sessions[session_id]

    def stop(self):
        sessions = [session_id for session_id in self._sessions.keys()]
        for session_id in sessions:
            self.close_session(session_id)


class ClipsSessionManager(SessionManager):
    SESSION_CLASS = ClipsSession

    def __init__(self, server):
        import threading

        SessionManager.__init__(self, server)
        self._server._mq = Queue()

        # Monitor STDIN/STDOUT
        self._stdin_worker_thread = threading.Thread(
            target=self._stdin_worker
        )
        self._stdout_worker_thread = threading.Thread(
            target=self._stdout_worker
        )
        self._stdin_worker_thread.daemon = True
        self._stdout_worker_thread.daemon = True
        self._stdin_worker_thread.start()
        self._stdout_worker_thread.start()

    def _stdin_worker(self):
        """Listen decode STDIN.

        Base64 encoded format:
        $BASE64$<SESSION_ID>$<B64_DATA>
        """
        line = sys.stdin.readline()
        while line:
            line = line.strip()
            if line:
                head, sep, tail = line.partition("$BASE64$")
                if not head:
                    session_id, sep, data = tail.partition("$")
                    try:
                        data = base64.b64decode(data)
                        session = self.get_session(session_id)
                        session.get_response(data)
                    except:
                        sys.stderr.write(traceback.format_exc())
                        sys.stderr.flush()
            line = sys.stdin.readline()


    def _stdout_worker(self):
        """Send data to STDOUT.

        Base64 encoded format:
        $BASE64$<SESSION_ID>$<B64_DATA>

        Base64 encoded format (on connect):
        $BASE64$<SESSION_ID>$$<PORT>$<ADDRESS>
        """
        while True:
            data = self._server._mq.get()
            sys.stdout.write(data)
            sys.stdout.flush()


def main():
    import atexit
    import termios

    def enable_echo(enable):
        fd = sys.stdin.fileno()
        new = termios.tcgetattr(fd)
        if enable:
            new[3] |= termios.ECHO
        else:
            new[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSANOW, new)

    atexit.register(enable_echo, True)
    enable_echo(False)

    ThreadingTCPServer.allow_reuse_address = True
    server = ThreadingTCPServer(("", 1080), Socks5RequestHandler)
    server.session_manager = ClipsSessionManager(server)
    try:
        sys.stderr.write("SOCKS server listening on port 1080 ...\n")
        sys.stderr.flush()
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        server.shutdown()
        server.session_manager.stop()


if __name__ == '__main__':
    main()
