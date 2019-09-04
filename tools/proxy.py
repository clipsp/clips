#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Clips - Proxy server proxy using clipout (read) and clipin (write).

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
import socket
import sys
import traceback
import threading

from contextlib import closing
from select import select

try:
    from Queue import Queue
except ImportError:
    from queue import Queue


class BaseHandler(object):
    """Basic spawn handler."""
    BUFFER_SIZE = 1024

    def __init__(self, clipin, clipout):
        self.rconn = socket.create_connection(clipout)
        self.rfile = self.rconn.makefile()
        self.wconn = socket.create_connection(clipin)
        self.wfile = self.wconn.makefile()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def _read(self, f):
        return f.readline()

    def _write(self, f, data):
        n = f.write(data)
        f.flush()
        return n

    def start(self):
        """Code to execute before reading stdout."""
        sys.stderr.write("Proxy on\n")
        sys.stderr.flush()

    def close(self):
        """Code to execute when the process ended."""
        self.rfile.close()
        self.wfile.close()
        sys.stderr.write("Proxy off\n")
        sys.stderr.flush()

    def read(self):
        """Hijack process' stdin result."""
        return self._read(self.rfile)

    def write(self, data):
        """Send data to process' stdin."""
        return self._write(self.wfile, data)


class SOCKSHandler(BaseHandler):
    def __init__(self, *args, **kwargs):
        BaseHandler.__init__(self, *args, **kwargs)
        self._sessions = {}

    def read(self):
        while True:
            line = self._read(self.rfile)
            sys.stderr.write(":{}\n".format(line.strip()))
            head, sep, tail = line.partition("$BASE64$")
            # Not a command
            if head:
                return line
            # Handle $BASE64$ command
            session_id, sep, tail = tail.partition("$")
            try:
                # Handle CONNECT
                if "$" in tail[:1]:
                    _, port, address = tail.split('$')
                    address = address.strip()
                    port = int(port)
                    self.spawn_worker(session_id, address, port)
                    continue
                # Handle SESSION data
                data = base64.b64decode(tail)
                self._sessions[session_id][2].put(data)
            except:
                sys.stderr.write(traceback.format_exc().replace("\n", "\r\n"))
                sys.stderr.flush()

    def spawn_worker(self, session_id, address, port):
        self._sessions[session_id] = (address, port, Queue())
        t = threading.Thread(target=self._worker, args=(session_id,))
        t.daemon = True
        t.start()
        sys.stderr.write("[PROXY] CONNECT {}:{} ({})\r\n".format(
            address, port, session_id
        ))


    def _send(self, session_id, data):
        data = "$BASE64${}${}\n".format(session_id, base64.b64encode(data))
        sys.stderr.write("!{}".format(data))
        return self.wconn.sendall(
            data
        )

    def _worker(self, session_id):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as proxy_socket:
            result = proxy_socket.connect_ex(self._sessions[session_id][:2])
            self._send(session_id, str(result))
            if result != 0:
                return
            is_alive = True
            while is_alive:
                rlist, wlist, xlist = select([proxy_socket], [], [], 0.5)
                for fd in rlist:
                    try:
                        data = fd.recv(self.BUFFER_SIZE)
                        self._send(session_id, data)
                        if not data:
                            sys.stderr.write("[PROXY] EMPTY RESPONSE ({})\n".format(session_id))
                            del self._sessions[session_id]
                            is_alive = False
                        else:
                            sys.stderr.write("[PROXY] RESPONSE data to {} [len={}]\n".format(
                                session_id, len(data)
                            ))
                    except IOError:
                        sys.stderr.write("[PROXY] IOError {}\n".format(session_id))
                        is_alive = False
                while is_alive and not self._sessions[session_id][2].empty():
                    data = self._sessions[session_id][2].get_nowait()
                    if data:
                        proxy_socket.sendall(data)
                        sys.stderr.write("[PROXY] REQUEST data to {} [len={}]\n".format(
                            session_id, len(data)
                        ))
                    else:
                        is_alive = False
                        sys.stderr.write("[PROXY] EMPTY REQUEST ({})\n".format(session_id))
                    sys.stderr.flush()
            sys.stderr.write("[PROXY] CLOSE {}\n".format(session_id))


if __name__ == "__main__":
    CLIPIN = ("127.0.0.1", 21000)
    CLIPOUT = ("127.0.0.1", 21001)

    with SOCKSHandler(CLIPIN, CLIPOUT) as h:
        data = h.read()
        while data:
            h.write(data)
            data = h.read()
