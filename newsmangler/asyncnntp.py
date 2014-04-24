# Copyright (c) 2005-2012 freddie@wafflemonster.org
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions, and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions, and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the author of this software nor the name of
#     contributors to this software may be used to endorse or promote products
#     derived from this software without specific prior written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"A basic NNTP client using asyncore"

import asyncore
import errno
import logging
import re
import select
import socket
import time
import ssl
from nntplib import *
import StringIO
import tempfile
import sys


# ---------------------------------------------------------------------------

try:
    from OpenSSL import SSL
    _ssl = SSL
    WantReadError = _ssl.WantReadError
    WantWriteError = _ssl.WantWriteError
    del SSL
    HAVE_SSL = True

except ImportError:
    _ssl = None
    HAVE_SSL = False


import threading
_RLock = threading.RLock
del threading

import select

class SSLConnection(object):
    def __init__(self, *args):
        self._ssl_conn = apply(_ssl.Connection, args)
        self._lock = _RLock()

    for f in ('get_context', 'pending', 'send', 'write', 'recv', 'read',
              'renegotiate', 'bind', 'listen', 'connect', 'accept',
              'setblocking', 'fileno', 'shutdown', 'close', 'get_cipher_list',
              'getpeername', 'getsockname', 'getsockopt', 'setsockopt',
              'makefile', 'get_app_data', 'set_app_data', 'state_string',
              'sock_shutdown', 'get_peer_certificate', 'want_read',
              'want_write', 'set_connect_state', 'set_accept_state',
              'connect_ex', 'sendall', 'do_handshake', 'settimeout'):
        exec """def %s(self, *args):
            self._lock.acquire()
            try:
                return apply(self._ssl_conn.%s, args)
            finally:
                self._lock.release()\n""" % (f, f)

# ---------------------------------------------------------------------------

STATE_DISCONNECTED = 0
STATE_CONNECTING = 1
STATE_CONNECTED = 2

MODE_AUTH = 0
MODE_COMMAND = 1
MODE_POST_INIT = 2
MODE_POST_DATA = 3
MODE_POST_DONE = 4
MODE_DATA = 5

POST_BUFFER_MIN = 16384
POST_READ_SIZE = 262144

MSGID_RE = re.compile(r'(<\S+@\S+>)')

NNTP_SSL_PORT = 443
CRLF = '\r\n'
# ---------------------------------------------------------------------------

class asyncNNTP(asyncore.dispatcher):
    def __init__(self, parent, connid, host, port, bindto, username, password, ssl = False):
        asyncore.dispatcher.__init__(self)
        
        self.logger = logging.getLogger('mangler')
        
        self.parent = parent
        self.connid = connid
        self.host = host
        self.port = port
        self.bindto = bindto
        self.username = username
        self.password = password
        self.ssl = ssl
        
        self.reset()
    
    def reset(self):
        self._readbuf = b''
        self._writebuf = b''
        self._article = None
        self._pointer = 0
        
        self.reconnect_at = 0
        self.mode = MODE_AUTH
        self.state = STATE_DISCONNECTED

    def do_connect(self):
        # Create the socket
        if self.ssl and not HAVE_SSL:
            self.logger.error("OPENSSL not installed but trying to use an SSL connection. SSL disabled.")
            self.ssl = False

        for res in socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            self.create_socket(af,socktype)

            if self.ssl:
                ctx = _ssl.Context(_ssl.SSLv23_METHOD)
                self.socket = SSLConnection(ctx, self.socket)

            # Try to set our send buffer a bit larger
            for i in range(17, 13, -1):
                try:
                    self.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**i)
                except socket.error:
                    continue
                else:
                    break

            # Try to connect. This can blow up!
            try:
                self.connect((self.host, self.port))
            except (socket.error, socket.gaierror), msg:
                self.really_close(msg)
            else:
                # Handshake
                if self.ssl:
                    # Waiting socket wants read and write
                    while True:
                        try:
                            self.socket.do_handshake()
                            break
                        except WantWriteError:
                            select.select([self.socket], [], [], 1.0)
                        except WantReadError:
                            select.select([self.socket], [], [], 1.0)

                self.state = STATE_CONNECTING
                self.logger.debug('%d: connecting to %s:%s', self.connid, self.host, self.port)

            break       
    
    # -----------------------------------------------------------------------
    # Check to see if it's time to reconnect yet
    def reconnect_check(self, now):
        if self.state == STATE_DISCONNECTED and now >= self.reconnect_at:
            self.do_connect()

    def add_channel(self, map=None):
        self.logger.debug('%d: adding FD %d to poller', self.connid, self._fileno)
        
        asyncore.dispatcher.add_channel(self, map)

        # Add ourselves to the poll object
        asyncore.poller.register(self._fileno)
    
    def del_channel(self, map=None):
        self.logger.debug('%d: removing FD %d from poller', self.connid, self._fileno)

        # Remove ourselves from the async map
        asyncore.dispatcher.del_channel(self, map)
        
        # Remove ourselves from the poll object
        if self._fileno is not None:
            try:
                asyncore.poller.unregister(self._fileno)
            except KeyError:
                pass

    def close(self):
        self.logger.debug('close')
        self.del_channel()
        if self.socket is not None:
            self.socket.close()
    
    # -----------------------------------------------------------------------
    # We only want to be writable if we're connecting, or something is in our
    # buffer.
    def writable(self):
        self.logger.debug('writable')
        return (not self.connected) or len(self._writebuf)
    
    # Send some data from our buffer when we can write
    def handle_write(self):
        self.logger.debug('%d wants to write!', self._fileno)
        
        if not self.writable():
            # We don't have any buffer, silly thing
            asyncore.poller.register(self._fileno, select.POLLIN)
            return
        
        sent = asyncore.dispatcher.send(self, self._writebuf[self._pointer:])
        self._pointer += sent
        
        # We've run out of data
        if self._pointer == len(self._writebuf):
            self._writebuf = b''
            self._pointer = 0
            asyncore.poller.register(self._fileno, select.POLLIN)
        
        # If we're posting, we might need to read some more data from our file
        if self.mode == MODE_POST_DATA:
            self.parent._bytes += sent
            if len(self._writebuf) == 0:
                self.post_data()
    
    # -----------------------------------------------------------------------
    # We want buffered output, duh
    def send(self, data):
        self._writebuf += data
        # We need to know about writable things now
        asyncore.poller.register(self._fileno)
        self.logger.debug('%d has data!', self._fileno)
    
    # -----------------------------------------------------------------------
    
    def handle_error(self):
        self.logger.exception('%d: unhandled exception!', self.connid)
    
    # -----------------------------------------------------------------------
    
    def handle_connect(self):
        self.status = STATE_CONNECTED
        self.logger.debug('%d: connected!', self.connid)
    
    def handle_close(self):
        self.really_close()
    
    def really_close(self, error=None):
        self.mode = MODE_COMMAND
        self.status = STATE_DISCONNECTED
        
        self.close()
        self.reset()
        
        if error and hasattr(error, 'args'):
            self.logger.warning('%d: %s!', self.connid, error.args[1])
            self.reconnect_at = time.time() + self.parent.conf['server']['reconnect_delay']
        else:
            self.logger.warning('%d: Connection closed: %s', self.connid, error)
    
    # There is some data waiting to be read
    def handle_read(self):
        self.logger.debug('handle_read')
        try:
            self._readbuf += self.recv(16384)
        except socket.error, msg:
            self.really_close(msg)
            return
        
        # Split the buffer into lines. Last line is always incomplete.
        lines = self._readbuf.split('\r\n')
        self._readbuf = lines.pop()
        
        # Do something useful here
        for line in lines:
            self.logger.debug('%d: < %s', self.connid, line)

            # Initial login stuff
            if self.mode == MODE_AUTH:
                resp = line.split(None, 1)[0]
                
                # Welcome... post, no post
                if resp in ('200', '201'):
                    if self.username:
                        text = 'AUTHINFO USER %s\r\n' % (self.username)
                        self.send(text)
                        self.logger.debug('%d: > AUTHINFO USER ********', self.connid)
                    else:
                        self.mode = MODE_COMMAND
                        self.parent._idle.append(self)
                        self.logger.debug('%d: ready.', self.connid)
                
                # Need password too
                elif resp in ('381'):
                    if self.password:
                        text = 'AUTHINFO PASS %s\r\n' % (self.password)
                        self.send(text)
                        self.logger.debug('%d: > AUTHINFO PASS ********', self.connid)
                    else:
                        self.really_close('need password!')
                
                # Auth ok
                elif resp in ('281'):
                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)
                    self.logger.debug('%d: ready.', self.connid)
                
                # Auth failure
                elif resp in ('502'):
                    self.really_close('authentication failure.')
                
                # Dunno
                else:
                    self.logger.warning('%d: unknown response while MODE_AUTH - "%s"',
                        self.connid, line)
            
            # Posting a file
            elif self.mode == MODE_POST_INIT:
                resp = line.split(None, 1)[0]
                # Posting is allowed
                if resp == '340':
                    self.mode = MODE_POST_DATA
                    
                    # TODO: use the suggested message-ID, will require some rethinking as to how
                    #       messages are constructed
                    m = MSGID_RE.search(line)
                    if m:
                        self.logger.debug('%d: changing Message-ID to %s', self.connid, m.group(1))
                        self._article.headers['Message-ID'] = m.group(1)

                    # Prepare the article for posting
                    article_size = self._article.prepare()
                    self.parent.remember_msgid(article_size, self._article)

                    self.post_data()
                
                # Posting is not allowed
                elif resp == '440':
                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)
                    del self._article
                    self.logger.warning('%d: posting not allowed!', self.connid)
                
                # WTF?
                else:
                    self.logger.warning('%d: unknown response while MODE_POST_INIT - "%s"',
                        self.connid, line)
            
            # Done posting
            elif self.mode == MODE_POST_DONE:
                resp = line.split(None, 1)[0]
                # Ok
                if resp == '240':
                    #self.parent.post_success(self._article)

                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)

                # Not ok
                elif resp.startswith('44'):
                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)
                    self.logger.warning('%d: posting failed - %s', self.connid, line)
                
                # WTF?
                else:
                    self.logger.warning('%d: unknown response while MODE_POST_DONE - "%s"',
                        self.connid, line)
            
            # Other stuff
            else:
                self.logger.warning('%d: unknown response from server - "%s"',
                    self.connid, line)
    
    # -----------------------------------------------------------------------
    # Guess what this does!
    def post_article(self, article):
        self.logger.debug('post_article')
        self.mode = MODE_POST_INIT
        self._article = article
        self.send('POST\r\n')
        self.logger.debug('%d: > POST', self.connid)
    
    def post_data(self):
        self.logger.debug('post_data')
        data = self._article.postfile.read(POST_READ_SIZE)
        if len(data) == 0:
            self.mode = MODE_POST_DONE
            self._article.postfile.close()
            self._article.postfile = None
        
        if len(data) > 0:
            f = open('/tmp/test','wb')
            f.write(data)
            f.close()
        self.send(data)

# ---------------------------------------------------------------------------

class myNNTP_SSL(asyncore.dispatcher):
    """NNTP client class over SSL connection

    Instantiate with: asyncNNTP_SSL(parent, connid, hostname, port, user, password)

        - parent: Instance that instanciate this class
        - connid: an integer for a connection number
        - hostname: hostname to connect to
        - port: port to connect to (default the standard NNTP port)
        - user: username to authenticate with
        - password: password to use with username
    """

    def __init__(self, parent, connid, host, port, user, password):
        asyncore.dispatcher.__init__(self)
        self.parent = parent
        self.connid = connid
        self.host = host
        self.port = port
        self.username = user
        self.password = password
        self.buffer = ""
        self.logger = logging.getLogger('mangler')

        self.reset()
    
    def reset(self):
        self._readbuf = ''
        self._writebuf = ''
        self._article = None
        self._pointer = 0
        
        self.reconnect_at = 0
        self.mode = MODE_AUTH
        self.state = STATE_DISCONNECTED

    def do_connect(self):
        for res in socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            ctx = _ssl.Context(_ssl.SSLv23_METHOD)
            self.create_socket(af,socktype)
            self.socket = SSLConnection(ctx, self.socket)
            # Try to set our send buffer a bit larger
            for i in range(17, 13, -1):
                try:
                    self.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**i)
                except socket.error:
                    continue
                else:
                    break

            self.connect((self.host,self.port))

            # Waiting socket want read
            while True:
                try:
                    self.socket.do_handshake()
                    break
                except WantWriteError:
                    select.select([self.socket], [], [], 1.0)
                except WantReadError:
                    select.select([self.socket], [], [], 1.0)
            break

        self.state = STATE_CONNECTING
        self.logger.debug('%d: connecting to %s:%s', self.connid, self.host, self.port)

    # Check to see if it's time to reconnect yet
    def reconnect_check(self, now):
        self.logger.debug('reconnect_check')
    	if self.state == STATE_DISCONNECTED and now >= self.reconnect_at:
        	self.do_connect()

    def add_channel(self, map=None):
        self.logger.debug('%d: adding FD %d to poller', self.connid, self._fileno)
        
        asyncore.dispatcher.add_channel(self, map)

        # Add ourselves to the poll object
        asyncore.poller.register(self._fileno)
    
    def del_channel(self, map=None):
        self.logger.debug('%d: removing FD %d from poller', self.connid, self._fileno)

        # Remove ourselves from the async map
        asyncore.dispatcher.del_channel(self, map)
        
        # Remove ourselves from the poll object
        if self._fileno is not None:
            try:
                asyncore.poller.unregister(self._fileno)
            except KeyError:
                pass

    def close(self):
        self.logger.debug('close')
        self.del_channel()
        if self.socket is not None:
            self.socket.close()
    
    # -----------------------------------------------------------------------
    # We only want to be writable if we're connecting, or something is in our
    # buffer.
    def writable(self):
        self.logger.debug('writable')
        return (not self.connected) or len(self._writebuf)
    
    # Send some data from our buffer when we can write
    def handle_write(self):
        self.logger.debug('%d wants to write!', self._fileno)
        
        if not self.writable():
            # We don't have any buffer, silly thing
            asyncore.poller.register(self._fileno, select.POLLIN)
            return
        
        sent = asyncore.dispatcher.send(self, self._writebuf[self._pointer:])
        self._pointer += sent
        
        # We've run out of data
        if self._pointer == len(self._writebuf):
            self._writebuf = ''
            self._pointer = 0
            asyncore.poller.register(self._fileno, select.POLLIN)
        
        # If we're posting, we might need to read some more data from our file
        if self.mode == MODE_POST_DATA:
            self.parent._bytes += sent
            if len(self._writebuf) == 0:
                self.post_data()
    
    # -----------------------------------------------------------------------
    # We want buffered output, duh
    def send(self, data):
        self._writebuf += data
        # We need to know about writable things now
        asyncore.poller.register(self._fileno)
        self.logger.debug('%d has data!', self._fileno)
    
    # -----------------------------------------------------------------------
    
    def handle_error(self):
        self.logger.exception('%d: unhandled exception!', self.connid)
    
    # -----------------------------------------------------------------------
    
    def handle_connect(self):
        self.status = STATE_CONNECTED
        self.logger.debug('%d: connected!', self.connid)
    
    def handle_close(self):
        self.really_close()
    
    def really_close(self, error=None):
        self.mode = MODE_COMMAND
        self.status = STATE_DISCONNECTED
        
        self.close()
        self.reset()
        
        if error and hasattr(error, 'args'):
            self.logger.warning('%d: %s!', self.connid, error.args[1])
            self.reconnect_at = time.time() + self.parent.conf['server']['reconnect_delay']
        else:
            self.logger.warning('%d: Connection closed: %s', self.connid, error)
    
    # There is some data waiting to be read
    def handle_read(self):
        self.logger.debug('handle_read')
        try:
            self._readbuf += self.recv(16384)
        except socket.error, msg:
            self.really_close(msg)
            return
        
        # Split the buffer into lines. Last line is always incomplete.
        lines = self._readbuf.split('\r\n')
        self._readbuf = lines.pop()
        
        # Do something useful here
        for line in lines:
            self.logger.debug('%d: < %s', self.connid, line)

            # Initial login stuff
            if self.mode == MODE_AUTH:
                resp = line.split(None, 1)[0]
                
                # Welcome... post, no post
                if resp in ('200', '201'):
                    if self.username:
                        text = 'AUTHINFO USER %s\r\n' % (self.username)
                        self.send(text)
                        self.logger.debug('%d: > AUTHINFO USER ********', self.connid)
                    else:
                        self.mode = MODE_COMMAND
                        self.parent._idle.append(self)
                        self.logger.debug('%d: ready.', self.connid)
                
                # Need password too
                elif resp in ('381'):
                    if self.password:
                        text = 'AUTHINFO PASS %s\r\n' % (self.password)
                        self.send(text)
                        self.logger.debug('%d: > AUTHINFO PASS ********', self.connid)
                    else:
                        self.really_close('need password!')
                
                # Auth ok
                elif resp in ('281'):
                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)
                    self.logger.debug('%d: ready.', self.connid)
                
                # Auth failure
                elif resp in ('502'):
                    self.really_close('authentication failure.')
                
                # Dunno
                else:
                    self.logger.warning('%d: unknown response while MODE_AUTH - "%s"',
                        self.connid, line)
            
            # Posting a file
            elif self.mode == MODE_POST_INIT:
                resp = line.split(None, 1)[0]
                # Posting is allowed
                if resp == '340':
                    self.mode = MODE_POST_DATA
                    
                    # TODO: use the suggested message-ID, will require some rethinking as to how
                    #       messages are constructed
                    m = MSGID_RE.search(line)
                    if m:
                        self.logger.debug('%d: changing Message-ID to %s', self.connid, m.group(1))
                        self._article.headers['Message-ID'] = m.group(1)

                    # Prepare the article for posting
                    article_size = self._article.prepare()
                    self.parent.remember_msgid(article_size, self._article)

                    self.post_data()
                
                # Posting is not allowed
                elif resp == '440':
                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)
                    del self._article
                    self.logger.warning('%d: posting not allowed!', self.connid)
                
                # WTF?
                else:
                    self.logger.warning('%d: unknown response while MODE_POST_INIT - "%s"',
                        self.connid, line)
            
            # Done posting
            elif self.mode == MODE_POST_DONE:
                resp = line.split(None, 1)[0]
                # Ok
                if resp == '240':
                    #self.parent.post_success(self._article)

                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)

                # Not ok
                elif resp.startswith('44'):
                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)
                    self.logger.warning('%d: posting failed - %s', self.connid, line)
                
                # WTF?
                else:
                    self.logger.warning('%d: unknown response while MODE_POST_DONE - "%s"',
                        self.connid, line)
            
            # Other stuff
            else:
                self.logger.warning('%d: unknown response from server - "%s"',
                    self.connid, line)
    
    # -----------------------------------------------------------------------
    # Guess what this does!
    def post_article(self, article):
        self.logger.debug('post_article')
        self.mode = MODE_POST_INIT
        self._article = article
        self.send('POST\r\n')
        self.logger.debug('%d: > POST', self.connid)
    
    def post_data(self):
        self.logger.debug('post_data')
        data = self._article.postfile.read(POST_READ_SIZE)
        if len(data) == 0:
            self.mode = MODE_POST_DONE
            self._article.postfile.close()
            self._article.postfile = None
        
        if len(data) > 0:
            f = open('/tmp/test','wb')
            f.write(data)
            f.close()
        self.send(data)

class asyncNNTP_SSL(asyncore.dispatcher):

    def __init__(self, parent, connid, host, port, dindto, user, password,
                 keyfile = None, certfile = None):
        asyncore.dispatcher.__init__(self)
        self.parent = parent
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.keyfile = keyfile
        self.connid = connid
        self.certfile = certfile
        self.buffer = ""
        self.logger = logging.getLogger('mangler')
        self.reset()

    def reset(self):
        self._readbuf = ''
        self._writebuf = ''
        self._article = None
        self._pointer = 0
        
        self.reconnect_at = 0
        self.mode = MODE_AUTH
        self.state = STATE_DISCONNECTED


    def do_connect(self):
        msg = "getaddrinfo returns an empty list"
        self.socket = None

        for res in socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
            except socket.error, msg:
                if sock:
                    sock.close()
                sock = None
                continue
            break
        if not sock:
            raise socket.error, msg
        #self.file = sock.makefile('rb')
        self.state = STATE_CONNECTING
        #self._sslobj = self.socket = ssl.wrap_socket(self.socket,server_side=True)
        self.sslobj = socket.ssl(sock, self.keyfile, self.certfile)
        self.family_and_type = af, socktype
        sock.setblocking(0)
        self.set_socket(sock)
        self._fileno = self.socket.fileno()
        self.connect(sa)
        #self.connect(sa)
        #self.socket = socket.ssl(self.socket, self.keyfile, self.certfile)
        self.debugging = 1
        self._writebuf = 'AUTHINFO USER %s\r\n' % self.user
        #self.welcome = self.getresp()

        # 'mode reader' is sometimes necessary to enable 'reader' mode.
        # However, the order in which 'mode reader' and 'authinfo' need to
        # arrive differs between some NNTP servers. Try to send
        # 'mode reader', and if it fails with an authorization failed
        # error, try again after sending authinfo.
        #resp = self.send('AUTHINFO USER %s\r\n' % self.user)
        #if resp[:3] == '381':
        #    if not self.password:
        #        raise NNTPReplyError(resp)
        #    else:
        #        resp = self.shortcmd(
        #                'authinfo pass '+self.password)
        #        if resp[:3] != '281':
        #            raise NNTPPermanentError(resp)
        #        else:
        #            self.state = STATE_CONNECTED
        #            self.parent._idle.append(self)


    def handle_connect(self):
        self.state = STATE_CONNECTED
        self.logger.debug('%d: connected!', self.connid)

    # Check to see if it's time to reconnect yet
    def reconnect_check(self, now):
        self.logger.debug('reconnect_check')
    	if self.state == STATE_DISCONNECTED and now >= self.reconnect_at:
        	self.do_connect()
        self.do_connect()

    def getwelcome(self):
        """Get the welcome message from the server
        (this is read and squirreled away by __init__()).
        If the response code is 200, posting is allowed;
        if it 201, posting is not allowed."""

        if self.debugging: print '*welcome*', repr(self.welcome)
        return self.welcome

    def set_debuglevel(self, level):
        """Set the debugging level.  Argument 'level' means:
        0: no debugging output (default)
        1: print commands and responses but not body text etc.
        2: also print raw lines read and sent before stripping CR/LF"""

        self.debugging = level
    debug = set_debuglevel

#    def putline(self, line):
#        """Internal: send one line to the server, appending CRLF."""
#        line = line + CRLF
#        if self.debugging > 1: print '*put*', repr(line)
#        self.sock.sendall(line)
    def shortcmd(self, line):
        """Internal: send a command and get the response."""
        self.putcmd(line)
        return self.getresp()

    def longcmd(self, line, file=None):
        """Internal: send a command and get the response plus following text."""
        self.putcmd(line)
        return self.getlongresp(file)


    def putcmd(self, line):
        """Internal: send one command to the server (through putline())."""
        if self.debugging: print '*cmd*', repr(line)
        self.putline(line)

#    def getline(self):
#        """Internal: return one line from the server, stripping CRLF.
#        Raise EOFError if the connection is closed."""
#        line = self.file.readline()
#        if self.debugging > 1:
#            print '*get*', repr(line)
#        if not line: raise EOFError
#        if line[-2:] == CRLF: line = line[:-2]
#        elif line[-1:] in CRLF: line = line[:-1]
#        return line

    def getresp(self):
        """Internal: get a response from the server.
        Raise various errors if the response indicates an error."""
        resp = self.getline()
        if self.debugging: print '*resp*', repr(resp)
        c = resp[:1]
        if c == '4':
            raise NNTPTemporaryError(resp)
        if c == '5':
            raise NNTPPermanentError(resp)
        return resp

    def _fillBuffer(self):
        localbuf = self.recv(16384)
        #localbuf = self.file.read()
        if len(localbuf) == 0:
            raise error_proto('-ERR EOF')
        self._writebuf += localbuf

    def getline(self):
        line = ""
        renewline = re.compile(r'.*?\n')
        match = renewline.match(self.buffer)
        while not match:
            self._fillBuffer()
            match = renewline.match(self.buffer)
        line = match.group(0)
        self.buffer = renewline.sub('' ,self.buffer, 1)
        if self.debugging > 1: print '*get*', repr(line)

        if not line: raise EOFError
        if line[-2:] == CRLF: line = line[:-2]
        elif line[-1:] in CRLF: line = line[:-1]
        return line

    def putline(self, line):
        if self.debugging > 1: print '*put*', repr(line)
        line += CRLF
        bytes = len(line)
        while bytes > 0:
            sent = self.file.write(line)
            asyncore.poller.register(self._fileno)
            if sent == bytes:
                break    # avoid copy
            line = line[sent:]
            bytes = bytes - sent

    def quit(self):
        """Process a QUIT command and close the socket.  Returns:
        - resp: server response if successful"""
        try:
            resp = self.shortcmd('QUIT')
        except error_proto, val:
            resp = val
        self.sock.close()
        del self.sslobj, self.sock
        return resp

    def post(self, f):
        """Process a POST command.  Arguments:
        - f: file containing the article
        Returns:
        - resp: server response if successful"""

        resp = self.shortcmd('POST')
        # Raises error_??? if posting is not allowed
        if resp[0] != '3':
            raise NNTPReplyError(resp)
        while 1:
            line = f.readline()
            if not line:
                break
            if line[-1] == '\n':
                line = line[:-1]
            if line[:1] == '.':
                line = '.' + line
            self.putline(line)
        self.putline('.')
        return self.getresp()


    def post_article(self, article):
        self.logger.debug('post_article')
        self._article = article
        article_size = self._article._prepare()
        data = self._article.postfile.read()
        asyncore.poller.register(self._fileno)
        if len(data) > 0:
            f = tempfile.TemporaryFile()
            f.write(data)
            f.seek(0)
            return self.post(f)
       
    def add_channel(self, map=None):
        self.logger.debug('%d: adding FD %d to poller', self.connid, self._fileno)
        
        asyncore.dispatcher.add_channel(self, map)

        # Add ourselves to the poll object
        asyncore.poller.register(self._fileno)
    
    def del_channel(self, map=None):
        self.logger.debug('%d: removing FD %d from poller', self.connid, self._fileno)

        # Remove ourselves from the async map
        asyncore.dispatcher.del_channel(self, map)
        
        # Remove ourselves from the poll object
        if self._fileno is not None:
            try:
                asyncore.poller.unregister(self._fileno)
            except KeyError:
                pass

    def close(self):
        self.logger.debug('close')
        self.del_channel()
        if self.socket is not None:
            self.socket.close()
    
    # -----------------------------------------------------------------------
    # We only want to be writable if we're connecting, or something is in our
    # buffer.

    def writable(self):
        self.logger.debug('writable: %s, %s' % (self.connected,len(self._writebuf)))
        return (not self.connected) or len(self._writebuf)
    
    # Send some data from our buffer when we can write
    def handle_write(self):
        self.logger.debug('%d wants to write!', self._fileno)
        
        if not self.writable():
            # We don't have any buffer, silly thing
            asyncore.poller.register(self._fileno, select.POLLIN)
            return
        
        sent = asyncore.dispatcher.send(self, self._writebuf[self._pointer:])
        self._pointer += sent
        
        # We've run out of data
        if self._pointer == len(self._writebuf):
            self._writebuf = ''
            self._pointer = 0
            asyncore.poller.register(self._fileno, select.POLLIN)
        
        # If we're posting, we might need to read some more data from our file
        if self.mode == MODE_POST_DATA:
            self.parent._bytes += sent
            if len(self._writebuf) == 0:
                self.post_data()
    
    # -----------------------------------------------------------------------
    # We want buffered output, duh
    def send(self, data):
        self._writebuf += data
        # We need to know about writable things now
        asyncore.poller.register(self._fileno)
        self.logger.debug('%d has data!', self._fileno)
    
    # -----------------------------------------------------------------------
    
    def handle_error(self):
        self.logger.exception('%d: unhandled exception!', self.connid)
    
    # -----------------------------------------------------------------------
    
    def handle_connect(self):
        self.state = STATE_CONNECTED
        self.logger.debug('%d: connected!', self.connid)
    
    def handle_close(self):
        self.really_close()
    
    def really_close(self, error=None):
        self.mode = MODE_COMMAND
        self.state = STATE_DISCONNECTED
        
        self.close()
        self.reset()
        
        if error and hasattr(error, 'args'):
            self.logger.warning('%d: %s!', self.connid, error.args[1])
            self.reconnect_at = time.time() + self.parent.conf['server']['reconnect_delay']
        else:
            self.logger.warning('%d: Connection closed: %s', self.connid, error)
    
    # There is some data waiting to be read
    def handle_read(self):
        self.logger.debug('handle_read')
        try:
            self._readbuf += self.recv(16384)
        except socket.error as msg:
            self.really_close(msg)
            return
        
        

        # Split the buffer into lines. Last line is always incomplete/empty.
        lines = str(self._readbuf.decode("utf-8"))
        lines = lines.split('\r\n')
        self._readbuf = lines.pop().encode('utf-8')


        # Do something useful here
        for line in lines:
            self.logger.debug('%d: < Mode:%d %s', self.connid, self.mode, line)

            # Initial login stuff
            if self.mode == MODE_AUTH:
                self.logger.debug('%d: < %s', self.connid, "MODE_AUTH")
                resp = line.split(None, 1)[0]
                
                # Welcome... post, no post
                if resp in ('200', '201'):
                    if self.username:
                        text = 'AUTHINFO USER %s\r\n' % (self.username)
                        self.send(text.encode('utf-8'))
                        self.logger.debug('%d: > AUTHINFO USER ********', self.connid)
                    else:
                        self.mode = MODE_COMMAND
                        self.parent._idle.append(self)
                        self.logger.debug('%d: ready.', self.connid)
                
                # Need password too
                elif resp in ('381'):
                    if self.password:
                        text = 'AUTHINFO PASS %s\r\n' % (self.password)
                        self.send(text.encode('utf-8'))
                        self.logger.debug('%d: > AUTHINFO PASS ********', self.connid)
                    else:
                        self.really_close('need password!')
                
                # Auth ok
                elif resp in ('281'):
                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)
                    self.logger.debug('%d: ready.', self.connid)
                
                # Auth failure
                elif resp in ('502'):
                    self.really_close('authentication failure.')
                
                # Dunno
                else:
                    self.logger.warning('%d: unknown response while MODE_AUTH - "%s"',
                        self.connid, line)
            
            # Posting a file
            elif self.mode == MODE_POST_INIT:
                self.logger.debug('%d: < %s', self.connid, "MODE_POST_INIT")
                resp = line.split(None, 1)[0]
                # Posting is allowed
                if resp == '340':
                    self.mode = MODE_POST_DATA
                    
                    # TODO: use the suggested message-ID, will require some rethinking as to how
                    #       messages are constructed
                    m = MSGID_RE.search(line)
                    if m:
                        self.logger.debug('%d: changing Message-ID to %s', self.connid, m.group(1))
                        self._article.headers['Message-ID'] = m.group(1)

                    # Prepare the article for posting
                    article_size = self._article.prepare()
                    self.parent.remember_msgid(article_size, self._article)

                    self.post_data()
                
                # Posting is not allowed
                elif resp == '440':
                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)
                    del self._article
                    self.logger.warning('%d: posting not allowed!', self.connid)
                
                # WTF?
                else:
                    self.logger.warning('%d: unknown response while MODE_POST_INIT - "%s"',
                        self.connid, line)
            
            # Done posting
            elif self.mode == MODE_POST_DONE:
                resp = line.split(None, 1)[0]
                # Ok
                if resp == '240':
                    #self.parent.post_success(self._article)

                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)

                # Not ok
                elif resp.startswith('44'):
                    self.mode = MODE_COMMAND
                    self.parent._idle.append(self)
                    self.logger.warning('%d: posting failed - %s', self.connid, line)
                
                # WTF?
                else:
                    self.logger.warning('%d: unknown response while MODE_POST_DONE - "%s"',
                        self.connid, line)
            
            # Other stuff
            else:
                self.logger.warning('%d: unknown response from server - "%s"',
                    self.connid, line)
    
    # -----------------------------------------------------------------------
    # Guess what this does!
    def post_article(self, article):
        self.logger.debug('post_article')
        self.mode = MODE_POST_INIT
        self._article = article
        self.send('POST\r\n'.encode('utf-8'))
        self.logger.debug('%d: > POST', self.connid)
    
    def post_data(self):
        self.logger.debug('post_data')
        data = self._article.postfile.read(POST_READ_SIZE)
        if len(data) == 0:
            self.mode = MODE_POST_DONE
            self._article.postfile.close()
            self._article.postfile = None
        
        if len(data) > 0:
            f = open('/tmp/test','wb')
            f.write(data)
            f.close()
        self.send(data)

# ---------------------------------------------------------------------------
