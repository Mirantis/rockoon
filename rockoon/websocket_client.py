# Copyright 2018 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import certifi
import select
import ssl
import time
from enum import IntEnum

from urllib.parse import urlparse, urlunparse

from websocket import WebSocket, ABNF


class channels(IntEnum):
    stdin = 0
    stdout = 1
    stderr = 2
    error = 3


DEFAULT_HTTP_TIMEOUT = 10


class KubernetesWebSocketsClient:
    def __init__(
        self, config, url, headers, timeout=DEFAULT_HTTP_TIMEOUT, verify=True
    ):
        """A websocket client with support for channels.

            Exec command uses different channels for different streams. for
        example, 0 is stdin, 1 is stdout and 2 is stderr. Some other API calls
        like port forwarding can forward different pods' streams to different
        channels.
        """
        self.config = config
        self.timeout = timeout
        self.headers = headers
        self._url = url

        self._connected = False
        self._returncode = None
        self._channels = {}

        self.sock = WebSocket(
            sslopt=self.ssl_headers, skip_utf8_validation=False
        )
        self.sock.connect(self.url, header=headers)

        self._connected = True

    @property
    def url(self):
        parsed_url = urlparse(self._url)
        parts = list(parsed_url)
        if parsed_url.scheme == "http":
            parts[0] = "ws"
        elif parsed_url.scheme == "https":
            parts[0] = "wss"
        return urlunparse(parts)

    @property
    def ssl_ca_certs(self):
        ca_certs = certifi.where()
        # setup certificate verification
        if os.environ.get("PYKUBE_SSL_CERTIFICATE_AUTHORITY") is not None:
            ca_certs = os.environ.get("PYKUBE_SSL_CERTIFICATE_AUTHORITY")
        elif "certificate-authority" in self.config.cluster:
            ca_certs = self.config.cluster["certificate-authority"].filename()

        return ca_certs

    @property
    def ssl_verify(self):
        return self.config.cluster.get("insecure-skip-tls-verify", True)

    @property
    def ssl_headers(self):
        headers = {}

        if self.url.startswith("wss://") and self.ssl_verify:
            headers["cert_reqs"] = ssl.CERT_REQUIRED
            headers["ca_certs"] = self.ssl_ca_certs
            if "client-certificate" in self.config.user:
                headers["certfile"] = self.config.user[
                    "client-certificate"
                ].filename()
                headers["keyfile"] = self.config.user["client-key"].filename()
        else:
            headers["cert_reqs"] = ssl.CERT_NONE

        # support for tls-server-name
        if "tls-server-name" in self.config.cluster:
            headers["check_hostname"] = self.config.cluster["tls-server-name"]
            headers["server_hostname"] = self.config.cluster["tls-server-name"]
        return headers

    # start
    def peek_channel(self, channel, timeout=0):
        """Peek a channel and return part of the input,
        empty string otherwise."""
        self.update(timeout=timeout)
        if channel in self._channels:
            return self._channels[channel]
        return ""

    def read_channel(self, channel, timeout=0):
        """Read data from a channel."""
        if channel not in self._channels:
            ret = self.peek_channel(channel, timeout)
        else:
            ret = self._channels[channel]
        if channel in self._channels:
            del self._channels[channel]
        return ret

    def readline_channel(self, channel, timeout=None):
        """Read a line from a channel."""
        if timeout is None:
            timeout = float("inf")
        start = time.time()
        while self.is_open() and time.time() - start < timeout:
            if channel in self._channels:
                data = self._channels[channel]
                if "\n" in data:
                    index = data.find("\n")
                    ret = data[:index]
                    data = data[index + 1 :]
                    if data:
                        self._channels[channel] = data
                    else:
                        del self._channels[channel]
                    return ret
            self.update(timeout=(timeout - time.time() + start))

    def write_channel(self, channel, data):
        """Write data to a channel."""
        # check if we're writing binary data or not
        binary = isinstance(data, bytes)
        opcode = ABNF.OPCODE_BINARY if binary else ABNF.OPCODE_TEXT

        channel_prefix = chr(channel)
        if binary:
            channel_prefix = channel_prefix.encode(encoding="ascii")

        payload = channel_prefix + data
        self.sock.send(payload, opcode=opcode)

    def peek_stdout(self, timeout=0):
        """Same as peek_channel with channel=1."""
        return self.peek_channel(channels.stdout, timeout=timeout)

    def read_stdout(self, timeout=None):
        """Same as read_channel with channel=1."""
        return self.read_channel(channels.stdout, timeout=timeout)

    def readline_stdout(self, timeout=None):
        """Same as readline_channel with channel=1."""
        return self.readline_channel(channels.stdout, timeout=timeout)

    def peek_stderr(self, timeout=0):
        """Same as peek_channel with channel=2."""
        return self.peek_channel(channels.stderr, timeout=timeout)

    def read_stderr(self, timeout=None):
        """Same as read_channel with channel=2."""
        return self.read_channel(channels.stderr, timeout=timeout)

    def readline_stderr(self, timeout=None):
        """Same as readline_channel with channel=2."""
        return self.readline_channel(channels.stderr, timeout=timeout)

    def write_stdin(self, data):
        """The same as write_channel with channel=0."""
        self.write_channel(channels.stdin, data)

    def read_all(self):
        """Return buffered data received on stdout and stderr channels.
        This is useful for non-interactive call where a set of command passed
        to the API call and their result is needed after the call is concluded.
        Should be called after run_forever() or update()

        TODO: Maybe we can process this and return a more meaningful map with
        channels mapped for each input.
        """
        out = {}
        for channel, data in self._channels.items():
            out[channels(channel).name] = data
        self._channels = {}
        return out

    def is_open(self):
        """True if the connection is still alive."""
        return self._connected

    def update(self, timeout=0):
        """Update channel buffers with at most one complete frame of input."""
        if not self.is_open():
            return
        if not self.sock.connected:
            self._connected = False
            return

        # The options here are:
        # select.select() - this will work on most OS, however, it has a
        #                   limitation of only able to read fd numbers up to 1024.
        #                   i.e. does not scale well. This was the original
        #                   implementation.
        # select.poll()   - this will work on most unix based OS, but not as
        #                   efficient as epoll. Will work for fd numbers above 1024.
        # select.epoll()  - newest and most efficient way of polling.
        #                   However, only works on linux.
        if hasattr(select, "poll"):
            poll = select.poll()
            poll.register(self.sock.sock, select.POLLIN)
            if timeout is not None:
                timeout *= (
                    1_000  # poll method uses milliseconds as the time unit
                )
            r = poll.poll(timeout)
            poll.unregister(self.sock.sock)
        else:
            r, _, _ = select.select((self.sock.sock,), (), (), timeout)

        if r:
            op_code, frame = self.sock.recv_data_frame(True)
            if op_code == ABNF.OPCODE_CLOSE:
                self._connected = False
                return
            elif op_code == ABNF.OPCODE_BINARY or op_code == ABNF.OPCODE_TEXT:
                data = frame.data
                data = data.decode("utf-8", "replace")
                if len(data) > 1:
                    channel = ord(data[0])
                    data = data[1:]
                    if data:
                        if channel not in self._channels:
                            self._channels[channel] = data
                        else:
                            self._channels[channel] += data

    def run_forever(self, timeout=None):
        """Wait till connection is closed or timeout reached. Buffer any input
        received during this time.
        :raises TimeoutError: When reached specified timeout.
        """
        if timeout:
            start = time.time()
            while self.is_open() and time.time() - start < timeout:
                self.update(timeout=(timeout - time.time() + start))
            if self.is_open():
                raise TimeoutError("Timeout reached waiting for socket close")
        else:
            while self.is_open():
                self.update(timeout=None)

    def close(self, **kwargs):
        """
        close websocket connection.
        """
        self._connected = False
        if self.sock:
            self.sock.close(**kwargs)
