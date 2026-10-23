"""Test doubles for the websocket endpoint: a minimal Redis server and an ASGI websocket client.

redis-py connections are bound to the event loop that opens them, so a test runs the fake Redis,
the websocket sessions and the HTTP requests that use Redis inside one ``asyncio.run`` call.
"""

import asyncio
import contextlib

from etebase_server.fastapi.redis import redisw


class FakeRedis:
    """RESP2 server with the commands the websocket code uses: SET, GET, DEL, SUBSCRIBE, PUBLISH."""

    def __init__(self):
        self.data = {}
        self.subscribers = {}  # channel -> writers of the subscribed connections
        self.writers = set()

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self):
        for writer in list(self.writers):
            writer.close()
        self.server.close()
        await self.server.wait_closed()

    def subscriber_count(self):
        return sum(len(writers) for writers in self.subscribers.values())

    @staticmethod
    def _bulk(value):
        return b"$-1\r\n" if value is None else b"$%d\r\n%s\r\n" % (len(value), value)

    @staticmethod
    async def _read_command(reader):
        line = await reader.readline()
        if not line:
            return None
        args = []
        for _ in range(int(line[1:])):
            size = int((await reader.readline())[1:])
            args.append((await reader.readexactly(size + 2))[:-2])
        return args

    async def _handle(self, reader, writer):
        self.writers.add(writer)
        try:
            while (command := await self._read_command(reader)) is not None:
                name, args = command[0].upper(), command[1:]
                if name == b"SET":
                    self.data[args[0]] = args[1]
                    writer.write(b"+OK\r\n")
                elif name == b"GET":
                    writer.write(self._bulk(self.data.get(args[0])))
                elif name == b"DEL":
                    writer.write(b":%d\r\n" % (self.data.pop(args[0], None) is not None))
                elif name == b"SUBSCRIBE":
                    for channel in args:
                        self.subscribers.setdefault(channel, set()).add(writer)
                        writer.write(b"*3\r\n" + self._bulk(b"subscribe") + self._bulk(channel) + b":1\r\n")
                elif name == b"PUBLISH":
                    receivers = self.subscribers.get(args[0], set())
                    for receiver in receivers:
                        receiver.write(b"*3\r\n" + self._bulk(b"message") + self._bulk(args[0]) + self._bulk(args[1]))
                    writer.write(b":%d\r\n" % len(receivers))
                else:  # CLIENT SETINFO, sent by redis-py on connect
                    writer.write(b"+OK\r\n")
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self.writers.discard(writer)
            for writers in self.subscribers.values():
                writers.discard(writer)
            writer.close()


@contextlib.asynccontextmanager
async def fake_redis():
    """Run a ``FakeRedis`` and point the server's Redis wrapper at it for the duration of the block."""
    server = FakeRedis()
    port = await server.start()
    previous_uri = redisw.redis_uri
    redisw.redis_uri = f"redis://127.0.0.1:{port}"
    await redisw.setup()
    try:
        yield server
    finally:
        await redisw.close()
        del redisw.redis
        redisw.redis_uri = previous_uri
        await server.stop()


class WebSocketSession:
    """ASGI websocket client for the app; it sends no data unless asked, like a real subscriber."""

    def __init__(self, app, path):
        self.messages = asyncio.Queue()  # binary frames sent by the server
        self.close_code = None
        self.error = None
        self._inbox = asyncio.Queue()
        self._inbox.put_nowait({"type": "websocket.connect"})
        scope = {
            "type": "websocket",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [(b"host", b"testserver")],
            "scheme": "ws",
            "server": ("testserver", 80),
            "client": ("testclient", 1),
            "root_path": "",
            "subprotocols": [],
        }
        self._task = asyncio.create_task(self._run(app, scope))

    async def _run(self, app, scope):
        try:
            await app(scope, self._inbox.get, self._send)
        except Exception as e:  # noqa: BLE001 - an ASGI server would log it and drop the connection
            self.error = e

    async def _send(self, message):
        if message["type"] == "websocket.send":
            self.messages.put_nowait(message["bytes"])
        elif message["type"] == "websocket.close":
            self.close_code = message.get("code", 1000)

    async def next_message(self, timeout=2):
        return await asyncio.wait_for(self.messages.get(), timeout)

    async def send(self, data):
        await self._inbox.put({"type": "websocket.receive", "bytes": data})

    async def disconnect(self):
        await self._inbox.put({"type": "websocket.disconnect", "code": 1000})
        await self.wait_finished()

    async def wait_finished(self, timeout=2):
        """Wait until the app is done with the connection, cleanup included."""
        await asyncio.wait_for(asyncio.shield(self._task), timeout)


async def eventually(condition, timeout=2):
    """Wait until ``condition()`` is true, e.g. for the fake Redis to notice a closed connection."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        assert loop.time() < deadline, "condition not met in time"
        await asyncio.sleep(0.01)
