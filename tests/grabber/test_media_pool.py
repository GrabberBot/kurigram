import asyncio
import os
import time
from types import SimpleNamespace

from pyrogram import raw
from pyrogram.client import Client
from pyrogram.file_id import FileId
from pyrogram.session.session import Session

from tests.grabber.test_client_sessions import PHOTO, offline_client

CHUNK = 1024 * 1024
REAL_SLEEP = asyncio.sleep


def quiet_sessions(monkeypatch, fail_from=None):
    started = []

    async def start(self):
        if fail_from is not None and len(started) >= fail_from:
            raise OSError("proxy refused")
        started.append(self)
        self.is_started.set()

    async def stop(self):
        self._must_stay_stopped = True
        self.is_started.clear()

    monkeypatch.setattr(Session, "start", start)
    monkeypatch.setattr(Session, "stop", stop)
    return started


async def client_with_primary():
    client = await offline_client()
    client.is_connected = True
    primary = Session(client, 2, "149.154.167.151", 443, os.urandom(256), False, is_media=True)
    primary.is_started.set()

    async def get_session(dc_id=None, is_media=False, **kwargs):
        return primary

    client.get_session = get_session
    return client, primary


async def settle():
    for _ in range(5):
        await REAL_SLEEP(0)


def test_one_connection_means_no_pool(monkeypatch):
    monkeypatch.setattr(Client, "MEDIA_CONNECTIONS", 1)

    async def scenario():
        client, primary = await client_with_primary()
        sessions = await client.get_media_sessions(2)
        await settle()
        return client, primary, sessions

    client, primary, sessions = asyncio.run(scenario())

    assert sessions == [primary]
    assert client.media_pool == {}


def test_the_pool_grows_in_the_background_with_the_same_key(monkeypatch):
    """Прокси режет скорость на соединение: три соединения дают в 2–3 раза больше одного."""
    monkeypatch.setattr(Client, "MEDIA_CONNECTIONS", 3)
    quiet_sessions(monkeypatch)

    async def scenario():
        client, primary = await client_with_primary()
        first = await client.get_media_sessions(2)
        await settle()
        second = await client.get_media_sessions(2)
        return primary, first, second

    primary, first, second = asyncio.run(scenario())

    assert first == [primary]
    assert len(second) == 3
    assert second[0] is primary
    assert all(session.is_media and session.auth_key == primary.auth_key for session in second)
    assert len({id(session) for session in second}) == 3


def test_a_stopped_pool_connection_is_replaced(monkeypatch):
    monkeypatch.setattr(Client, "MEDIA_CONNECTIONS", 3)
    quiet_sessions(monkeypatch)

    async def scenario():
        client, primary = await client_with_primary()
        await client.get_media_sessions(2)
        await settle()
        gone = client.media_pool[2][0]
        await gone.stop()
        await client.get_media_sessions(2)
        await settle()
        return gone, await client.get_media_sessions(2)

    gone, sessions = asyncio.run(scenario())

    assert gone not in sessions
    assert len(sessions) == 3


def test_a_connection_that_would_not_open_does_not_break_the_download(monkeypatch):
    monkeypatch.setattr(Client, "MEDIA_CONNECTIONS", 3)
    quiet_sessions(monkeypatch, fail_from=1)

    async def scenario():
        client, primary = await client_with_primary()
        await client.get_media_sessions(2)
        await settle()
        return await client.get_media_sessions(2)

    sessions = asyncio.run(scenario())

    assert 1 <= len(sessions) <= 2


def test_a_pool_connection_is_still_wanted_after_a_drop(monkeypatch):
    monkeypatch.setattr(Client, "MEDIA_CONNECTIONS", 2)
    quiet_sessions(monkeypatch)

    async def scenario():
        client, primary = await client_with_primary()
        await client.get_media_sessions(2)
        await settle()
        return client.media_pool[2][0]

    extra = asyncio.run(scenario())

    assert extra._still_wanted()


class Line:
    def __init__(self, data, delay=0.02, started=True):
        self.data = data
        self.delay = delay
        self.is_started = asyncio.Event()
        if started:
            self.is_started.set()
        self.offsets = []
        self.busy = 0

    async def invoke(self, query, *args, **kwargs):
        self.offsets.append(query.offset)
        await REAL_SLEEP(self.delay)
        return raw.types.upload.File(
            type=raw.types.storage.FilePartial(),
            mtime=0,
            bytes=self.data[query.offset: query.offset + query.limit],
        )


def download_over(lines, data, monkeypatch, parallel=3):
    monkeypatch.setattr(Client, "DOWNLOAD_PARALLELISM", parallel)

    async def scenario():
        client = await offline_client()

        async def get_media_sessions(dc_id):
            return lines

        client.get_media_sessions = get_media_sessions
        chunks = []
        async for chunk in client.get_file(FileId.decode(PHOTO), file_size=len(data)):
            chunks.append(chunk)
        return b"".join(chunks)

    return asyncio.run(scenario())


def test_parts_are_spread_over_the_connections(monkeypatch):
    data = os.urandom(CHUNK * 9 + 5)
    lines = [Line(data), Line(data), Line(data)]

    assert download_over(lines, data, monkeypatch) == data
    assert all(len(line.offsets) >= 2 for line in lines)
    assert sorted(o for line in lines for o in line.offsets) == [CHUNK * i for i in range(10)]


def test_a_connection_that_is_not_up_is_skipped(monkeypatch):
    data = os.urandom(CHUNK * 4)
    down = Line(data, started=False)
    lines = [down, Line(data), Line(data)]

    assert download_over(lines, data, monkeypatch) == data
    assert down.offsets == []


def test_busy_counters_return_to_zero(monkeypatch):
    data = os.urandom(CHUNK * 5 + 3)
    lines = [Line(data), Line(data)]

    download_over(lines, data, monkeypatch)

    assert [line.busy for line in lines] == [0, 0]


def test_silence_counts_any_bytes_on_the_wire():
    """Мегабайтный ответ через медленный прокси идёт дольше 30 с; сессию перезапускали посреди него."""
    session = Session.__new__(Session)
    session.last_received_at = time.monotonic() - 100
    session.connection = SimpleNamespace(protocol=SimpleNamespace(last_activity=time.monotonic() - 2))

    assert session.silence() < 5


def test_silence_without_bytes_is_measured_from_the_last_packet():
    session = Session.__new__(Session)
    session.last_received_at = time.monotonic() - 100
    session.connection = SimpleNamespace(protocol=SimpleNamespace(last_activity=time.monotonic() - 100))

    assert session.silence() >= 99


def test_terminate_stops_the_pool(monkeypatch):
    stopped = []

    class Stub:
        def __init__(self, name):
            self.name = name

        async def stop(self):
            stopped.append(self.name)

    async def scenario():
        client = await offline_client()
        client.is_initialized = True
        client.media_pool = {2: [Stub("a"), Stub("b")]}

        async def dispatcher_stop(clear_handlers=False):
            return None

        client.dispatcher.stop = dispatcher_stop
        await client.terminate()
        return client

    client = asyncio.run(scenario())

    assert sorted(stopped) == ["a", "b"]
    assert client.media_pool == {}
