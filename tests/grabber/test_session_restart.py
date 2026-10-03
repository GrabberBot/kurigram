import asyncio
import os
from types import SimpleNamespace

from python_socks import ProxyError

from pyrogram.connection.connection import Connection
from pyrogram.session.session import Session, SessionState


class RefusingProtocol:
    def __init__(self, **kwargs):
        self.crypto_executor = None

    async def connect(self, address):
        raise ProxyError("Connection not allowed by ruleset", 2)

    async def close(self):
        return None


def client(**overrides):
    loop = asyncio.get_running_loop()
    base = dict(
        connection_factory=Connection,
        proxy=None,
        protocol_factory=RefusingProtocol,
        loop=loop,
        init_connection_params=None,
        connect_handler=None,
        disconnect_handler=None,
        name="test",
        storage=None,
        ipv6=False,
        is_connected=True,
        session=None,
        media_sessions={},
        sessions={},
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def session_for(fake):
    session = Session(fake, 2, "149.154.167.151", 443, os.urandom(256), False, is_media=True)
    fake.media_sessions[2] = session
    return session


REAL_SLEEP = asyncio.sleep


def fast(monkeypatch):
    async def instant(_seconds):
        await REAL_SLEEP(0)

    monkeypatch.setattr("pyrogram.connection.connection.asyncio.sleep", instant)
    monkeypatch.setattr(Session, "RESTART_RETRY_DELAY", 0)


def test_a_proxy_refusal_counts_as_a_network_failure(monkeypatch):
    fast(monkeypatch)

    async def scenario():
        connection = Connection(
            2, "149.154.167.151", 443, False,
            protocol_factory=RefusingProtocol, loop=asyncio.get_running_loop(),
        )
        try:
            await connection.connect()
        except ConnectionError:
            return True
        return False

    assert asyncio.run(scenario())


def test_a_refused_restart_keeps_trying_instead_of_dying(monkeypatch):
    fast(monkeypatch)
    attempts = {"n": 0}

    async def scenario():
        fake = client()
        session = session_for(fake)
        original = Session.start

        async def counting_start(self):
            attempts["n"] += 1
            if attempts["n"] >= 4:
                fake.is_connected = False
            await original(self)

        monkeypatch.setattr(Session, "start", counting_start)
        task = asyncio.create_task(session.restart())
        for _ in range(200):
            await REAL_SLEEP(0)
        await task
        return task

    task = asyncio.run(scenario())

    assert task.exception() is None
    assert attempts["n"] >= 3


def test_a_restart_stops_once_the_session_was_dropped(monkeypatch):
    fast(monkeypatch)
    starts = {"n": 0}

    async def scenario():
        fake = client()
        session = session_for(fake)

        async def failing_start(self):
            starts["n"] += 1
            raise RuntimeError("File descriptor 58 is used by transport")

        monkeypatch.setattr(Session, "start", failing_start)
        fake.media_sessions.clear()
        try:
            await session.restart()
        except RuntimeError:
            return "raised"
        return "returned"

    outcome = asyncio.run(scenario())

    assert outcome == "raised"
    assert starts["n"] == 1


def test_an_unexpected_failure_while_wanted_is_retried(monkeypatch):
    fast(monkeypatch)
    starts = {"n": 0}

    async def scenario():
        fake = client()
        session = session_for(fake)

        async def flaky_start(self):
            starts["n"] += 1
            if starts["n"] == 1:
                raise RuntimeError("File descriptor 58 is used by transport")
            fake.is_connected = False

        monkeypatch.setattr(Session, "start", flaky_start)
        await session.restart()
        for _ in range(50):
            await REAL_SLEEP(0)

    asyncio.run(scenario())

    assert starts["n"] == 2


def test_a_session_of_a_stopped_client_is_not_revived(monkeypatch):
    fast(monkeypatch)

    async def scenario():
        fake = client(is_connected=False)
        session = session_for(fake)
        return session._still_wanted()

    assert asyncio.run(scenario()) is False


def test_the_state_ends_stopped_not_hanging_after_a_refusal(monkeypatch):
    fast(monkeypatch)

    async def scenario():
        fake = client()
        session = session_for(fake)
        fake.is_connected = False
        await session.restart()
        return session.state

    assert asyncio.run(scenario()) in (SessionState.STOPPED, SessionState.STARTING)
