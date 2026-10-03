import asyncio
import os
import time
from types import SimpleNamespace

import pytest

from pyrogram import raw
from pyrogram.client import Client
from pyrogram.raw.core import FutureSalt
from pyrogram.session.session import Result, Session, SessionState

REAL_SLEEP = asyncio.sleep


class StubProtocol:
    crypto_executor = None


class StubConnection:
    def __init__(self):
        self.protocol = StubProtocol()
        self.sent = []

    async def send(self, data):
        self.sent.append(data)

    async def close(self):
        return None


def client(**overrides):
    base = dict(
        loop=asyncio.get_running_loop(),
        is_connected=True,
        session=None,
        media_sessions={},
        sessions={},
        server_time=time.time(),
        connect_handler=None,
        disconnect_handler=None,
        handle_updates=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def started_session(fake=None):
    fake = fake or client()
    session = Session(fake, 2, "149.154.167.51", 443, os.urandom(256), False)
    session.connection = StubConnection()
    session._state = SessionState.STARTED
    session.is_started.set()
    fake.media_sessions[2] = session
    return session


def test_stopping_fails_pending_requests_at_once():
    """Раньше запрос в остановленной сессии ждал полный WAIT_TIMEOUT."""

    async def scenario():
        session = started_session()
        result = Result()
        session.results[1] = result
        started = time.monotonic()
        await session.stop()
        return result, time.monotonic() - started

    result, elapsed = asyncio.run(scenario())

    assert isinstance(result.exception, TimeoutError)
    assert result.event.is_set()
    assert elapsed < 1


def test_a_request_on_a_session_that_never_started_fails_clearly(monkeypatch):
    monkeypatch.setattr(Session, "WAIT_TIMEOUT", 0.05)

    async def scenario():
        session = Session(client(), 2, "149.154.167.51", 443, os.urandom(256), False)
        with pytest.raises(TimeoutError) as raised:
            await session.invoke(raw.functions.help.GetConfig())
        return str(raised.value)

    message = asyncio.run(scenario())

    assert 'invoke "help.GetConfig"' in message


def test_a_restart_queued_before_stop_does_not_reconnect():
    starts = []

    async def scenario():
        session = started_session()

        async def start():
            starts.append(1)

        session.start = start
        restarting = asyncio.get_running_loop().create_task(session.restart())
        await session.stop()
        await restarting
        return session.state

    state = asyncio.run(scenario())

    assert starts == []
    assert state is SessionState.STOPPED


def test_a_stop_during_a_restart_wins():
    async def scenario():
        session = started_session()
        starting, release = asyncio.Event(), asyncio.Event()

        async def start():
            starting.set()
            await release.wait()
            session._state = SessionState.STARTED
            session.is_started.set()

        session.start = start
        restarting = asyncio.get_running_loop().create_task(session.restart())
        await starting.wait()
        await session.stop()
        release.set()
        await restarting
        return session

    session = asyncio.run(scenario())

    assert session.state is SessionState.STOPPED
    assert not session.is_started.is_set()


def test_stop_waits_for_the_tasks_the_session_spawned():
    finished = []

    async def scenario():
        session = started_session()

        async def work():
            await REAL_SLEEP(0.01)
            finished.append(1)

        session._create_tracked_task(work())
        await session.stop()

    asyncio.run(scenario())

    assert finished == [1]


def test_a_task_stuck_at_stop_is_cancelled(monkeypatch):
    monkeypatch.setattr(Session, "STOP_TIMEOUT", 0.05)
    cancelled = []

    async def scenario():
        session = started_session()

        async def stuck():
            try:
                await REAL_SLEEP(10)
            except asyncio.CancelledError:
                cancelled.append(1)
                raise

        session._create_tracked_task(stuck())
        await asyncio.wait_for(session.stop(), timeout=3)

    asyncio.run(scenario())

    assert cancelled == [1]


def test_a_silent_connection_is_restarted(monkeypatch):
    """Полуоткрытое соединение через прокси: ответов нет, а ошибок записи тоже нет."""
    monkeypatch.setattr(Session, "PING_INTERVAL", 0.01)
    monkeypatch.setattr(Session, "SILENCE_TIMEOUT", 0.05)
    restarts = []

    async def scenario():
        session = started_session()
        session.last_received_at = time.monotonic() - 10

        async def restart():
            restarts.append(1)

        session.restart = restart
        await asyncio.wait_for(session.ping_worker(), timeout=3)
        await REAL_SLEEP(0)

    asyncio.run(scenario())

    assert restarts == [1]


def test_a_talking_connection_is_left_alone(monkeypatch):
    monkeypatch.setattr(Session, "PING_INTERVAL", 0.01)
    monkeypatch.setattr(Session, "SILENCE_TIMEOUT", 5)
    restarts = []

    async def scenario():
        session = started_session()
        session.restart = lambda: restarts.append(1)

        async def no_salts():
            return None

        session._update_future_salts = no_salts
        worker = asyncio.get_running_loop().create_task(session.ping_worker())
        await REAL_SLEEP(0.1)
        session.ping_task_event.set()
        await asyncio.wait_for(worker, timeout=3)

    asyncio.run(scenario())

    assert restarts == []


def test_the_next_salt_takes_over_when_its_time_comes():
    async def scenario():
        now = time.time()
        session = started_session()
        session.salt = 1
        session.future_salts = [
            FutureSalt(valid_since=int(now) - 10, valid_until=int(now) + 1800, salt=2),
            FutureSalt(valid_since=int(now) + 1700, valid_until=int(now) + 3600, salt=3),
        ]
        return session._current_salt(now), session.future_salts

    salt, remaining = asyncio.run(scenario())

    assert salt == 2
    assert [item.salt for item in remaining] == [3]


def test_future_salts_are_asked_for_before_the_current_one_runs_out():
    asked = []

    async def scenario():
        now = time.time()
        session = started_session(client(server_time=now))
        session.salt_valid_until = now + 30

        async def send(query, wait_response=True, timeout=None):
            asked.append(type(query).__name__)
            return SimpleNamespace(
                salts=[FutureSalt(valid_since=int(now) + 20, valid_until=int(now) + 2000, salt=9)]
            )

        session.send = send
        await session._update_future_salts()
        await session._update_future_salts()
        return session

    session = asyncio.run(scenario())

    assert asked == ["GetFutureSalts"]
    assert [item.salt for item in session.future_salts] == [9]


def test_a_cdn_session_does_not_ask_for_salts():
    asked = []

    async def scenario():
        session = started_session()
        session.is_cdn = True

        async def send(*args, **kwargs):
            asked.append(1)

        session.send = send
        await session._update_future_salts()

    asyncio.run(scenario())

    assert asked == []


def test_parallel_downloads_share_one_new_media_session(monkeypatch):
    """Шесть параллельных скачиваний создавали шесть сессий и шесть импортов авторизации."""
    created = []

    async def start(self):
        created.append(self.dc_id)
        await REAL_SLEEP(0.01)

    monkeypatch.setattr(Session, "start", start)

    async def scenario():
        app = Client("lock-test", api_id=1, api_hash="0" * 32, in_memory=True)
        await app.storage.open()
        await app.storage.dc_id(2)
        await app.storage.auth_key(os.urandom(256))
        await app.storage.test_mode(False)
        app.session = Session(app, 2, "149.154.167.51", 443, os.urandom(256), False)

        async def get_dc_option(dc_id, is_media=False, ipv6=False, is_cdn=False):
            return raw.types.DcOption(id=dc_id, ip_address="149.154.167.151", port=443)

        app.get_dc_option = get_dc_option
        sessions = await asyncio.gather(*(app.get_session(2, is_media=True) for _ in range(6)))
        return sessions, app.media_sessions

    sessions, cached = asyncio.run(scenario())

    assert len(created) == 1
    assert len({id(item) for item in sessions}) == 1
    assert cached == {2: sessions[0]}


def test_a_retry_waits_for_the_restarted_session_instead_of_a_dead_one(monkeypatch):
    """Повтор уходил в закрытое соединение и ждал полный таймаут вхолостую."""
    monkeypatch.setattr(Session, "RETRY_DELAY", 0)
    attempts = []

    async def scenario():
        session = started_session()
        answer = object()

        async def send(query, wait_response=True, timeout=None):
            attempts.append(session.is_started.is_set())
            if len(attempts) == 1:
                session.is_started.clear()

                async def come_back():
                    await REAL_SLEEP(0.02)
                    session.is_started.set()

                asyncio.get_running_loop().create_task(come_back())
                raise TimeoutError("Request timed out")
            return answer

        session.send = send
        return await session.invoke(raw.functions.help.GetConfig()), answer

    got, answer = asyncio.run(scenario())

    assert got is answer
    assert attempts == [True, True]


def test_sending_through_a_stopped_session_fails_at_once():
    async def scenario():
        session = Session(client(), 2, "149.154.167.51", 443, os.urandom(256), False)
        started = time.monotonic()
        with pytest.raises(TimeoutError, match="not running"):
            await session.send(raw.functions.help.GetConfig())
        return time.monotonic() - started

    assert asyncio.run(scenario()) < 1
