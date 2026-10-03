import asyncio
import os

import pytest

from pyrogram import raw
from pyrogram.client import Client
from pyrogram.file_id import FileId

from tests.grabber.test_client_sessions import PHOTO, offline_client

CHUNK = 1024 * 1024
REAL_SLEEP = asyncio.sleep


class FileSession:
    def __init__(self, data: bytes, delay: float = 0.01, fail_at=None):
        self.data = data
        self.delay = delay
        self.fail_at = fail_at
        self.in_flight = 0
        self.peak = 0
        self.offsets = []
        self.cancelled = 0

    async def invoke(self, query, *args, **kwargs):
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        self.offsets.append(query.offset)
        try:
            await REAL_SLEEP(self.delay)
            if self.fail_at is not None and query.offset == self.fail_at:
                raise ConnectionError("lost")
            return raw.types.upload.File(
                type=raw.types.storage.FilePartial(),
                mtime=0,
                bytes=self.data[query.offset: query.offset + query.limit],
            )
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        finally:
            self.in_flight -= 1


def download(session, size_hint, parallel, monkeypatch, stop_after=None, per_connection=8):
    monkeypatch.setattr(Client, "DOWNLOAD_PARALLELISM", parallel)
    monkeypatch.setattr(Client, "MEDIA_PARTS_PER_CONNECTION", per_connection)

    async def scenario():
        client = await offline_client()

        async def get_session(*args, **kwargs):
            return session

        client.get_session = get_session
        chunks = []
        generator = client.get_file(FileId.decode(PHOTO), file_size=size_hint)
        async for chunk in generator:
            chunks.append(chunk)
            if stop_after is not None and len(chunks) >= stop_after:
                await generator.aclose()
                break
        return b"".join(chunks)

    return asyncio.run(scenario())


def test_a_file_comes_out_whole_and_in_order(monkeypatch):
    data = os.urandom(CHUNK * 5 + 1234)
    session = FileSession(data)

    assert download(session, len(data), 4, monkeypatch) == data


def test_parts_are_fetched_side_by_side(monkeypatch):
    """Через прокси с задержкой в секунды последовательные куски упирались в задержку."""
    data = os.urandom(CHUNK * 8)
    session = FileSession(data, delay=0.03)

    download(session, len(data), 4, monkeypatch)

    assert session.peak >= 3


def test_without_parallelism_it_stays_sequential(monkeypatch):
    data = os.urandom(CHUNK * 4 + 10)
    session = FileSession(data)

    assert download(session, len(data), 1, monkeypatch) == data
    assert session.peak == 1


def test_an_unknown_size_is_downloaded_sequentially(monkeypatch):
    data = os.urandom(CHUNK * 3 + 10)
    session = FileSession(data)

    assert download(session, 0, 4, monkeypatch) == data
    assert session.peak == 1


def test_an_understated_size_still_yields_the_whole_file(monkeypatch):
    """Если размер в метаданных меньше настоящего, хвост докачивается по-старому."""
    data = os.urandom(CHUNK * 6 + 99)
    session = FileSession(data)

    assert download(session, CHUNK * 2, 4, monkeypatch) == data


def test_an_exact_multiple_of_the_chunk_ends_cleanly(monkeypatch):
    data = os.urandom(CHUNK * 4)
    session = FileSession(data)

    assert download(session, len(data), 4, monkeypatch) == data


def test_a_failed_part_cancels_the_rest(monkeypatch):
    data = os.urandom(CHUNK * 8)
    session = FileSession(data, delay=0.05, fail_at=CHUNK * 2)

    with pytest.raises(ConnectionError):
        download(session, len(data), 4, monkeypatch)

    assert session.in_flight == 0


def test_stopping_early_cancels_the_parts_requested_ahead(monkeypatch):
    data = os.urandom(CHUNK * 8)
    session = FileSession(data, delay=0.05)

    got = download(session, len(data), 4, monkeypatch, stop_after=2)

    assert got == data[: CHUNK * 2]
    assert session.in_flight == 0


def test_a_loaded_connection_gets_no_parts_ahead(monkeypatch):
    """Части наперёд в одном медленном соединении только отодвигали нужную по порядку."""
    data = os.urandom(CHUNK * 8 + 7)
    session = FileSession(data, delay=0.02)

    assert download(session, len(data), 4, monkeypatch, per_connection=2) == data
    assert session.peak <= 2


def test_parts_cancelled_before_they_start_release_their_connection(monkeypatch):
    data = os.urandom(CHUNK * 8)
    session = FileSession(data, delay=0.05)

    download(session, len(data), 4, monkeypatch, stop_after=1)

    assert session.busy == 0


class Recording(FileSession):
    def __init__(self, data):
        super().__init__(data)
        self.timeouts = []

    async def invoke(self, query, *args, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        return await super().invoke(query, *args, **kwargs)


def test_file_parts_wait_long_instead_of_being_sent_again(monkeypatch):
    """Ответ в очереди медленного соединения не успевал за 60 с, часть запрашивалась заново, и мегабайт шёл дважды."""
    monkeypatch.setattr(Client, "FILE_PART_TIMEOUT", 321)
    data = os.urandom(CHUNK * 4 + 5)
    session = Recording(data)

    assert download(session, len(data), 3, monkeypatch) == data
    assert session.timeouts and set(session.timeouts) == {321}
