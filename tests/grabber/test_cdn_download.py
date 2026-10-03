import asyncio
import os
from hashlib import sha256
from types import SimpleNamespace

import pytest

from pyrogram import raw
from pyrogram.client import Client
from pyrogram.crypto import aes
from pyrogram.errors import CDNFileHashMismatch
from pyrogram.file_id import FileId
from pyrogram.session.session import Session

from tests.grabber.test_client_sessions import PHOTO, dc_option, offline_client

CHUNK = 1024 * 1024
PIECE = 128 * 1024
REAL_SLEEP = asyncio.sleep


class Cdn:
    def __init__(self, data, *, hashes_per_answer=8, first_hashes=0, reupload_at=None, corrupt_at=None):
        self.data = data
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        self.token = b"token"
        self.hashes_per_answer = hashes_per_answer
        self.first_hashes = first_hashes
        self.reupload_at = reupload_at
        self.reuploaded = False
        self.corrupt_at = corrupt_at
        self.master = FakeMaster(self)
        self.session = FakeCdnSession(self)

    def hashes_from(self, offset, count):
        return [
            raw.types.FileHash(
                offset=start,
                limit=PIECE,
                hash=sha256(self.data[start:start + PIECE]).digest(),
            )
            for start in range(offset, min(len(self.data), offset + count * PIECE), PIECE)
        ]

    def part(self, offset, limit):
        plain = self.data[offset:offset + limit]
        if not plain:
            return b""
        if self.corrupt_at is not None and offset == self.corrupt_at:
            plain = bytes([plain[0] ^ 1]) + plain[1:]
        return aes.ctr256_encrypt(
            plain,
            self.key,
            bytearray(self.iv[:-4] + (offset // 16).to_bytes(4, "big")),
        )


class FakeMaster:
    def __init__(self, cdn):
        self.cdn = cdn
        self.queries = []

    async def invoke(self, query, *args, **kwargs):
        self.queries.append(query)
        if isinstance(query, raw.functions.upload.GetFile):
            return raw.types.upload.FileCdnRedirect(
                dc_id=203,
                file_token=self.cdn.token,
                encryption_key=self.cdn.key,
                encryption_iv=self.cdn.iv,
                file_hashes=self.cdn.hashes_from(0, self.cdn.first_hashes),
            )
        if isinstance(query, raw.functions.upload.GetCdnFileHashes):
            return self.cdn.hashes_from(query.offset, self.cdn.hashes_per_answer)
        if isinstance(query, raw.functions.upload.ReuploadCdnFile):
            self.cdn.reuploaded = True
            return []
        raise AssertionError(query)


class FakeCdnSession:
    def __init__(self, cdn):
        self.cdn = cdn
        self.cdn_initialized = False
        self.queries = []
        self.in_flight = 0
        self.peak = 0
        self.stopped = False

    async def invoke(self, query, *args, **kwargs):
        self.queries.append(query)
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            await REAL_SLEEP(0.01)
            inner = query
            while not isinstance(inner, raw.functions.upload.GetCdnFile):
                inner = inner.query
            if inner.offset == self.cdn.reupload_at and not self.cdn.reuploaded:
                return raw.types.upload.CdnFileReuploadNeeded(request_token=b"again")
            return raw.types.upload.CdnFile(bytes=self.cdn.part(inner.offset, inner.limit))
        finally:
            self.in_flight -= 1

    async def stop(self):
        self.stopped = True


def download(cdn, monkeypatch, parallel=4, size_hint=None):
    monkeypatch.setattr(Client, "DOWNLOAD_PARALLELISM", parallel)
    asked = []

    async def scenario():
        client = await offline_client()

        async def get_session(dc_id=None, is_media=False, is_cdn=False, **kwargs):
            asked.append((dc_id, is_media, is_cdn, kwargs))
            return cdn.session if is_cdn else cdn.master

        client.get_session = get_session
        chunks = []
        size = len(cdn.data) if size_hint is None else size_hint
        async for chunk in client.get_file(FileId.decode(PHOTO), file_size=size):
            chunks.append(chunk)
        return b"".join(chunks)

    return asyncio.run(scenario()), asked


def test_a_cdn_file_comes_out_decrypted_whole_and_in_order(monkeypatch):
    cdn = Cdn(os.urandom(CHUNK * 5 + 4321))

    data, _ = download(cdn, monkeypatch)

    assert data == cdn.data


def test_cdn_parts_are_fetched_side_by_side(monkeypatch):
    cdn = Cdn(os.urandom(CHUNK * 8))

    download(cdn, monkeypatch)

    assert cdn.session.peak >= 3


def test_the_cdn_session_is_kept_for_the_next_file(monkeypatch):
    """Раньше на каждый файл создавался новый ключ на CDN — лишний DH и повод для отказов."""
    cdn = Cdn(os.urandom(1000))

    _, asked = download(cdn, monkeypatch)

    assert asked[1][:3] == (203, False, True)
    assert not asked[1][3].get("temporary", False)
    assert asked[1][3]["export_authorization"] is False
    assert not cdn.session.stopped


def test_only_the_first_request_of_a_session_is_wrapped(monkeypatch):
    cdn = Cdn(os.urandom(CHUNK * 2 + 10))

    download(cdn, monkeypatch, parallel=1)

    first, *rest = cdn.session.queries
    assert isinstance(first, raw.functions.InvokeWithLayer)
    assert isinstance(first.query, raw.functions.InitConnection)
    assert isinstance(first.query.query, raw.functions.upload.GetCdnFile)
    assert all(isinstance(query, raw.functions.upload.GetCdnFile) for query in rest)


def test_a_restarted_cdn_session_is_initialized_again():
    """После переподключения CDN снова ждёт initConnection перед первым запросом."""

    async def scenario():
        client = await offline_client()

        def refuse(**kwargs):
            raise OSError("no route")

        client.connection_factory = refuse
        session = Session(client, 203, "91.108.56.181", 443, os.urandom(256), False, is_cdn=True)
        session.cdn_initialized = True
        with pytest.raises(OSError):
            await session.start()
        return session

    assert asyncio.run(scenario()).cdn_initialized is False


def test_hashes_from_the_redirect_are_used_and_the_rest_fetched(monkeypatch):
    cdn = Cdn(os.urandom(CHUNK * 3), first_hashes=8, hashes_per_answer=8)

    data, _ = download(cdn, monkeypatch)

    assert data == cdn.data
    asked = [q.offset for q in cdn.master.queries if isinstance(q, raw.functions.upload.GetCdnFileHashes)]
    assert asked == [CHUNK, CHUNK * 2]


def test_hashes_spanning_several_parts_are_fetched_once(monkeypatch):
    cdn = Cdn(os.urandom(CHUNK * 4), hashes_per_answer=32)

    download(cdn, monkeypatch)

    asked = [q for q in cdn.master.queries if isinstance(q, raw.functions.upload.GetCdnFileHashes)]
    assert len(asked) == 1


def test_a_tampered_part_is_rejected(monkeypatch):
    cdn = Cdn(os.urandom(CHUNK * 3), corrupt_at=CHUNK)

    with pytest.raises(CDNFileHashMismatch):
        download(cdn, monkeypatch)


def test_a_part_without_a_hash_is_rejected(monkeypatch):
    cdn = Cdn(os.urandom(CHUNK), hashes_per_answer=0)

    with pytest.raises(CDNFileHashMismatch):
        download(cdn, monkeypatch)


def test_a_reupload_request_is_honoured_and_the_part_asked_again(monkeypatch):
    cdn = Cdn(os.urandom(CHUNK * 3), reupload_at=CHUNK * 2)

    data, _ = download(cdn, monkeypatch)

    assert data == cdn.data
    assert cdn.reuploaded
    assert any(isinstance(q, raw.functions.upload.ReuploadCdnFile) for q in cdn.master.queries)


def test_an_unknown_size_is_fetched_from_the_cdn_sequentially(monkeypatch):
    cdn = Cdn(os.urandom(CHUNK * 2 + 77))

    data, _ = download(cdn, monkeypatch, size_hint=0)

    assert data == cdn.data
    assert cdn.session.peak == 1


def test_a_cdn_session_is_created_once_and_kept(monkeypatch):
    calls = []

    async def start(self):
        calls.append(("start", self.dc_id, self.is_cdn))

    async def create(self):
        calls.append(("auth", self.dc_id))
        return os.urandom(256)

    monkeypatch.setattr(Session, "start", start)
    monkeypatch.setattr("pyrogram.client.Auth.create", create)

    async def scenario():
        client = await offline_client()
        client.get_dc_option = dc_option("91.108.56.181")

        async def load_cdn_keys():
            calls.append(("keys",))

        async def invoke(query, *args, **kwargs):
            calls.append(("invoke", type(query).__name__))

        client.load_cdn_keys = load_cdn_keys
        client.invoke = invoke
        first = await client.get_session(203, is_cdn=True, export_authorization=False)
        second = await client.get_session(203, is_cdn=True, export_authorization=False)
        return client, first, second

    client, first, second = asyncio.run(scenario())

    assert first is second
    assert client.sessions[203] is first
    assert first.is_cdn
    assert calls.count(("auth", 203)) == 1
    assert not any(call[0] == "invoke" for call in calls)


def test_terminate_stops_the_sessions_to_other_dcs(monkeypatch):
    stopped = []

    class Stub:
        def __init__(self, name):
            self.name = name

        async def stop(self):
            stopped.append(self.name)

    async def scenario():
        client = await offline_client()
        client.is_initialized = True
        client.sessions = {4: Stub("dc4"), 203: Stub("cdn203")}
        client.media_sessions = {2: Stub("media2")}

        async def dispatcher_stop(clear_handlers=False):
            return None

        client.dispatcher.stop = dispatcher_stop
        await client.terminate()
        return client

    client = asyncio.run(scenario())

    assert sorted(stopped) == ["cdn203", "dc4", "media2"]
    assert client.sessions == {}
    assert client.media_sessions == {}


def test_a_cdn_dc_missing_from_the_config_falls_back_to_its_known_address():
    async def scenario():
        client = await offline_client()

        async def invoke(query, *args, **kwargs):
            return SimpleNamespace(
                this_dc=2,
                dc_options=[raw.types.DcOption(id=2, ip_address="149.154.167.51", port=443)],
            )

        client.invoke = invoke
        found = await client.get_dc_option(203, is_cdn=True)
        with pytest.raises(ValueError, match="DC201 not found among 2"):
            await client.get_dc_option(201, is_cdn=True)
        return found

    found = asyncio.run(scenario())

    assert found.ip_address == "91.105.192.100"
    assert found.cdn


class SwitchingMaster(FakeMaster):
    def __init__(self, cdn, switch_at):
        super().__init__(cdn)
        self.switch_at = switch_at

    async def invoke(self, query, *args, **kwargs):
        if isinstance(query, raw.functions.upload.GetFile) and query.offset < self.switch_at:
            self.queries.append(query)
            await REAL_SLEEP(0.01)
            return raw.types.upload.File(
                type=raw.types.storage.FilePartial(),
                mtime=0,
                bytes=self.cdn.data[query.offset:query.offset + query.limit],
            )
        return await super().invoke(query, *args, **kwargs)


@pytest.mark.parametrize("parallel", [1, 3])
def test_a_redirect_in_the_middle_continues_from_the_cdn(monkeypatch, parallel):
    """Популярный файл уходит на CDN посреди скачивания; раньше это был ValueError и потерянный файл."""
    cdn = Cdn(os.urandom(CHUNK * 5 + 99))
    cdn.master = SwitchingMaster(cdn, CHUNK * 2)

    data, _ = download(cdn, monkeypatch, parallel=parallel)

    assert data == cdn.data
    cdn_offsets = sorted(
        (q if isinstance(q, raw.functions.upload.GetCdnFile) else q.query.query).offset
        for q in cdn.session.queries
    )
    assert cdn_offsets[0] == CHUNK * 2


def test_cdn_parts_wait_long_too(monkeypatch):
    monkeypatch.setattr(Client, "FILE_PART_TIMEOUT", 321)
    cdn = Cdn(os.urandom(CHUNK * 3 + 1))
    seen = []
    original = cdn.session.invoke

    async def invoke(query, *args, **kwargs):
        seen.append(kwargs.get("timeout"))
        return await original(query, *args, **kwargs)

    cdn.session.invoke = invoke

    data, _ = download(cdn, monkeypatch)

    assert data == cdn.data
    assert seen and set(seen) == {321}
