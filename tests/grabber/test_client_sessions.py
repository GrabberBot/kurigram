import asyncio
import os
import re
from pathlib import Path

import pytest

from pyrogram import raw
from pyrogram.client import Client
from pyrogram.crypto import rsa
from pyrogram.file_id import FileId
from pyrogram.session.session import Session

PHOTO = (
    "AgACAgIAAx0CVLpJTwABASf4arzGPk3sOourje38vyRrbJAGbdsAAnMqaxsvkOBJzLJ3XgGLiH8AC"
    "AEAAwIAA3kABx4E"
)


def builtin_pem():
    source = Path(rsa.__file__).read_text()
    fingerprint, comment = re.findall(
        r"(0x[0-9a-f]+) - \(1 << 64\): PublicKey\(.*?\n((?:\s*# .*\n)+)", source
    )[0]
    lines = [line.strip().lstrip("#").strip() for line in comment.splitlines()]
    start = lines.index("-----BEGIN RSA PUBLIC KEY-----")
    end = lines.index("-----END RSA PUBLIC KEY-----")
    return int(fingerprint, 16) - (1 << 64), "\n".join(lines[start:end + 1])


async def offline_client():
    client = Client("grabber-test", api_id=1, api_hash="0" * 32, in_memory=True)
    await client.storage.open()
    await client.storage.dc_id(2)
    await client.storage.auth_key(os.urandom(256))
    await client.storage.test_mode(False)
    await client.storage.api_id(1)
    client.session = Session(client, 2, "149.154.167.51", 443, os.urandom(256), False)
    return client


def dc_option(ip="149.154.167.151"):
    async def get_dc_option(dc_id, is_media=False, ipv6=False, is_cdn=False):
        return raw.types.DcOption(id=dc_id, ip_address=ip, port=443)

    return get_dc_option


def test_a_media_session_that_failed_to_start_is_not_kept(monkeypatch):
    async def broken_start(self):
        raise RuntimeError("File descriptor 58 is used by transport")

    async def stop(self):
        return None

    monkeypatch.setattr(Session, "start", broken_start)
    monkeypatch.setattr(Session, "stop", stop)

    async def scenario():
        client = await offline_client()
        client.get_dc_option = dc_option()
        with pytest.raises(RuntimeError):
            await client.get_session(2, is_media=True)
        return client.media_sessions

    assert asyncio.run(scenario()) == {}


def test_a_media_session_that_started_is_kept(monkeypatch):
    async def start(self):
        return None

    monkeypatch.setattr(Session, "start", start)

    async def scenario():
        client = await offline_client()
        client.get_dc_option = dc_option()
        session = await client.get_session(2, is_media=True)
        return client.media_sessions, session

    sessions, session = asyncio.run(scenario())

    assert sessions == {2: session}


def test_cdn_keys_are_learned_from_the_master_dc():
    fingerprint, pem = builtin_pem()
    original = rsa.server_public_keys.pop(fingerprint)

    async def scenario():
        client = await offline_client()

        async def invoke(query, *args, **kwargs):
            assert isinstance(query, raw.functions.help.GetCdnConfig)
            return raw.types.CdnConfig(
                public_keys=[raw.types.CdnPublicKey(dc_id=203, public_key=pem)]
            )

        client.invoke = invoke
        await client.load_cdn_keys()

    try:
        asyncio.run(scenario())
        assert rsa.server_public_keys[fingerprint] == original
    finally:
        rsa.server_public_keys[fingerprint] = original


def test_a_cdn_session_gets_keys_and_no_authorization_export(monkeypatch):
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
        session = await client.get_session(
            203, is_cdn=True, temporary=True, export_authorization=False
        )
        return client, session

    client, session = asyncio.run(scenario())

    assert ("keys",) in calls
    assert ("auth", 203) in calls
    assert ("start", 203, True) in calls
    assert not any(call[0] == "invoke" for call in calls)
    assert 203 not in client.sessions


class FakeSession:
    def __init__(self, name, answers):
        self.name = name
        self.answers = answers
        self.queries = []

    async def invoke(self, query, *args, **kwargs):
        self.queries.append(query)
        answer = self.answers(query)
        if isinstance(answer, Exception):
            raise answer
        return answer

    async def stop(self):
        self.queries.append("stopped")


def test_a_cdn_redirect_downloads_from_the_cdn_dc(monkeypatch):
    key, iv = os.urandom(32), os.urandom(16)
    master = FakeSession(
        "master",
        lambda query: (
            raw.types.upload.FileCdnRedirect(
                dc_id=203, file_token=b"token", encryption_key=key,
                encryption_iv=iv, file_hashes=[],
            )
            if isinstance(query, raw.functions.upload.GetFile)
            else []
        ),
    )
    cdn = FakeSession("cdn", lambda query: raw.types.upload.CdnFile(bytes=b"x" * 100))
    asked = []

    async def scenario():
        client = await offline_client()

        async def get_session(dc_id=None, is_media=False, is_cdn=False, **kwargs):
            asked.append((dc_id, is_media, is_cdn, kwargs.get("export_authorization", True)))
            return cdn if is_cdn else master

        client.get_session = get_session
        chunks = []
        async for chunk in client.get_file(FileId.decode(PHOTO), file_size=100):
            chunks.append(chunk)
        return chunks

    chunks = asyncio.run(scenario())

    assert asked[0] == (2, True, False, True)
    assert asked[1] == (203, False, True, False)
    first = cdn.queries[0]
    assert isinstance(first, raw.functions.InvokeWithLayer)
    assert isinstance(first.query, raw.functions.InitConnection)
    assert isinstance(first.query.query, raw.functions.upload.GetCdnFile)
    assert cdn.queries[-1] == "stopped"
    assert len(b"".join(chunks)) == 100


def test_later_cdn_requests_are_not_wrapped_again(monkeypatch):
    key, iv = os.urandom(32), os.urandom(16)
    master = FakeSession(
        "master",
        lambda query: (
            raw.types.upload.FileCdnRedirect(
                dc_id=203, file_token=b"token", encryption_key=key,
                encryption_iv=iv, file_hashes=[],
            )
            if isinstance(query, raw.functions.upload.GetFile)
            else []
        ),
    )
    sizes = iter([1024 * 1024, 10])
    cdn = FakeSession("cdn", lambda query: raw.types.upload.CdnFile(bytes=b"y" * next(sizes)))

    async def scenario():
        client = await offline_client()

        async def get_session(dc_id=None, is_media=False, is_cdn=False, **kwargs):
            return cdn if is_cdn else master

        client.get_session = get_session
        async for _ in client.get_file(FileId.decode(PHOTO), file_size=1024 * 1024 + 10):
            pass

    asyncio.run(scenario())

    queries = [q for q in cdn.queries if q != "stopped"]
    assert isinstance(queries[0], raw.functions.InvokeWithLayer)
    assert isinstance(queries[1], raw.functions.upload.GetCdnFile)
