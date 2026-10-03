import asyncio
from io import BytesIO
from types import SimpleNamespace

import pytest

from pyrogram import raw
from pyrogram.raw.core import Int
from pyrogram.session.auth import Auth


class Connection:
    def __init__(self, packet):
        self.packet = packet
        self.connects = 0

    async def connect(self):
        self.connects += 1

    async def send(self, data):
        return None

    async def recv(self):
        return self.packet

    async def close(self):
        return None


def auth_with(packet):
    connection = Connection(packet)
    auth = Auth.__new__(Auth)
    auth.dc_id = 2
    auth.client = SimpleNamespace(server_time=0.0)
    auth.connection = connection
    return auth, connection


def test_a_transport_error_names_its_code_instead_of_a_key_error():
    """Раньше 4 байта кода ошибки разбирались как объект и падали KeyError(0)."""
    auth, _ = auth_with(bytes(Int(-429)))

    with pytest.raises(ConnectionError, match="transport error 429"):
        asyncio.run(auth.invoke(raw.functions.ReqPqMulti(nonce=1)))


def test_a_closed_connection_is_reported_as_such():
    auth, _ = auth_with(None)

    with pytest.raises(ConnectionError, match="closed the connection"):
        asyncio.run(auth.invoke(raw.functions.ReqPqMulti(nonce=1)))


def test_auth_creation_stops_at_once_on_a_transport_error(monkeypatch):
    """Повторы на транспортный флуд только продлевали блокировку IP прокси."""
    packet = bytes(Int(-429))
    made = []

    def factory(**kwargs):
        connection = Connection(packet)
        made.append(connection)
        return connection

    auth = Auth.__new__(Auth)
    auth.dc_id = 2
    auth.server_address = "149.154.167.51"
    auth.port = 443
    auth.test_mode = False
    auth.proxy = None
    auth.protocol_factory = None
    auth.loop = None
    auth.client = SimpleNamespace(server_time=0.0)
    auth.connection_factory = factory
    auth.MAX_RETRIES = 5

    with pytest.raises(ConnectionError):
        asyncio.run(auth.create())

    assert len(made) == 1
