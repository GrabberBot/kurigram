import asyncio
import os
from hashlib import sha1, sha256
from io import BytesIO
from random import getrandbits
from types import SimpleNamespace

import pytest

from pyrogram import raw
from pyrogram.crypto import aes, prime, rsa
from pyrogram.raw.core import TLObject
from pyrogram.session.auth import Auth

LEGACY = -4344800451088585951
PRODUCTION = -3414540481677951611


def generate_key():
    def generate_prime(bits):
        while True:
            candidate = getrandbits(bits) | (1 << bits - 1) | (1 << bits - 2) | 1
            if prime.is_probable_prime(candidate, 16):
                return candidate

    p, q = generate_prime(1024), generate_prime(1024)
    e = 65537
    return rsa.PublicKey(p * q, e), pow(e, -1, (p - 1) * (q - 1))


@pytest.fixture(scope="module")
def own_key():
    public, private = generate_key()
    fingerprint = rsa.fingerprint(public)
    rsa.server_public_keys[fingerprint] = public
    yield fingerprint, public, private
    rsa.server_public_keys.pop(fingerprint, None)


def unpad(encrypted, public, private):
    key_aes_encrypted = pow(int.from_bytes(encrypted, "big"), private, public.m).to_bytes(256, "big")
    temp_key_xor, aes_encrypted = key_aes_encrypted[:32], key_aes_encrypted[32:]
    temp_key = bytes(a ^ b for a, b in zip(temp_key_xor, sha256(aes_encrypted).digest()))
    data_with_hash = aes.ige256_decrypt(aes_encrypted, temp_key, bytes(32))
    data_with_padding = data_with_hash[:192][::-1]
    assert sha256(temp_key + data_with_padding).digest() == data_with_hash[192:]
    return data_with_padding


def test_the_current_production_key_is_known():
    """Новый паддинг сервер принимает только для нового ключа; старый ключ 2017 года — только со старым."""
    assert PRODUCTION in rsa.server_public_keys
    assert PRODUCTION not in rsa.LEGACY_FINGERPRINTS
    assert LEGACY in rsa.LEGACY_FINGERPRINTS


def test_a_current_key_is_preferred_over_a_legacy_one():
    assert rsa.pick_fingerprint([LEGACY, PRODUCTION]) == PRODUCTION
    assert rsa.pick_fingerprint([LEGACY, 12345]) == LEGACY


def test_no_known_key_is_an_error():
    with pytest.raises(ValueError):
        rsa.pick_fingerprint([1, 2, 3])


def test_rsa_pad_round_trips(own_key):
    fingerprint, public, private = own_key
    data = os.urandom(120)

    encrypted = rsa.encrypt_padded(data, fingerprint)

    assert len(encrypted) == 256
    assert unpad(encrypted, public, private)[:120] == data


def test_rsa_pad_refuses_data_that_does_not_fit(own_key):
    with pytest.raises(ValueError):
        rsa.encrypt_padded(os.urandom(145), own_key[0])


def test_a_cdn_key_gets_the_new_padding(own_key):
    """CDN-датацентры отвечали -404 на старую схему: их ключи новые."""
    fingerprint, public, private = own_key
    data = os.urandom(96)

    encrypted = rsa.encrypt_inner_data(data, fingerprint)

    assert unpad(encrypted, public, private)[:96] == data


def test_a_legacy_key_keeps_the_old_padding(monkeypatch):
    captured = []
    monkeypatch.setattr(rsa, "encrypt", lambda data, fingerprint: captured.append(data) or b"x" * 256)
    data = os.urandom(96)

    rsa.encrypt_inner_data(data, LEGACY)

    assert captured[0][:20] == sha1(data).digest()
    assert captured[0][20:116] == data
    assert len(captured[0]) == 255


def test_the_known_dh_prime_is_accepted_at_once():
    assert prime.is_safe_dh_prime(prime.CURRENT_DH_PRIME)


def test_a_bad_dh_prime_is_rejected():
    assert not prime.is_safe_dh_prime(2 ** 2047 + 1)
    assert not prime.is_safe_dh_prime(23)
    assert not prime.is_safe_dh_prime(prime.CURRENT_DH_PRIME + 2)


class Server:
    def __init__(self, fingerprint):
        self.fingerprint = fingerprint
        self.sent = []

    async def connect(self):
        return None

    async def close(self):
        return None

    async def send(self, data):
        self.sent.append(TLObject.read(BytesIO(data[20:])))

    async def recv(self):
        query = self.sent[-1]
        if isinstance(query, raw.functions.ReqPqMulti):
            answer = raw.types.ResPQ(
                nonce=query.nonce,
                server_nonce=7,
                pq=(1000003 * 1000033).to_bytes(8, "big"),
                server_public_key_fingerprints=[LEGACY, self.fingerprint],
            )
            return bytes(20) + answer.write()
        return None


def handshake(fingerprint, dc_id, test_mode):
    server = Server(fingerprint)
    auth = Auth.__new__(Auth)
    auth.dc_id = dc_id
    auth.server_address = "91.108.56.181"
    auth.port = 443
    auth.test_mode = test_mode
    auth.proxy = None
    auth.protocol_factory = None
    auth.loop = None
    auth.client = SimpleNamespace(server_time=0.0)
    auth.connection_factory = lambda **kwargs: server
    auth.MAX_RETRIES = 0

    with pytest.raises(ConnectionError):
        asyncio.run(auth.create())

    return server.sent[-1]


@pytest.mark.parametrize(("dc_id", "test_mode", "expected"), [(203, False, 203), (2, True, 10002)])
def test_the_inner_data_names_the_dc(own_key, dc_id, test_mode, expected):
    fingerprint, public, private = own_key

    request = handshake(fingerprint, dc_id, test_mode)

    assert isinstance(request, raw.functions.ReqDHParams)
    assert request.public_key_fingerprint == fingerprint
    inner = TLObject.read(BytesIO(unpad(request.encrypted_data, public, private)))
    assert isinstance(inner, raw.types.PQInnerDataDc)
    assert inner.dc == expected
    assert {int.from_bytes(inner.p, "big"), int.from_bytes(inner.q, "big")} == {1000003, 1000033}
