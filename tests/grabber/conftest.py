import pytest

from pyrogram.crypto import rsa


@pytest.fixture(autouse=True)
def isolated_cdn_keys():
    saved = set(rsa.cdn_fingerprints)
    yield
    rsa.cdn_fingerprints.clear()
    rsa.cdn_fingerprints.update(saved)
