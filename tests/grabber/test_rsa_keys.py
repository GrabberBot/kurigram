import re
from pathlib import Path

import pytest

from pyrogram.crypto import rsa


def builtin_pems():
    source = Path(rsa.__file__).read_text()
    for fingerprint, comment in re.findall(
        r"(0x[0-9a-f]+) - \(1 << 64\): PublicKey\(.*?\n((?:\s*# .*\n)+)", source
    ):
        lines = [line.strip().lstrip("#").strip() for line in comment.splitlines()]
        if "-----BEGIN RSA PUBLIC KEY-----" not in lines:
            continue
        start = lines.index("-----BEGIN RSA PUBLIC KEY-----")
        end = lines.index("-----END RSA PUBLIC KEY-----")
        yield int(fingerprint, 16) - (1 << 64), "\n".join(lines[start:end + 1])


@pytest.mark.parametrize(("expected", "pem"), list(builtin_pems()))
def test_a_pem_key_yields_the_fingerprint_telegram_announces(expected, pem):
    key = rsa.parse_pem(pem)

    assert rsa.fingerprint(key) == expected
    assert rsa.server_public_keys[expected] == key


def test_a_cdn_key_is_registered_for_the_handshake():
    fingerprint, pem = next(builtin_pems())
    original = rsa.server_public_keys.pop(fingerprint)
    try:
        assert rsa.add_public_key(pem) == fingerprint
        assert rsa.server_public_keys[fingerprint] == original
    finally:
        rsa.server_public_keys[fingerprint] = original


def test_garbage_is_rejected():
    with pytest.raises(ValueError):
        rsa.parse_pem("-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----")
