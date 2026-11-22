"""SMTP listener regression tests: AUTH replies and TLS rules per port.

These start the real listeners from build_smtp_controllers (plain, STARTTLS,
implicit TLS) and talk to them with smtplib, so they check what a client
actually sees on the wire.
"""
from __future__ import annotations

import asyncio
import smtplib
import socket
import ssl
from contextlib import ExitStack

import pytest_asyncio

from common.certs import generate_self_signed
from common.db import session_scope
from common.models import Settings, SmtpAccount
from common.passwords import hash_password
from relay import smtp_handler
from relay.main import build_smtp_controllers
from relay.smtp_handler import RelayAuthenticator, RelayHandler

USER = "relay-user"
PASSWORD = "correct-horse-battery"


def _free_ports(n: int) -> list[int]:
    """n distinct free ports; all sockets stay open until every port is picked."""
    with ExitStack() as stack:
        socks = [stack.enter_context(socket.socket()) for _ in range(n)]
        for s in socks:
            s.bind(("127.0.0.1", 0))
        return [s.getsockname()[1] for s in socks]


def _client_tls(cert_pem: str) -> ssl.SSLContext:
    """Client context that trusts exactly the listeners' test certificate.

    The chain is verified against that pinned certificate; only the host
    name is not, since the tests connect to 127.0.0.1.
    """
    ctx = ssl.create_default_context(cadata=cert_pem)
    ctx.check_hostname = False
    return ctx


def _login(smtp: smtplib.SMTP, password: str) -> int:
    """Reply code the relay gives `USER` with `password`."""
    try:
        smtp.login(USER, password)
    except smtplib.SMTPAuthenticationError as exc:
        return exc.smtp_code
    return 235


def _wrong_then_right(smtp: smtplib.SMTP) -> tuple[int, int]:
    return _login(smtp, "wrong-password"), _login(smtp, PASSWORD)


@pytest_asyncio.fixture
async def listeners(db, tmp_path, monkeypatch):
    # Local SMTP auth on, with one account: the replies below then come from
    # the real password check, not from the "local auth disabled" refusal.
    async with session_scope() as s:
        s.add(Settings(id=1, smtp_auth_local_enabled=True))
        s.add(SmtpAccount(username=USER, password_hash=hash_password(PASSWORD)))

    cert = generate_self_signed(subject_cn="localhost", valid_years=1)
    (tmp_path / "fullchain.pem").write_text(cert.public_cert_pem)
    (tmp_path / "privkey.pem").write_text(cert.private_key_pem)
    plain, starttls, implicit = _free_ports(3)
    monkeypatch.setenv("SMTP_LISTEN_HOST", "127.0.0.1")
    monkeypatch.setenv("SMTP_LISTEN_PORT", str(plain))
    monkeypatch.setenv("SMTP_STARTTLS_PORT", str(starttls))
    monkeypatch.setenv("SMTP_IMPLICIT_TLS_PORT", str(implicit))
    monkeypatch.setenv("SMTP_TLS_CERT", str(tmp_path / "fullchain.pem"))
    monkeypatch.setenv("SMTP_TLS_KEY", str(tmp_path / "privkey.pem"))

    controllers = build_smtp_controllers(
        RelayHandler(max_message_size=1_000_000), RelayAuthenticator()
    )
    assert len(controllers) == 3  # the TLS listeners need the cert above
    for c in controllers:
        c.start()
    try:
        yield {
            "plain": plain,
            "starttls": starttls,
            "implicit": implicit,
            "cert_pem": cert.public_cert_pem,
        }
    finally:
        for c in controllers:
            c.stop()


async def test_plain_listener_answers_auth(listeners):
    # Before the fix a failed AUTH got no reply at all and the client hung
    # until its own timeout.
    def run():
        with smtplib.SMTP("127.0.0.1", listeners["plain"], timeout=10) as s:
            s.ehlo()
            return _wrong_then_right(s)

    assert await asyncio.to_thread(run) == (535, 235)


async def test_starttls_listener_offers_auth_only_after_tls(listeners):
    def run():
        with smtplib.SMTP("127.0.0.1", listeners["starttls"], timeout=10) as s:
            s.ehlo()
            before = s.has_extn("auth")
            s.starttls(context=_client_tls(listeners["cert_pem"]))
            s.ehlo()
            return (before, s.has_extn("auth"), *_wrong_then_right(s))

    assert await asyncio.to_thread(run) == (False, True, 535, 235)


async def test_implicit_tls_listener_offers_auth(listeners):
    # Before the fix EHLO hid AUTH on 465 and AUTH got "538 Encryption
    # required", although the connection is TLS from the first byte.
    def run():
        ctx = _client_tls(listeners["cert_pem"])
        with smtplib.SMTP_SSL(
            "127.0.0.1", listeners["implicit"], context=ctx, timeout=10
        ) as s:
            s.ehlo()
            return (s.has_extn("auth"), *_wrong_then_right(s))

    assert await asyncio.to_thread(run) == (True, 535, 235)


async def test_crashed_credential_check_gets_454(listeners, monkeypatch):
    # Our failure, not the client's: a temporary reply, not "wrong password".
    def boom(*args):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(smtp_handler, "_run_auth_check", boom)

    def run():
        with smtplib.SMTP("127.0.0.1", listeners["plain"], timeout=10) as s:
            s.ehlo()
            return _login(s, PASSWORD)

    assert await asyncio.to_thread(run) == 454
