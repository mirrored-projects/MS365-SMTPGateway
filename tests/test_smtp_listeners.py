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

import pytest_asyncio

from common.certs import generate_self_signed
from relay.main import build_smtp_controllers
from relay.smtp_handler import RelayAuthenticator, RelayHandler


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _client_tls(cert_pem: str) -> ssl.SSLContext:
    """Client context that trusts exactly the listeners' test certificate.

    The chain is verified against that pinned certificate; only the host
    name is not, since the tests connect to 127.0.0.1.
    """
    ctx = ssl.create_default_context(cadata=cert_pem)
    ctx.check_hostname = False
    return ctx


def _bad_login(smtp: smtplib.SMTP) -> int:
    """Reply code for a login with unknown credentials."""
    try:
        smtp.login("nobody", "wrong-password")
    except smtplib.SMTPAuthenticationError as exc:
        return exc.smtp_code
    return 235


@pytest_asyncio.fixture
async def listeners(db, tmp_path, monkeypatch):
    cert = generate_self_signed(subject_cn="localhost", valid_years=1)
    (tmp_path / "fullchain.pem").write_text(cert.public_cert_pem)
    (tmp_path / "privkey.pem").write_text(cert.private_key_pem)
    ports = {"plain": _free_port(), "starttls": _free_port(), "implicit": _free_port()}
    ports["cert_pem"] = cert.public_cert_pem
    monkeypatch.setenv("SMTP_LISTEN_HOST", "127.0.0.1")
    monkeypatch.setenv("SMTP_LISTEN_PORT", str(ports["plain"]))
    monkeypatch.setenv("SMTP_STARTTLS_PORT", str(ports["starttls"]))
    monkeypatch.setenv("SMTP_IMPLICIT_TLS_PORT", str(ports["implicit"]))
    monkeypatch.setenv("SMTP_TLS_CERT", str(tmp_path / "fullchain.pem"))
    monkeypatch.setenv("SMTP_TLS_KEY", str(tmp_path / "privkey.pem"))

    controllers = build_smtp_controllers(
        RelayHandler(max_message_size=1_000_000), RelayAuthenticator()
    )
    assert len(controllers) == 3  # the TLS listeners need the cert above
    for c in controllers:
        c.start()
    try:
        yield ports
    finally:
        for c in controllers:
            c.stop()


async def test_failed_auth_gets_535_on_plain_listener(listeners):
    # Before the fix the relay sent no reply at all and the client hung
    # until its own timeout.
    def run():
        with smtplib.SMTP("127.0.0.1", listeners["plain"], timeout=10) as s:
            s.ehlo()
            return _bad_login(s)

    assert await asyncio.to_thread(run) == 535


async def test_starttls_listener_offers_auth_only_after_tls(listeners):
    def run():
        with smtplib.SMTP("127.0.0.1", listeners["starttls"], timeout=10) as s:
            s.ehlo()
            before = s.has_extn("auth")
            s.starttls(context=_client_tls(listeners["cert_pem"]))
            s.ehlo()
            return before, s.has_extn("auth"), _bad_login(s)

    assert await asyncio.to_thread(run) == (False, True, 535)


async def test_implicit_tls_listener_offers_auth(listeners):
    # Before the fix EHLO hid AUTH on 465 and AUTH got "538 Encryption
    # required", although the connection is TLS from the first byte.
    def run():
        ctx = _client_tls(listeners["cert_pem"])
        with smtplib.SMTP_SSL(
            "127.0.0.1", listeners["implicit"], context=ctx, timeout=10
        ) as s:
            s.ehlo()
            return s.has_extn("auth"), _bad_login(s)

    assert await asyncio.to_thread(run) == (True, 535)
