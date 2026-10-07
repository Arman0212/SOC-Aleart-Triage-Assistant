"""Sending account codes: which backend is used, the Gmail SMTP exchange and safe errors."""

import smtplib

import pytest

from nullpunkt.app import mail


@pytest.fixture
def no_mail_settings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no .env here
    for name in ("MAIL_BACKEND", "SMTP_USER", "SMTP_PASSWORD", "SMTP_HOST", "SMTP_PORT"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


class FakeSMTP:
    last: "FakeSMTP | None" = None

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        self.host, self.port, self.calls = host, port, []
        FakeSMTP.last = self

    def __enter__(self) -> "FakeSMTP":
        return self

    def __exit__(self, *exc: object) -> None:
        self.calls.append("quit")

    def starttls(self, context=None) -> None:
        self.calls.append("starttls")

    def login(self, user: str, password: str) -> None:
        self.calls.append(("login", user))
        if password == "normal-gmail-password":
            raise smtplib.SMTPAuthenticationError(535, b"Username and Password not accepted")

    def send_message(self, message) -> None:
        self.calls.append(("send", message["To"], message["From"]))


def test_not_set_up(no_mail_settings):
    assert not mail.mail_configured()
    with pytest.raises(mail.MailError, match="isn't set up"):
        mail.send("k@example.com", "subject", "body")


def test_memory_backend_keeps_the_code(no_mail_settings):
    no_mail_settings.setenv("MAIL_BACKEND", "memory")
    mail.OUTBOX.clear()
    mail.send_code("k@example.com", "kavish", "123456", "reset")
    (message,) = mail.OUTBOX
    assert message["To"] == "k@example.com" and "123456" in message["Subject"]
    assert "reset your password" in message.get_content()


def test_console_backend_prints_the_email(no_mail_settings, capsys):
    no_mail_settings.setenv("MAIL_BACKEND", "console")
    assert mail.mail_configured()
    mail.send_code("k@example.com", "kavish", "654321", "verify")
    assert "654321" in capsys.readouterr().err


def test_gmail_over_smtp(no_mail_settings):
    no_mail_settings.setattr(mail.smtplib, "SMTP", FakeSMTP)
    no_mail_settings.setenv("SMTP_USER", "team@gmail.com")
    no_mail_settings.setenv("SMTP_PASSWORD", "abcd efgh ijkl mnop")
    assert mail.mail_configured()
    mail.send("k@example.com", "subject", "body")
    smtp = FakeSMTP.last
    assert (smtp.host, smtp.port) == ("smtp.gmail.com", 587)
    assert smtp.calls == [
        "starttls",
        ("login", "team@gmail.com"),
        ("send", "k@example.com", "team@gmail.com"),
        "quit",
    ]


def test_a_refused_gmail_password_explains_app_passwords(no_mail_settings):
    no_mail_settings.setattr(mail.smtplib, "SMTP", FakeSMTP)
    no_mail_settings.setenv("SMTP_USER", "team@gmail.com")
    no_mail_settings.setenv("SMTP_PASSWORD", "normal-gmail-password")
    with pytest.raises(mail.MailError, match="App Password") as refused:
        mail.send("k@example.com", "subject", "body")
    assert "normal-gmail-password" not in str(refused.value)


def test_network_errors_become_mail_errors(no_mail_settings):
    def unreachable(*args, **kwargs):
        raise OSError("network is unreachable")

    no_mail_settings.setattr(mail.smtplib, "SMTP", unreachable)
    no_mail_settings.setenv("SMTP_USER", "team@gmail.com")
    no_mail_settings.setenv("SMTP_PASSWORD", "abcd efgh ijkl mnop")
    with pytest.raises(mail.MailError, match="Couldn't send"):
        mail.send("k@example.com", "subject", "body")
