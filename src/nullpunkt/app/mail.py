"""Email for account codes: Gmail (or another SMTP server), or a local stand-in.

Settings come from the environment or .env:

- ``SMTP_USER`` and ``SMTP_PASSWORD``: a Gmail address and a Google App Password (the account
  needs 2-Step Verification; a normal Gmail password does not work).
- ``SMTP_HOST`` and ``SMTP_PORT``: default ``smtp.gmail.com`` and 587 (STARTTLS); 465 uses TLS
  from the start.
- ``MAIL_FROM``: the sender shown, default ``SMTP_USER``.
- ``MAIL_BACKEND``: ``smtp`` (the default once ``SMTP_USER`` is set), ``console`` (prints the
  email to the terminal; local testing only, never on a shared server) or ``memory`` (tests).

Codes are never logged by the smtp backend, and error messages never include the password.
"""

from __future__ import annotations

import smtplib
import ssl
import sys
from email.message import EmailMessage

from pydantic_settings import BaseSettings, SettingsConfigDict

NOT_SET_UP = (
    "Email isn't set up on this server, so codes can't be sent. Add SMTP_USER and SMTP_PASSWORD "
    "(a Gmail App Password) to .env, or ask an admin to create your account with "
    "nullpunkt-add-analyst."
)

# Messages sent with MAIL_BACKEND=memory, for tests.
OUTBOX: list[EmailMessage] = []


class MailError(RuntimeError):
    """The email could not be sent; the message is safe to show."""


class MailSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mail_backend: str | None = None
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    mail_from: str | None = None


def _backend(settings: MailSettings) -> str | None:
    chosen = (settings.mail_backend or "").strip().lower()
    if chosen:
        return chosen
    return "smtp" if settings.smtp_user else None


def mail_configured() -> bool:
    """True when codes can be sent."""
    settings = MailSettings()
    backend = _backend(settings)
    if backend == "smtp":
        return bool(settings.smtp_user and settings.smtp_password)
    return backend in ("console", "memory")


def send(to: str, subject: str, body: str) -> None:
    """Send one plain-text email, or raise ``MailError``."""
    settings = MailSettings()
    backend = _backend(settings)
    message = EmailMessage()
    message["From"] = settings.mail_from or settings.smtp_user or "nullpunkt@localhost"
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    if backend == "memory":
        OUTBOX.append(message)
    elif backend == "console":
        print(f"--- email to {to}: {subject}\n{body}\n---", file=sys.stderr, flush=True)
    elif backend == "smtp" and settings.smtp_user and settings.smtp_password:
        _send_smtp(settings, message)
    else:
        raise MailError(NOT_SET_UP)


def _send_smtp(settings: MailSettings, message: EmailMessage) -> None:
    context = ssl.create_default_context()
    try:
        if settings.smtp_port == 465:
            server = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=15, context=context
            )
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15)
        with server:
            if settings.smtp_port != 465:
                server.starttls(context=context)
            server.login(settings.smtp_user or "", settings.smtp_password or "")
            server.send_message(message)
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError(
            "The email server refused the sign-in. For Gmail, SMTP_PASSWORD must be an App "
            "Password, not the normal account password."
        ) from exc
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(f"Couldn't send the email ({type(exc).__name__}). Try again.") from exc


def send_code(to: str, username: str, code: str, purpose: str) -> None:
    """Email a one-time code for confirming the address (``verify``) or a reset (``reset``)."""
    what = "confirm your email address" if purpose == "verify" else "reset your password"
    send(
        to,
        f"Nullpunkt code: {code}",
        f"Hello {username},\n\n"
        f"Your code to {what} is {code}. It expires in 10 minutes and works once.\n\n"
        "If you didn't ask for it, ignore this email; your account is unchanged.\n\n"
        "Nullpunkt\n",
    )
