"""Analyst accounts: registration, email confirmation, log-in and password reset.

Accounts live in their own SQLite database (``ACCOUNTS_DB_PATH`` from the environment or .env,
default ``data/generated/accounts.db``), so ``nullpunkt-demo-reset`` never touches them.

- Passwords are stored as salted scrypt hashes, one-time codes as SHA-256 hashes; neither is
  stored in clear.
- A code is 6 digits, expires after 10 minutes, allows 5 tries and is used once. Issuing a new
  code retires the older one; a new code can be asked for once a minute.
- Five wrong passwords in a row lock the account for 15 minutes; a password reset unlocks it.
- ``AccountError`` messages are safe to show. Log-in and reset never reveal whether an account
  exists; only registration says that a username or address is taken.

    nullpunkt-add-analyst NAME --email ADDRESS    # create a confirmed account (asks for a password)
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import re
import secrets
import sqlite3
import sys
from base64 import b64decode, b64encode
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from nullpunkt.storage.db import bundled_migrations, connect, migrate

Clock = Callable[[], datetime]

DEFAULT_PATH = "data/generated/accounts.db"
USERNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,31}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
MIN_PASSWORD, MAX_PASSWORD = 8, 128
CODE_TTL = timedelta(minutes=10)
CODE_TRIES = 5
RESEND_AFTER = timedelta(seconds=60)
LOCK_AFTER = 5  # wrong passwords in a row
LOCK_FOR = timedelta(minutes=15)
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
PURPOSES = ("verify", "reset")
WRONG_LOGIN = "Wrong username or password."
EXPIRED_CODE = "That code has expired or was already used. Ask for a new one."


class AccountError(ValueError):
    """A refused account action, with a message that is safe to show."""


class NotVerified(AccountError):
    """The password was right, but the email address is not confirmed yet."""


class AccountSettings(BaseSettings):
    """``ACCOUNTS_DB_PATH`` from the environment or .env."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    accounts_db_path: str | None = None


def accounts_db_path() -> str:
    return AccountSettings().accounts_db_path or DEFAULT_PATH


@dataclass(frozen=True)
class Account:
    """An account as the app sees it (never the password hash)."""

    username: str
    email: str
    verified: bool


def hash_password(password: str) -> str:
    """``scrypt$n$r$p$salt$digest`` with a fresh 16-byte salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def check_password(password: str, stored: str) -> bool:
    """True when ``password`` matches ``stored`` (compared in constant time)."""
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        expected = b64decode(digest)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except ValueError:
        return False
    return scheme == "scrypt" and hmac.compare_digest(actual, expected)


@cache
def _dummy_hash() -> str:
    # Checked against for unknown accounts, so a wrong username takes as long as a wrong password.
    return hash_password(secrets.token_hex(16))


def _b64(data: bytes) -> str:
    return b64encode(data).decode("ascii")


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _code_hash(username: str, code: str) -> str:
    return hashlib.sha256(f"{username.lower()}:{code.strip()}".encode()).hexdigest()


def _check_new_password(password: str, username: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise AccountError(f"Passwords need at least {MIN_PASSWORD} characters.")
    if len(password) > MAX_PASSWORD:
        raise AccountError(f"Passwords can have at most {MAX_PASSWORD} characters.")
    if password.strip().lower() == username.lower():
        raise AccountError("The password can't be the same as the username.")


def mask_email(email: str) -> str:
    """``k****@gmail.com``: enough to recognise an address without showing it."""
    local, _, domain = email.partition("@")
    return f"{local[:1]}{'*' * max(len(local) - 1, 3)}@{domain}"


class AccountStore:
    """The accounts database. ``clock`` is injectable so tests can move time."""

    def __init__(self, path: str | Path | None = None, clock: Clock | None = None) -> None:
        self.path = str(path or accounts_db_path())
        self._clock = clock or (lambda: datetime.now(UTC))
        self._conn = connect(self.path)
        migrate(self._conn, bundled_migrations("account_migrations"))

    def close(self) -> None:
        self._conn.close()

    def now(self) -> datetime:
        return self._clock().astimezone(UTC)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def _row(self, identifier: str) -> sqlite3.Row | None:
        """The account whose username or email address is ``identifier`` (any case)."""
        key = identifier.strip().lower()
        return self._conn.execute(
            "SELECT * FROM accounts WHERE username_key = ? OR email_key = ?", (key, key)
        ).fetchone()

    @staticmethod
    def _account(row: sqlite3.Row) -> Account:
        return Account(row["username"], row["email"], row["verified_at"] is not None)

    def account(self, identifier: str) -> Account | None:
        row = self._row(identifier)
        return self._account(row) if row else None

    # --- registration and confirmation --------------------------------------------------------

    def register(self, username: str, email: str, password: str) -> Account:
        """Create an unconfirmed account."""
        username, email = username.strip(), email.strip()
        if not USERNAME_RE.fullmatch(username):
            raise AccountError(
                "Usernames have 3 to 32 characters: letters, digits, dots, dashes or "
                "underscores, starting with a letter or digit."
            )
        if not EMAIL_RE.fullmatch(email):
            raise AccountError("Enter a valid email address.")
        _check_new_password(password, username)
        password_hash = hash_password(password)
        try:
            self._conn.execute(
                "INSERT INTO accounts (username, username_key, email, email_key, "
                "password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    username,
                    username.lower(),
                    email,
                    email.lower(),
                    password_hash,
                    _iso(self.now()),
                ),
            )
        except sqlite3.IntegrityError:
            raise AccountError("That username or email address is already registered.") from None
        return Account(username, email, verified=False)

    def add_confirmed(self, username: str, email: str, password: str) -> Account:
        """Create an account that needs no email confirmation (``nullpunkt-add-analyst``)."""
        account = self.register(username, email, password)
        self._conn.execute(
            "UPDATE accounts SET verified_at = ? WHERE username = ?",
            (_iso(self.now()), account.username),
        )
        return Account(account.username, account.email, verified=True)

    def issue_code(self, identifier: str, purpose: str) -> str:
        """A new one-time code for ``purpose`` (``verify`` or ``reset``); returns it in clear so it
        can be emailed. Refused within a minute of the previous one."""
        if purpose not in PURPOSES:
            raise ValueError(f"purpose must be one of {PURPOSES}")
        row = self._row(identifier)
        if row is None:
            raise AccountError("No such account.")
        now = self.now()
        with self._transaction() as conn:
            last = conn.execute(
                "SELECT created_at FROM codes WHERE username = ? AND purpose = ? "
                "ORDER BY id DESC LIMIT 1",
                (row["username"], purpose),
            ).fetchone()
            if last and now - _utc(last["created_at"]) < RESEND_AFTER:
                wait = RESEND_AFTER - (now - _utc(last["created_at"]))
                raise AccountError(
                    f"A code was just sent. Ask for a new one in {int(wait.total_seconds()) + 1} s."
                )
            code = f"{secrets.randbelow(10**6):06d}"
            conn.execute(
                "UPDATE codes SET used_at = ? WHERE username = ? AND purpose = ? "
                "AND used_at IS NULL",
                (_iso(now), row["username"], purpose),
            )
            conn.execute(
                "INSERT INTO codes (username, purpose, code_hash, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    row["username"],
                    purpose,
                    _code_hash(row["username"], code),
                    _iso(now),
                    _iso(now + CODE_TTL),
                ),
            )
        return code

    def _use_code(
        self, conn: sqlite3.Connection, username: str, purpose: str, code: str
    ) -> str | None:
        """Consume the account's current code for ``purpose``. Returns None, or why it was
        refused; the caller raises after the transaction commits, so wrong tries stay counted."""
        row = conn.execute(
            "SELECT * FROM codes WHERE username = ? AND purpose = ? AND used_at IS NULL "
            "ORDER BY id DESC LIMIT 1",
            (username, purpose),
        ).fetchone()
        now = self.now()
        if row is None or now >= _utc(row["expires_at"]):
            return EXPIRED_CODE
        if row["attempts"] >= CODE_TRIES:
            return "Too many wrong codes. Ask for a new one."
        if not hmac.compare_digest(_code_hash(username, code), row["code_hash"]):
            conn.execute("UPDATE codes SET attempts = attempts + 1 WHERE id = ?", (row["id"],))
            left = CODE_TRIES - row["attempts"] - 1
            return f"Wrong code. {left} tries left." if left else "Wrong code. Ask for a new one."
        conn.execute("UPDATE codes SET used_at = ? WHERE id = ?", (_iso(now), row["id"]))
        return None

    def confirm_email(self, identifier: str, code: str) -> Account:
        """Confirm the account's email address with the code sent at registration."""
        row = self._row(identifier)
        if row is None:
            raise AccountError(EXPIRED_CODE)
        with self._transaction() as conn:
            refused = self._use_code(conn, row["username"], "verify", code)
            if refused is None:
                conn.execute(
                    "UPDATE accounts SET verified_at = ? WHERE username = ?",
                    (_iso(self.now()), row["username"]),
                )
        if refused:
            raise AccountError(refused)
        return Account(row["username"], row["email"], verified=True)

    # --- log-in and password reset ------------------------------------------------------------

    def authenticate(self, identifier: str, password: str) -> Account:
        """The account for a username or email address and its password, or ``AccountError``.
        ``NotVerified`` means the password was right but the address is not confirmed."""
        row = self._row(identifier)
        if row is None:
            check_password(password, _dummy_hash())
            raise AccountError(WRONG_LOGIN)
        now = self.now()
        if row["locked_until"] and now < _utc(row["locked_until"]):
            raise AccountError(
                "Too many wrong passwords. Try again in 15 minutes, or reset your password."
            )
        if not check_password(password, row["password_hash"]):
            failures = row["failed_logins"] + 1
            locked = _iso(now + LOCK_FOR) if failures >= LOCK_AFTER else None
            self._conn.execute(
                "UPDATE accounts SET failed_logins = ?, locked_until = ? WHERE username = ?",
                (0 if locked else failures, locked, row["username"]),
            )
            raise AccountError(WRONG_LOGIN)
        self._conn.execute(
            "UPDATE accounts SET failed_logins = 0, locked_until = NULL WHERE username = ?",
            (row["username"],),
        )
        if row["verified_at"] is None:
            raise NotVerified("Confirm your email address first, with the code we sent you.")
        return self._account(row)

    def request_reset(self, identifier: str) -> tuple[Account, str] | None:
        """A reset code for a confirmed account, or None (unknown, unconfirmed, or a code was just
        sent). The caller shows the same message either way."""
        row = self._row(identifier)
        if row is None or row["verified_at"] is None:
            return None
        try:
            code = self.issue_code(row["username"], "reset")
        except AccountError:
            return None
        return self._account(row), code

    def reset_password(self, identifier: str, code: str, new_password: str) -> Account:
        """Set a new password with a reset code; also lifts a log-in lock."""
        row = self._row(identifier)
        if row is None:
            raise AccountError(EXPIRED_CODE)
        _check_new_password(new_password, row["username"])
        new_hash = hash_password(new_password)
        with self._transaction() as conn:
            refused = self._use_code(conn, row["username"], "reset", code)
            if refused is None:
                conn.execute(
                    "UPDATE accounts SET password_hash = ?, failed_logins = 0, "
                    "locked_until = NULL WHERE username = ?",
                    (new_hash, row["username"]),
                )
        if refused:
            raise AccountError(refused)
        return self._account(row)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nullpunkt-add-analyst",
        description="Create a confirmed analyst account (no email needed).",
    )
    parser.add_argument("username")
    parser.add_argument("--email", required=True)
    parser.add_argument("--db", help="accounts database (default: ACCOUNTS_DB_PATH or .env)")
    args = parser.parse_args(argv)
    password = getpass.getpass("Password: ")
    if getpass.getpass("Repeat password: ") != password:
        print("error: the passwords differ", file=sys.stderr)
        return 1
    store = AccountStore(args.db)
    try:
        account = store.add_confirmed(args.username, args.email, password)
    except AccountError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(f"created {account.username} ({account.email}) in {store.path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
