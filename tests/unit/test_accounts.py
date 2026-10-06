"""Accounts: password hashing, registration, email confirmation, log-in lock and password reset."""

from datetime import UTC, datetime, timedelta

import pytest

from nullpunkt.storage.accounts import (
    CODE_TRIES,
    LOCK_AFTER,
    WRONG_LOGIN,
    AccountError,
    AccountStore,
    NotVerified,
    check_password,
    hash_password,
    main,
    mask_email,
)

T0 = datetime(2026, 10, 7, 9, 0, tzinfo=UTC)
PASSWORD = "correct horse"


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kwargs: float) -> None:
        self.t += timedelta(**kwargs)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path, clock):
    accounts = AccountStore(tmp_path / "accounts.db", clock=clock)
    yield accounts
    accounts.close()


def confirmed(store: AccountStore, username: str = "kavish", email: str = "Kavish@Example.com"):
    store.register(username, email, PASSWORD)
    return store.confirm_email(username, store.issue_code(username, "verify"))


def test_password_hashes_are_salted_and_checked():
    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    assert first != second and first.startswith("scrypt$")
    assert check_password(PASSWORD, first) and not check_password("wrong password", first)
    assert not check_password(PASSWORD, "not a hash")


def test_passwords_and_codes_are_never_stored_in_clear(store, tmp_path):
    store.register("kavish", "k@example.com", PASSWORD)
    code = store.issue_code("kavish", "verify")
    stored = b"".join(p.read_bytes() for p in tmp_path.glob("accounts.db*"))
    assert PASSWORD.encode() not in stored and code.encode() not in stored


@pytest.mark.parametrize(
    ("username", "email", "password", "message"),
    [
        ("ab", "k@example.com", PASSWORD, "3 to 32 characters"),
        ("kavish gupta", "k@example.com", PASSWORD, "3 to 32 characters"),
        ("kavish", "not-an-email", PASSWORD, "valid email"),
        ("kavish", "k@example.com", "short", "at least 8"),
        ("kavish123", "k@example.com", "KAVISH123", "same as the username"),
    ],
)
def test_registration_is_validated(store, username, email, password, message):
    with pytest.raises(AccountError, match=message):
        store.register(username, email, password)


def test_usernames_and_addresses_are_unique_without_regard_to_case(store):
    store.register("kavish", "k@example.com", PASSWORD)
    for username, email in [("KAVISH", "other@example.com"), ("other", "K@EXAMPLE.COM")]:
        with pytest.raises(AccountError, match="already registered"):
            store.register(username, email, PASSWORD)


def test_log_in_needs_a_confirmed_address(store):
    store.register("kavish", "k@example.com", PASSWORD)
    with pytest.raises(NotVerified):
        store.authenticate("kavish", PASSWORD)
    assert store.confirm_email("k@example.com", store.issue_code("kavish", "verify")).verified
    assert store.authenticate("K@Example.COM", PASSWORD).username == "kavish"  # email, any case


def test_wrong_log_in_reads_the_same_for_unknown_accounts(store):
    confirmed(store)
    for identifier in ("kavish", "nobody", "nobody@example.com"):
        with pytest.raises(AccountError, match=WRONG_LOGIN) as refused:
            store.authenticate(identifier, "wrong password")
        assert type(refused.value) is AccountError


def test_repeated_wrong_passwords_lock_the_account(store, clock):
    confirmed(store)
    for _ in range(LOCK_AFTER):
        with pytest.raises(AccountError, match=WRONG_LOGIN):
            store.authenticate("kavish", "wrong password")
    with pytest.raises(AccountError, match="Too many wrong passwords"):
        store.authenticate("kavish", PASSWORD)  # even the right one, while locked
    clock.advance(minutes=16)
    assert store.authenticate("kavish", PASSWORD).username == "kavish"


def test_codes_expire_and_work_once(store, clock):
    store.register("kavish", "k@example.com", PASSWORD)
    code = store.issue_code("kavish", "verify")
    clock.advance(minutes=11)
    with pytest.raises(AccountError, match="expired"):
        store.confirm_email("kavish", code)
    code = store.issue_code("kavish", "verify")
    store.confirm_email("kavish", code)
    with pytest.raises(AccountError, match="already used"):
        store.confirm_email("kavish", code)


def test_wrong_codes_are_counted_and_limited(store):
    store.register("kavish", "k@example.com", PASSWORD)
    code = store.issue_code("kavish", "verify")
    wrong = "000000" if code != "000000" else "111111"
    for left in range(CODE_TRIES - 1, 0, -1):
        with pytest.raises(AccountError, match=f"{left} tries left"):
            store.confirm_email("kavish", wrong)
    with pytest.raises(AccountError, match="Ask for a new one"):
        store.confirm_email("kavish", wrong)
    with pytest.raises(AccountError, match="Too many wrong codes"):
        store.confirm_email("kavish", code)  # even the right code once the tries are used up


def test_a_new_code_waits_a_minute_and_retires_the_old_one(store, clock):
    store.register("kavish", "k@example.com", PASSWORD)
    first = store.issue_code("kavish", "verify")
    with pytest.raises(AccountError, match="just sent"):
        store.issue_code("kavish", "verify")
    clock.advance(seconds=61)
    second = store.issue_code("kavish", "verify")
    if first != second:
        with pytest.raises(AccountError, match="Wrong code"):
            store.confirm_email("kavish", first)
    assert store.confirm_email("kavish", second).verified


def test_password_reset(store):
    confirmed(store)
    account, code = store.request_reset("kavish@example.com")
    assert account.username == "kavish"
    with pytest.raises(AccountError, match="at least 8"):
        store.reset_password("kavish", code, "short")  # checked first, so the code still works
    store.reset_password("kavish", code, "new battery staple")
    with pytest.raises(AccountError, match=WRONG_LOGIN):
        store.authenticate("kavish", PASSWORD)
    assert store.authenticate("kavish", "new battery staple").username == "kavish"


def test_reset_says_nothing_for_unknown_or_unconfirmed_accounts(store, clock):
    store.register("pending", "p@example.com", PASSWORD)
    assert store.request_reset("nobody@example.com") is None
    assert store.request_reset("pending") is None
    confirmed(store)
    assert store.request_reset("kavish") is not None
    assert store.request_reset("kavish") is None  # a code was just sent: no error, no new email


def test_reset_lifts_a_lock(store):
    confirmed(store)
    for _ in range(LOCK_AFTER):
        with pytest.raises(AccountError):
            store.authenticate("kavish", "wrong password")
    _, code = store.request_reset("kavish")
    store.reset_password("kavish", code, "new battery staple")
    assert store.authenticate("kavish", "new battery staple").username == "kavish"


def test_mask_email():
    assert mask_email("kavish@gmail.com") == "k*****@gmail.com"
    assert mask_email("a@b.co") == "a***@b.co"


def test_add_analyst_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSWORD)
    db = tmp_path / "accounts.db"
    assert main(["kavish", "--email", "k@example.com", "--db", str(db)]) == 0
    store = AccountStore(db)
    assert store.authenticate("kavish", PASSWORD).verified  # confirmed without email
    store.close()
    assert main(["kavish", "--email", "x@example.com", "--db", str(db)]) == 1
    assert "already registered" in capsys.readouterr().err
