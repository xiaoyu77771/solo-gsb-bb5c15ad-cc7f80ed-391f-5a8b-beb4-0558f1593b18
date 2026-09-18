"""Stdlib-only smoke test for history snapshot export (run without FastAPI)."""

import base64
import hashlib
import hmac
import json
import os
import tempfile
import threading
import traceback

tmp = tempfile.mkdtemp()
os.environ["DATABASE_PATH"] = os.path.join(tmp, "snapshots.db")

from app import db, repo, snapshots  # noqa: E402

db.initialise()

failures = []


def check(name, cond, extra=""):
    print(f"{'PASS' if cond else 'FAIL'}: {name} {extra}")
    if not cond:
        failures.append(name)


# Seed a stream: applied 0..4, deltas [10, 20, 30, 40, 50] (balance 150).
for seq in range(5):
    repo.submit_event("acct", f"e{seq}", seq, (seq + 1) * 10)

# 1. first request pins next_sequence and the version balance
page = snapshots.export_page("acct", limit=2, cursor=None)
check("first page bound", page.snapshot_next_sequence == 5, str(page.snapshot_next_sequence))
check("first page balance", page.balance == 150, str(page.balance))
check("first page from", page.from_sequence == 0)
check("first page rows", [e.sequence for e in page.events] == [0, 1])
check("first page cursor", page.next_cursor is not None)

# 2. walk the remaining pages: no gaps, no duplicates, ascending order
seen = [(e.event_id, e.sequence, e.delta) for e in page.events]
cursor = page.next_cursor
while cursor is not None:
    page = snapshots.export_page("acct", limit=2, cursor=cursor)
    check("bound stable across pages", page.snapshot_next_sequence == 5)
    check("balance stable across pages", page.balance == 150)
    seen.extend((e.event_id, e.sequence, e.delta) for e in page.events)
    cursor = page.next_cursor
check(
    "full walk exact once",
    seen == [(f"e{s}", s, (s + 1) * 10) for s in range(5)],
    str(seen),
)
check("end page cursor null", page.next_cursor is None)

# 3. buffered pending events never enter the snapshot
repo.submit_event("pend", "p1", 1, 999)  # gap at 0 -> buffered
p = snapshots.export_page("pend", limit=10, cursor=None)
check(
    "pending excluded",
    p.snapshot_next_sequence == 0 and p.balance == 0 and p.events == [] and p.next_cursor is None,
)
repo.submit_event("pend", "p0", 0, 1)  # catch-up -> next_sequence 2
p = snapshots.export_page("pend", limit=10, cursor=None)
check(
    "pending applied after catch-up",
    p.snapshot_next_sequence == 2 and p.balance == 1000 and [e.sequence for e in p.events] == [0, 1],
)

# 4. appends between pages never mix into an open snapshot and never shift balance
first = snapshots.export_page("acct", limit=2, cursor=None)
repo.submit_event("acct", "e5", 5, 60)
repo.submit_event("acct", "e6", 6, 70)  # next_sequence now 7, balance 280
second = snapshots.export_page("acct", limit=2, cursor=first.next_cursor)
check(
    "open snapshot frozen",
    second.snapshot_next_sequence == 5
    and second.balance == 150
    and [e.sequence for e in second.events] == [2, 3],
    str(second),
)
third = snapshots.export_page("acct", limit=2, cursor=second.next_cursor)
check(
    "snapshot ends at pinned bound",
    [e.sequence for e in third.events] == [4] and third.next_cursor is None,
)
fresh = snapshots.export_page("acct", limit=100, cursor=None)
check(
    "fresh snapshot sees new version",
    fresh.snapshot_next_sequence == 7 and fresh.balance == 280
    and [e.sequence for e in fresh.events] == list(range(7)),
)

# 5. unknown stream -> None (HTTP 404 at the API layer)
check("unknown stream", snapshots.export_page("ghost", limit=10, cursor=None) is None)

# 6. cursor cryptographic/semantic validation -> CursorError (HTTP 400 at API layer)


def expect_error(name, token, stream="acct", code=None):
    try:
        snapshots.export_page(stream, limit=2, cursor=token)
    except snapshots.CursorError as exc:
        check(name, code is None or exc.code == code, exc.code)
        return
    check(name, False, "no error raised")


expect_error("garbage cursor", "not-a-cursor", code="invalid_cursor")
expect_error("empty segments", ".", code="invalid_cursor")
expect_error("non-base64", "!!!.!!!", code="invalid_cursor")

# forged signature: flip the signature segment
body, _, sig = first.next_cursor.partition(".")
flipped = "A" if sig[0] != "A" else "B"
expect_error("bad signature", f"{body}.{flipped + sig[1:]}", code="invalid_cursor_signature")

# signed with a different secret
payload_obj = {"next_sequence": 0, "snapshot_next_sequence": 5, "stream_id": "acct"}
raw = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode()
foreign_sig = hmac.new(b"some-other-secret", raw, hashlib.sha256).digest()
foreign_token = (
    base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    + "."
    + base64.urlsafe_b64encode(foreign_sig).rstrip(b"=").decode()
)
expect_error("foreign secret", foreign_token, code="invalid_cursor_signature")

# tampered payload re-signed with the real key would be a valid signature, but
# unsigned tampering breaks HMAC; verify each illegal payload shape is rejected.


def signed_token(obj):
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    s = hmac.new(snapshots.config.snapshot_cursor_secret(), raw, hashlib.sha256).digest()
    return (
        base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        + "."
        + base64.urlsafe_b64encode(s).rstrip(b"=").decode()
    )


base_obj = {"next_sequence": 0, "snapshot_next_sequence": 5, "stream_id": "acct"}
illegal = [
    dict(base_obj, extra=1),
    {k: v for k, v in base_obj.items() if k != "next_sequence"},
    dict(base_obj, next_sequence=-1),
    dict(base_obj, next_sequence=6),
    dict(base_obj, snapshot_next_sequence=-1),
    dict(base_obj, stream_id=""),
    dict(base_obj, stream_id=7),
    dict(base_obj, next_sequence=True),
]
for obj in illegal:
    expect_error(f"illegal payload {obj}", signed_token(obj), code="invalid_cursor")

# cross-stream use: valid signature, wrong path stream
expect_error(
    "cross stream cursor",
    snapshots.encode_cursor("acct", 5, 0),
    stream="other",
    code="cursor_stream_mismatch",
)

# 7. a cursor at the bound returns an empty final page even after appends
end_cursor = snapshots.encode_cursor("acct", 5, 5)
p = snapshots.export_page("acct", limit=10, cursor=end_cursor)
check(
    "bound cursor empty final page",
    p.events == [] and p.balance == 150 and p.snapshot_next_sequence == 5
    and p.next_cursor is None,
)

# 8. concurrent appenders never corrupt an interleaved snapshot walk
for seq in range(10):
    repo.submit_event("race", f"r{seq}", seq, 1)

collected = []
errors = []


def walk():
    cursor = None
    bounds = set()
    try:
        while True:
            p = snapshots.export_page("race", limit=3, cursor=cursor)
            bounds.add(p.snapshot_next_sequence)
            collected.extend(e.sequence for e in p.events)
            cursor = p.next_cursor
            if cursor is None:
                break
        check("walk bound single value", bounds == {10}, str(bounds))
    except Exception:  # noqa: BLE001 - record any failure for the main thread
        errors.append(traceback.format_exc())


def append():
    for seq in range(10, 30):
        repo.submit_event("race", f"late-{seq}", seq, 1)


t1 = threading.Thread(target=walk)
t2 = threading.Thread(target=append)
t1.start()
t2.start()
t1.join()
t2.join()
check("walk no errors", not errors, str(errors[:1]))
check(
    "walk exact prefix once",
    collected == list(range(len(collected))) and len(collected) <= 10,
    str(collected),
)

print()
if failures:
    print(f"{len(failures)} FAILURES: {failures}")
    raise SystemExit(1)
print("ALL SNAPSHOT CHECKS PASSED")
