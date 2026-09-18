"""History snapshot export with opaque, signed pagination cursors.

A first ``GET /streams/{stream_id}/events?limit=...`` request (no cursor) opens
one deferred read transaction and pins the stream's current
``next_sequence`` — call it ``snapshot_next_sequence`` — inside that same
transaction. Only the *applied* prefix ``[0, snapshot_next_sequence)`` is ever
returned, together with the balance at exactly that version; events buffered
behind a gap and events appended afterwards are invisible to the snapshot.

Every subsequent request must carry the cursor handed out by the previous page.
The cursor binds three values — ``stream_id``, ``snapshot_next_sequence`` and
``next_sequence`` (the sequence at which the following page starts) — and is an
opaque token: canonical JSON (compact, sorted keys, UTF-8), URL-safe Base64
without padding, a ``.`` separator and an HMAC-SHA256 signature over the
encoded payload using ``SNAPSHOT_CURSOR_SECRET``. Because each cursor pins the
same upper bound, pages can never mix in concurrently appended events, skip an
event or repeat one. A tampered signature, cross-stream reuse or any illegal
field is rejected with HTTP 400; the final page returns ``next_cursor = null``.

Read transactions are deferred: under WAL they take a read snapshot without
blocking writers, so paging never interferes with event submission.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass

from . import config, db

# Hard cap so a client-supplied limit can never pull an unbounded result set.
MAX_LIMIT = 1000
DEFAULT_LIMIT = 100

# Cursor payload keys; the set is fixed, so extra/unknown keys are rejected.
_CURSOR_KEYS = {"stream_id", "snapshot_next_sequence", "next_sequence"}


class CursorError(Exception):
    """Raised when a snapshot cursor is malformed, forged or illegal (HTTP 400)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SnapshotEvent:
    event_id: str
    sequence: int
    delta: int

    def as_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "sequence": self.sequence,
            "delta": self.delta,
        }


@dataclass(frozen=True)
class SnapshotPage:
    stream_id: str
    snapshot_next_sequence: int  # exclusive upper bound shared by every page
    balance: int  # balance of the applied prefix at the snapshot version
    from_sequence: int  # sequence of the first event in this page
    events: list[SnapshotEvent]
    next_cursor: str | None  # null on the final page

    def as_dict(self) -> dict:
        return {
            "stream_id": self.stream_id,
            "snapshot_next_sequence": self.snapshot_next_sequence,
            "balance": self.balance,
            "from_sequence": self.from_sequence,
            "events": [event.as_dict() for event in self.events],
            "next_cursor": self.next_cursor,
        }


def _canonical_payload(payload: dict) -> bytes:
    """Render the cursor payload as canonical UTF-8 JSON.

    ``sort_keys`` pins member order, the compact separators remove insignificant
    whitespace and ``ensure_ascii=False`` keeps non-ASCII stream ids literal.
    """
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sign(body: bytes) -> bytes:
    return hmac.new(config.snapshot_cursor_secret(), body, hashlib.sha256).digest()


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    # validate=True rejects non-alphabet characters instead of silently
    # discarding them (which would turn e.g. "!!!" into empty bytes).
    return base64.b64decode(
        (text + padding).encode("ascii"), altchars=b"-_", validate=True
    )


def encode_cursor(
    stream_id: str, snapshot_next_sequence: int, next_sequence: int
) -> str:
    """Build the opaque signed cursor token for a follow-up page."""
    body = _canonical_payload(
        {
            "stream_id": stream_id,
            "snapshot_next_sequence": snapshot_next_sequence,
            "next_sequence": next_sequence,
        }
    )
    return f"{_b64encode(body)}.{_b64encode(_sign(body))}"


def decode_cursor(token: str, expected_stream_id: str) -> dict:
    """Validate a cursor token and return its payload.

    ``expected_stream_id`` is the id from the request path: a cursor minted for
    another stream is rejected (HTTP 400). Any structural, cryptographic or
    semantic problem raises :class:`CursorError`.
    """
    if not isinstance(token, str) or "." not in token:
        raise CursorError("invalid_cursor", "cursor must be '<payload>.<signature>'")
    body_text, _, signature_text = token.rpartition(".")
    if not body_text or not signature_text:
        raise CursorError("invalid_cursor", "cursor payload and signature must be non-empty")

    try:
        body = _b64decode(body_text)
        provided_signature = _b64decode(signature_text)
    except (binascii.Error, ValueError):
        raise CursorError("invalid_cursor", "cursor is not valid URL-safe Base64")

    # Verify against the exact transmitted bytes first: a forged or truncated
    # token never reaches payload parsing.
    if not hmac.compare_digest(provided_signature, _sign(body)):
        raise CursorError("invalid_cursor_signature", "cursor signature does not match")

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CursorError("invalid_cursor", "cursor payload is not valid UTF-8 JSON")

    if not isinstance(payload, dict) or set(payload.keys()) != _CURSOR_KEYS:
        raise CursorError(
            "invalid_cursor",
            "cursor payload must contain exactly stream_id, snapshot_next_sequence "
            "and next_sequence",
        )

    stream_id = payload["stream_id"]
    snapshot_next_sequence = payload["snapshot_next_sequence"]
    next_sequence = payload["next_sequence"]
    # bool is an int subclass in Python; a JSON boolean is not a legal sequence.
    if (
        not isinstance(stream_id, str)
        or not isinstance(snapshot_next_sequence, int)
        or isinstance(snapshot_next_sequence, bool)
        or not isinstance(next_sequence, int)
        or isinstance(next_sequence, bool)
    ):
        raise CursorError(
            "invalid_cursor", "cursor fields have illegal types"
        )
    if not stream_id:
        raise CursorError("invalid_cursor", "cursor stream_id must be non-empty")
    if snapshot_next_sequence < 0 or next_sequence < 0:
        raise CursorError("invalid_cursor", "cursor sequence fields must be >= 0")
    if next_sequence > snapshot_next_sequence:
        raise CursorError(
            "invalid_cursor",
            "cursor next_sequence must be <= snapshot_next_sequence",
        )
    if not hmac.compare_digest(stream_id, expected_stream_id):
        raise CursorError(
            "cursor_stream_mismatch",
            "cursor was issued for a different stream",
        )
    return payload


def _fetch_page(
    conn: sqlite3.Connection,
    stream_id: str,
    snapshot_next_sequence: int,
    from_sequence: int,
    limit: int,
) -> list[SnapshotEvent]:
    rows = conn.execute(
        "SELECT event_id, sequence, delta FROM events "
        "WHERE stream_id = ? AND sequence >= ? AND sequence < ? "
        "ORDER BY sequence ASC LIMIT ?",
        (stream_id, from_sequence, snapshot_next_sequence, limit),
    ).fetchall()
    return [
        SnapshotEvent(row["event_id"], row["sequence"], row["delta"]) for row in rows
    ]


def export_page(stream_id: str, limit: int, cursor: str | None) -> SnapshotPage | None:
    """Return one snapshot page for ``stream_id``.

    Returns ``None`` when the stream does not exist (HTTP 404). Raises
    :class:`CursorError` (HTTP 400) for an invalid ``cursor``.

    The first request (``cursor is None``) pins the snapshot inside a single
    read transaction; follow-up requests continue the snapshot bound recorded in
    the signed cursor.
    """
    if cursor is None:
        with db.read_transaction() as conn:
            stream = conn.execute(
                "SELECT balance, next_sequence FROM streams WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            if stream is None:
                return None
            # Pin the current applied-prefix length within this one read
            # transaction; the balance row and the events below come from the
            # same read snapshot.
            snapshot_next_sequence = stream["next_sequence"]
            balance = stream["balance"]
            from_sequence = 0
            events = _fetch_page(conn, stream_id, snapshot_next_sequence, 0, limit)
    else:
        payload = decode_cursor(cursor, stream_id)
        snapshot_next_sequence = payload["snapshot_next_sequence"]
        from_sequence = payload["next_sequence"]
        with db.read_transaction() as conn:
            stream = conn.execute(
                "SELECT 1 FROM streams WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            if stream is None:
                return None
            # Reconstruct the balance of exactly this snapshot version. Rows at
            # sequences below the pinned upper bound are immutable applied
            # events, so the sum is identical on every page of the snapshot.
            balance_row = conn.execute(
                "SELECT COALESCE(SUM(delta), 0) FROM events "
                "WHERE stream_id = ? AND sequence >= 0 AND sequence < ?",
                (stream_id, snapshot_next_sequence),
            ).fetchone()
            balance = balance_row[0]
            events = _fetch_page(
                conn, stream_id, snapshot_next_sequence, from_sequence, limit
            )

    next_sequence = from_sequence + len(events)
    # Exactly the last page (a short page ending at the snapshot bound) ends the
    # walk. A full page may still be the final one when its last event is
    # snapshot_next_sequence - 1; the bound check covers that case too.
    if next_sequence >= snapshot_next_sequence:
        next_cursor = None
    else:
        next_cursor = encode_cursor(stream_id, snapshot_next_sequence, next_sequence)

    return SnapshotPage(
        stream_id=stream_id,
        snapshot_next_sequence=snapshot_next_sequence,
        balance=balance,
        from_sequence=from_sequence,
        events=events,
        next_cursor=next_cursor,
    )
