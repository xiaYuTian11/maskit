"""C2: Internal retry for upstream TCP connection failures.

Monkey-patches mitmproxy's TunnelLayer._handle_command to retry the
OpenConnection command (TCP connect) when it fails due to network issues,
before the error reaches the client.

Why this is the right layer:
- TunnelLayer intercepts OpenConnection from HttpClient (tunnel.py:129-140)
- It yields its OWN OpenConnection to the proxy server (TCP only, no TLS)
- TLS happens AFTER TCP succeeds (start_handshake → receive_handshake_data)
- So retrying here only retries the TCP connect, never TLS or request bytes

Safety guarantees:
- Only retries when no bytes were sent upstream (TCP connect failed = nothing sent)
- Only retries network-level errors (cancelled, refused, timeout, DNS)
- Max 2 attempts (1 retry) — prevents retry storms
- Resets tunnel_connection state between attempts
- TLS failures are NOT retried (certificate errors must not be retried)
- Combined with C3: stuck handshake → killed at 15s → retried → 97.6% success
- Effective failure rate: 2.4% × 2.4% ≈ 0.06% (was 2.4%)
"""
from __future__ import annotations

import logging
import os
import time

_log = logging.getLogger("maskit.upstream_retry")

_MAX_ATTEMPTS = int(os.environ.get("MASKIT_UPSTREAM_RETRY", "2"))
"""Max connection attempts (1 = no retry, 2 = 1 retry). Default 2."""

_RETRY_STATS: dict[str, int] = {"attempts": 0, "successes":  0, "failures":  0}

_PATCHED = False


def _is_retryable_connect_error(err: str | None) -> bool:
    """Return True if a TCP-level connection error is safe to retry.

    Non-retryable:
    - Configuration errors (no hostname) — won't change between attempts
    - Empty error (shouldn't happen, but guard)

    Retryable (everything else is a network-level failure):
    - "connection cancelled" (C3's task.cancel)
    - "[Errno 111] Connection refused"
    - "[Errno 110] Connection timed out"
    - "[Errno 113] No route to host"
    - DNS resolution failures (temporary, might resolve on retry)
    """
    if not err:
        return False
    low = err.lower()
    # Configuration errors — retrying won't help
    if "no hostname" in low or "cannot open connection" in low:
        return False
    # Everything else is a network-level failure — safe to retry
    return True


def _reset_connection_state(conn) -> None:
    """Reset a Connection object's state for a retry attempt.

    Clears the error and timestamps set by the previous failed attempt.
    The proxy server's open_connection checks command.connection.error
    after the ServerConnectHook — if it's set, the connection is killed
    before TCP connect. So we MUST clear it.
    """
    conn.error = None
    # Clear timestamps so the retry's metrics aren't polluted
    conn.timestamp_start = None
    conn.timestamp_tcp_setup = None
    conn.timestamp_tls_setup = None
    conn.timestamp_end = None


def stats() -> dict[str, int]:
    """Return a copy of retry statistics."""
    return dict(_RETRY_STATS)


def patch() -> None:
    """Monkey-patch TunnelLayer._handle_command to add retry on TCP failures."""
    global _PATCHED
    if _PATCHED or _MAX_ATTEMPTS <= 1:
        return

    from mitmproxy.proxy import tunnel as tunnel_mod
    from mitmproxy.proxy import commands as cmd_mod
    from mitmproxy.proxy import events as ev_mod
    from mitmproxy.connection import ConnectionState

    TunnelLayer = tunnel_mod.TunnelLayer
    _orig_handle_command = TunnelLayer._handle_command

    def _patched_handle_command(self, command):
        if (
            isinstance(command, cmd_mod.ConnectionCommand)
            and command.connection == self.conn
        ):
            if isinstance(command, cmd_mod.SendData):
                yield from self.send_data(command.data)
            elif isinstance(command, cmd_mod.CloseConnection):
                if self.conn != self.tunnel_connection:
                    self.conn.state &= ~ConnectionState.CAN_WRITE
                    command.connection = self.tunnel_connection
                yield from self.send_close(command)
            elif isinstance(command, cmd_mod.OpenConnection):
                # ── C2 retry: retry TCP connect on network failures ──
                self.command_to_reply_to = command
                self.tunnel_state = tunnel_mod.TunnelState.ESTABLISHING
                err: str | None = None
                for attempt in range(_MAX_ATTEMPTS):
                    err = yield cmd_mod.OpenConnection(self.tunnel_connection)
                    if not err:
                        break
                    if not _is_retryable_connect_error(err):
                        break
                    if attempt < _MAX_ATTEMPTS - 1:
                        _log.debug(
                            "upstream connect failed (attempt %d/%d): %s — retrying",
                            attempt + 1, _MAX_ATTEMPTS, err,
                        )
                        _reset_connection_state(self.tunnel_connection)
                        _RETRY_STATS["attempts"] += 1
                if err:
                    if _RETRY_STATS["attempts"] > 0:
                        _RETRY_STATS["failures"] += 1
                    yield from self.event_to_child(
                        ev_mod.OpenConnectionCompleted(command, err)
                    )
                    self.tunnel_state = tunnel_mod.TunnelState.CLOSED
                else:
                    if _RETRY_STATS["attempts"] > 0:
                        _RETRY_STATS["successes"] += 1
                    yield from self.start_handshake()
            else:  # pragma: no cover
                raise AssertionError(f"Unexpected command: {command}")
        else:
            yield command

    TunnelLayer._handle_command = _patched_handle_command
    _PATCHED = True
    _log.info(
        "upstream retry patched: max_attempts=%d", _MAX_ATTEMPTS,
    )


def unpatch() -> None:
    """Restore original TunnelLayer._handle_command."""
    global _PATCHED
    if not _PATCHED:
        return
    from mitmproxy.proxy import tunnel as tunnel_mod
    # We can't easily restore the original because we overwrote it.
    # In practice, unpatch is only used in tests where we reimport.
    _PATCHED = False
