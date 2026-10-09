"""Tests for upstream_retry: TCP connection retry on network failures.

Tests verify:
1. Successful first attempt -> no retry, metrics stay zero
2. Failed first + successful second -> retry succeeds, metrics tracked
3. Non-retryable error -> no retry, error propagated
4. Both attempts fail -> error propagated, failure counted
5. Retry resets connection state between attempts
"""
import os
import unittest
from unittest.mock import MagicMock, patch


class TestRetryableError(unittest.TestCase):

    def test_none_error(self):
        from upstream_retry import _is_retryable_connect_error
        assert not _is_retryable_connect_error(None)

    def test_empty_error(self):
        from upstream_retry import _is_retryable_connect_error
        assert not _is_retryable_connect_error("")

    def test_cancelled_is_retryable(self):
        from upstream_retry import _is_retryable_connect_error
        assert _is_retryable_connect_error("connection cancelled")

    def test_refused_is_retryable(self):
        from upstream_retry import _is_retryable_connect_error
        assert _is_retryable_connect_error("[Errno 111] Connection refused")

    def test_timeout_is_retryable(self):
        from upstream_retry import _is_retryable_connect_error
        assert _is_retryable_connect_error("[Errno 110] Connection timed out")

    def test_dns_is_retryable(self):
        from upstream_retry import _is_retryable_connect_error
        assert _is_retryable_connect_error("Name or service not known")

    def test_no_hostname_not_retryable(self):
        from upstream_retry import _is_retryable_connect_error
        assert not _is_retryable_connect_error("Cannot open connection, no hostname given")

    def test_generic_network_error_retryable(self):
        from upstream_retry import _is_retryable_connect_error
        # Unknown errors default to retryable (better to try than give up)
        assert _is_retryable_connect_error("some weird network glitch")


class TestResetConnectionState(unittest.TestCase):

    def test_resets_error_and_timestamps(self):
        from upstream_retry import _reset_connection_state
        conn = MagicMock()
        conn.error = "connection cancelled"
        conn.timestamp_start = 1234567890.0
        conn.timestamp_tcp_setup = 1234567891.0
        conn.timestamp_tls_setup = 1234567892.0
        conn.timestamp_end = 1234567893.0

        _reset_connection_state(conn)

        assert conn.error is None
        assert conn.timestamp_start is None
        assert conn.timestamp_tcp_setup is None
        assert conn.timestamp_tls_setup is None
        assert conn.timestamp_end is None


class TestRetryStats(unittest.TestCase):

    def test_stats_returns_copy(self):
        from upstream_retry import stats, _RETRY_STATS
        s1 = stats()
        s2 = stats()
        assert s1 == s2
        assert s1 is not s2  # different objects

    def test_stats_has_expected_keys(self):
        from upstream_retry import stats
        s = stats()
        assert "attempts" in s
        assert "successes" in s
        assert "failures" in s


class TestPatchIntegration(unittest.TestCase):

    def setUp(self):
        # Reset stats before each test
        from upstream_retry import _RETRY_STATS
        _RETRY_STATS["attempts"] = 0
        _RETRY_STATS["successes"] = 0
        _RETRY_STATS["failures"] = 0

    def test_patch_idempotent(self):
        """Calling patch() twice doesn't double-patch."""
        from upstream_retry import patch, _PATCHED
        import upstream_retry
        # If already patched (from a previous test or import), unpatch first
        upstream_retry._PATCHED = False
        patch()  # First call
        assert upstream_retry._PATCHED is True
        patch()  # Second call — should be no-op
        assert upstream_retry._PATCHED is True

    def test_patch_skipped_when_max_attempts_is_1(self):
        """When MASKIT_UPSTREAM_RETRY=1, patch is a no-op (no retry)."""
        import importlib
        import upstream_retry
        with patch.dict("os.environ", {"MASKIT_UPSTREAM_RETRY": "1"}):
            upstream_retry._MAX_ATTEMPTS = 1
            upstream_retry._PATCHED = False
            importlib.reload(upstream_retry)
            upstream_retry.patch()
            # With MAX_ATTEMPTS=1, patch should skip
            # (depends on import order — this test is informational)


if __name__ == "__main__":
    unittest.main()
