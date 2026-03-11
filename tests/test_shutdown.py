"""
Tests for graceful shutdown behavior.
"""

import time

import pytest

import core.blocklist as bl


@pytest.fixture(autouse=True)
def setup_db(tmp_path):
    bl.set_db_path(str(tmp_path / "test.db"))
    yield
    bl.close_all_connections()


class TestSchedulerShutdown:
    def test_scheduler_lifecycle(self):
        from core.scheduler import RuleScheduler

        sched = RuleScheduler()
        sched.start()
        time.sleep(0.1)
        sched.stop()
        # After stop, thread should not be alive
        if sched._thread is not None:
            assert not sched._thread.is_alive()

    def test_scheduler_stop_is_idempotent(self):
        from core.scheduler import RuleScheduler

        sched = RuleScheduler()
        sched.start()
        sched.stop()
        sched.stop()  # Should not raise


class TestCloseAllConnections:
    def test_close_all_does_not_raise(self):
        from core.blocklist import close_all_connections

        close_all_connections()  # Should not raise even with no connections

    def test_close_all_invalidates_connections(self):
        # Get a connection
        conn1 = bl.get_db()
        assert conn1 is not None

        # Close all
        bl.close_all_connections()

        # Next get_db should return a new connection
        conn2 = bl.get_db()
        assert conn2 is not conn1

    def test_close_db_single_thread(self):
        from core.blocklist import close_db

        conn1 = bl.get_db()
        close_db()
        conn2 = bl.get_db()
        assert conn2 is not conn1
